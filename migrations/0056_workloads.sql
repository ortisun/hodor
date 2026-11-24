-- Service accounts and agents: their owners, the clients that act as
-- them, and the access tokens issued for them.
-- See docs/architecture/contexts/identity.md, "Service accounts and
-- agents", and docs/architecture/contexts/oauth.md, "Clients that act as
-- a workload".

-- The people responsible for a workload. That the workload is a service
-- account or an agent, and the owner a person, is checked by the use
-- cases, which load both in the same transaction.
CREATE TABLE identity.workload_owner (
    tenant_id   uuid        NOT NULL,
    workload_id uuid        NOT NULL,
    owner_id    uuid        NOT NULL,
    added_at    timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, workload_id, owner_id),
    CONSTRAINT workload_owner_workload_fk
        FOREIGN KEY (tenant_id, workload_id)
        REFERENCES identity."user" (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT workload_owner_owner_fk
        FOREIGN KEY (tenant_id, owner_id)
        REFERENCES identity."user" (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT workload_owner_not_itself CHECK (owner_id <> workload_id)
);

SELECT platform.enable_tenant_rls('identity.workload_owner');
-- The workloads a person owns.
CREATE INDEX workload_owner_owner_idx ON identity.workload_owner (tenant_id, owner_id);

-- The workload a client of the client credentials grant acts as. Not a
-- reference: contexts do not reference each other's tables. A client with
-- a principal has that grant and no other.
ALTER TABLE oauth.client
    ADD COLUMN principal_id uuid,
    ADD CONSTRAINT client_principal_only_client_credentials CHECK (
        principal_id IS NULL OR grant_types = ARRAY['client_credentials']::text[]);

-- The workload an access token was issued for, so that the token is in
-- force only while the workload may act, and is revoked with it.
ALTER TABLE oauth.access_token
    ADD COLUMN principal_id uuid;

CREATE INDEX access_token_principal_idx ON oauth.access_token (tenant_id, principal_id)
    WHERE principal_id IS NOT NULL;
