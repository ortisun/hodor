-- Invitations to an organization. Only the hash of the secret the link
-- carries is kept.
-- See docs/architecture/contexts/identity.md, "Invitations".

CREATE TABLE identity.organization_invitation (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    organization_id uuid        NOT NULL,
    email           text        NOT NULL,
    unit_ids        uuid[]      NOT NULL DEFAULT '{}',
    token_hash      bytea       NOT NULL,
    status          text        NOT NULL,
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    accepted_by     uuid,
    accepted_at     timestamptz,
    withdrawn_at    timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT organization_invitation_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES identity.organization (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT organization_invitation_accepted_by_fk
        FOREIGN KEY (tenant_id, accepted_by)
        REFERENCES identity."user" (tenant_id, id) ON DELETE SET NULL (accepted_by),
    CONSTRAINT organization_invitation_token_unique UNIQUE (tenant_id, token_hash),
    CONSTRAINT organization_invitation_token_is_sha256 CHECK (octet_length(token_hash) = 32),
    CONSTRAINT organization_invitation_status_known
        CHECK (status IN ('pending', 'accepted', 'withdrawn')),
    CONSTRAINT organization_invitation_lifetime CHECK (expires_at > created_at),
    CONSTRAINT organization_invitation_accepted_whole
        CHECK ((status = 'accepted') = (accepted_at IS NOT NULL)),
    CONSTRAINT organization_invitation_withdrawn_whole
        CHECK ((status = 'withdrawn') = (withdrawn_at IS NOT NULL))
);

SELECT platform.enable_tenant_rls('identity.organization_invitation');
-- At most one pending invitation of an organization to an address.
CREATE UNIQUE INDEX organization_invitation_one_pending
    ON identity.organization_invitation (tenant_id, organization_id, email)
    WHERE status = 'pending';
