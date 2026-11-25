-- Claim mappers: the claims an administrator adds to the tokens of one
-- client. Every rule is checked when a mapper is saved; the database
-- keeps the shape of each row, and one mapper per claim in a client.
-- See docs/architecture/contexts/oauth.md, "Claim mappers".

CREATE TABLE oauth.claim_mapper (
    tenant_id        uuid        NOT NULL,
    id               uuid        NOT NULL,
    client_id        uuid        NOT NULL,
    claim            text        COLLATE "C" NOT NULL,
    claim_normalized text        COLLATE "C" NOT NULL,
    targets          text[]      NOT NULL,
    scope            text,
    source           jsonb       NOT NULL,
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    version          integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    -- A mapper belongs to a client of its own tenant, and goes with it.
    CONSTRAINT claim_mapper_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    -- One mapper per claim in a client, without regard to case.
    CONSTRAINT claim_mapper_claim_once UNIQUE (tenant_id, client_id, claim_normalized),
    CONSTRAINT claim_mapper_claim_length CHECK (octet_length(claim) BETWEEN 1 AND 128),
    CONSTRAINT claim_mapper_claim_normalized CHECK (claim_normalized = lower(claim)),
    CONSTRAINT claim_mapper_targets_known CHECK (
        cardinality(targets) BETWEEN 1 AND 3
        AND targets <@ ARRAY['id_token', 'access_token', 'userinfo']::text[]),
    CONSTRAINT claim_mapper_scope_length CHECK (char_length(scope) BETWEEN 1 AND 128),
    CONSTRAINT claim_mapper_source_known CHECK (
        jsonb_typeof(source) = 'object'
        AND source ->> 'kind' IN ('attribute', 'groups', 'group_member', 'organization', 'constant')),
    -- A constant is at most 1024 bytes as Hodor writes it; jsonb writes it
    -- with spaces Hodor leaves out, so the bound here is looser.
    CONSTRAINT claim_mapper_constant_size CHECK (
        source ->> 'kind' <> 'constant'
        OR (source ? 'value' AND jsonb_typeof(source -> 'value') <> 'null'
            AND octet_length((source -> 'value')::text) <= 2048))
);

SELECT platform.enable_tenant_rls('oauth.claim_mapper');
