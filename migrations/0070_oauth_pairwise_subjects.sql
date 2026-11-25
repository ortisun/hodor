-- Issue-98: pairwise subject identifiers. How a client knows a person,
-- the sector identifier address that may name its sector, and the
-- tenant's pairwise secret, sealed.
-- See docs/architecture/contexts/oauth.md, "Pairwise subject identifiers",
-- and docs/decisions/0040-pairwise-subjects.md.

ALTER TABLE oauth.client
    ADD COLUMN subject_type text NOT NULL DEFAULT 'public',
    -- Compared byte for byte; fetched when it is set, never again.
    ADD COLUMN sector_identifier_uri text COLLATE "C";

ALTER TABLE oauth.client
    ADD CONSTRAINT client_subject_type_known CHECK (subject_type IN ('public', 'pairwise')),
    -- Only a client that signs people in with a code knows people at all.
    ADD CONSTRAINT client_pairwise_needs_code CHECK (
        subject_type = 'public' OR 'authorization_code' = ANY (grant_types)),
    ADD CONSTRAINT client_sector_identifier_uri_form CHECK (
        char_length(sector_identifier_uri) BETWEEN 1 AND 2000
        AND (sector_identifier_uri LIKE 'https://%' OR sector_identifier_uri LIKE 'http://%')),
    ADD CONSTRAINT client_sector_identifier_uri_needs_pairwise CHECK (
        sector_identifier_uri IS NULL OR subject_type = 'pairwise');

-- One secret per tenant, never replaced: a new one would change every
-- pairwise identifier of the tenant.
CREATE TABLE oauth.pairwise_secret (
    tenant_id     uuid        NOT NULL,
    id            uuid        NOT NULL,
    sealed_secret bytea       NOT NULL,
    created_at    timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT pairwise_secret_one_per_tenant UNIQUE (tenant_id)
);

SELECT platform.enable_tenant_rls('oauth.pairwise_secret');
