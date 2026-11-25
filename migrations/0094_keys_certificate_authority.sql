-- The keys context: the certificate authority of a tenant, and the source
-- `authority` of the trust domains it adds.
-- See docs/architecture/contexts/keys.md, "The certificate authority of a
-- tenant" and "Storage", and Decision 0062.

CREATE TABLE keys.certificate_authority (
    tenant_id                   uuid        NOT NULL,
    id                          uuid        NOT NULL,
    kind                        text        NOT NULL,
    state                       text        NOT NULL,
    trust_domains               text[]      NOT NULL,
    common_name                 text        NOT NULL,
    lifetime_days               integer,
    intermediate_lifetime_days  integer     NOT NULL,
    for_development             boolean     NOT NULL,
    key_id                      uuid        NOT NULL,
    provider                    text        NOT NULL,
    key_material                bytea       NOT NULL,
    public_p256_x               bytea       NOT NULL,
    public_p256_y               bytea       NOT NULL,
    certificate_signing_request bytea,
    certificate                 bytea,
    serial_number               text,
    not_before                  timestamptz,
    not_after                   timestamptz,
    certificate_sha256          text,
    chain                       bytea[]     NOT NULL DEFAULT '{}',
    created_at                  timestamptz NOT NULL,
    activated_at                timestamptz,
    updated_at                  timestamptz NOT NULL,
    version                     integer     NOT NULL DEFAULT 0,
    -- One authority per tenant.
    PRIMARY KEY (tenant_id),
    CONSTRAINT certificate_authority_id_unique UNIQUE (tenant_id, id),
    CONSTRAINT certificate_authority_kind_known CHECK (kind IN ('root', 'intermediate')),
    CONSTRAINT certificate_authority_state_known
        CHECK (state IN ('awaiting_certificate', 'active')),
    CONSTRAINT certificate_authority_only_an_intermediate_awaits
        CHECK (state = 'active' OR kind = 'intermediate'),
    CONSTRAINT certificate_authority_trust_domain_count
        CHECK (cardinality(trust_domains) BETWEEN 1 AND 10),
    CONSTRAINT certificate_authority_common_name_length
        CHECK (char_length(common_name) BETWEEN 1 AND 80),
    CONSTRAINT certificate_authority_lifetime_of_a_root
        CHECK ((kind = 'root') = (lifetime_days IS NOT NULL)),
    CONSTRAINT certificate_authority_lifetime_bounds CHECK (lifetime_days BETWEEN 1 AND 3650),
    CONSTRAINT certificate_authority_intermediate_lifetime_bounds
        CHECK (intermediate_lifetime_days BETWEEN 1 AND 365),
    CONSTRAINT certificate_authority_provider_shape CHECK (provider ~ '^[a-z0-9_]{1,32}$'),
    CONSTRAINT certificate_authority_public_key_on_p256
        CHECK (octet_length(public_p256_x) = 32 AND octet_length(public_p256_y) = 32),
    CONSTRAINT certificate_authority_request_of_an_intermediate
        CHECK ((kind = 'intermediate') = (certificate_signing_request IS NOT NULL)),
    CONSTRAINT certificate_authority_certificate_when_active
        CHECK ((state = 'active') = (certificate IS NOT NULL)
               AND (certificate IS NULL) = (serial_number IS NULL)
               AND (certificate IS NULL) = (not_before IS NULL)
               AND (certificate IS NULL) = (not_after IS NULL)
               AND (certificate IS NULL) = (certificate_sha256 IS NULL)
               AND (certificate IS NULL) = (activated_at IS NULL)),
    CONSTRAINT certificate_authority_chain_of_an_intermediate
        CHECK (kind = 'intermediate' OR cardinality(chain) = 0),
    CONSTRAINT certificate_authority_chain_length CHECK (cardinality(chain) <= 5)
);

SELECT platform.enable_tenant_rls('keys.certificate_authority');

-- A trust domain may hold the bundle of the tenant's certificate
-- authority.
ALTER TABLE keys.trust_domain DROP CONSTRAINT trust_domain_source_known;
ALTER TABLE keys.trust_domain ADD CONSTRAINT trust_domain_source_known
    CHECK (source IN ('uploaded', 'bundle_endpoint', 'mesh', 'authority'));
