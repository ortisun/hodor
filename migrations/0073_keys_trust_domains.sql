-- The keys context: the SPIFFE trust domains a tenant trusts, each with the
-- bundle of its authorities, given by an administrator, fetched from a
-- bundle endpoint, or left to the mesh.
-- See docs/architecture/contexts/keys.md, "Trust domains" and "Storage".

CREATE TABLE keys.trust_domain (
    tenant_id                   uuid        NOT NULL,
    id                          uuid        NOT NULL,
    name                        text        NOT NULL,
    source                      text        NOT NULL,
    bundle_endpoint_url         text,
    bundle                      text,
    bundle_sequence             bigint,
    bundle_refresh_hint_seconds bigint,
    bundle_changed_at           timestamptz,
    fetched_at                  timestamptz,
    next_refresh_at             timestamptz,
    leased_until                timestamptz,
    failing_since               timestamptz,
    last_error                  text,
    created_at                  timestamptz NOT NULL,
    updated_at                  timestamptz NOT NULL,
    version                     integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    -- Unique within a tenant, and only within it: two tenants may each
    -- trust a `cluster.local` of their own.
    CONSTRAINT trust_domain_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT trust_domain_name_shape CHECK (name ~ '^[a-z0-9._-]{1,255}$'),
    CONSTRAINT trust_domain_source_known
        CHECK (source IN ('uploaded', 'bundle_endpoint', 'mesh')),
    CONSTRAINT trust_domain_url_for_endpoint
        CHECK ((source = 'bundle_endpoint') = (bundle_endpoint_url IS NOT NULL)),
    CONSTRAINT trust_domain_url_length
        CHECK (char_length(bundle_endpoint_url) BETWEEN 1 AND 1000),
    CONSTRAINT trust_domain_bundle_unless_mesh
        CHECK ((source = 'mesh') = (bundle IS NULL)),
    CONSTRAINT trust_domain_bundle_changed_with_bundle
        CHECK ((bundle IS NULL) = (bundle_changed_at IS NULL)),
    CONSTRAINT trust_domain_bundle_size CHECK (octet_length(bundle) <= 65536),
    CONSTRAINT trust_domain_numbers_with_bundle
        CHECK (bundle IS NOT NULL OR (bundle_sequence IS NULL AND bundle_refresh_hint_seconds IS NULL)),
    CONSTRAINT trust_domain_sequence_not_negative CHECK (bundle_sequence >= 0),
    CONSTRAINT trust_domain_refresh_hint_positive CHECK (bundle_refresh_hint_seconds >= 1),
    CONSTRAINT trust_domain_refreshed_only_from_endpoint
        CHECK ((source = 'bundle_endpoint') = (next_refresh_at IS NOT NULL)),
    CONSTRAINT trust_domain_fetched_only_from_endpoint
        CHECK (source = 'bundle_endpoint'
               OR (fetched_at IS NULL AND leased_until IS NULL AND failing_since IS NULL)),
    CONSTRAINT trust_domain_failure_whole
        CHECK ((failing_since IS NULL) = (last_error IS NULL)),
    CONSTRAINT trust_domain_last_error_length CHECK (char_length(last_error) BETWEEN 1 AND 100)
);

SELECT platform.enable_tenant_rls('keys.trust_domain');

-- The worker's search for bundles due to be fetched, across tenants.
CREATE INDEX trust_domain_due_idx
    ON keys.trust_domain (next_refresh_at)
    WHERE source = 'bundle_endpoint';
