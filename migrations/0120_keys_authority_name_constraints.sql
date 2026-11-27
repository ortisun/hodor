-- The keys context: which names a tenant's certificate authority leaves to
-- its meshes. Whether it constrains URIs, which an authority made before
-- these columns does, and the DNS names it permits besides its trust
-- domains, such as where a mesh's control plane serves.
-- See docs/architecture/contexts/keys.md, "Its certificate", and
-- Decision 0076.

ALTER TABLE keys.certificate_authority
    ADD COLUMN uri_constraints boolean NOT NULL DEFAULT true,
    ADD COLUMN additional_dns_names text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT certificate_authority_additional_dns_name_count
        CHECK (cardinality(additional_dns_names) <= 10);
