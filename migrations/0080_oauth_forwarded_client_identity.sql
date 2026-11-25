-- Issue-107: clients that prove who they are with the identity a trusted
-- proxy forwards, `tls_client_auth`, `spiffe_x509` and `linkerd_identity`.
-- `spiffe_x509` reuses the SPIFFE identifier of migration 0078;
-- `linkerd_identity` is bound to a Linkerd identity; `tls_client_auth` to
-- one of the two.
-- See docs/architecture/contexts/oauth.md, "An identity forwarded by a
-- proxy", and docs/decisions/0056-forwarded-client-identity.md.

ALTER TABLE oauth.client
    DROP CONSTRAINT client_method_known,
    ADD CONSTRAINT client_method_known CHECK (authentication_method IN
        ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'spiffe_jwt',
         'tls_client_auth', 'spiffe_x509', 'linkerd_identity', 'none')),
    DROP CONSTRAINT client_spiffe_id_with_spiffe_jwt,
    -- Compared byte for byte with what the proxy forwards.
    ADD COLUMN linkerd_identity text COLLATE "C",
    ADD CONSTRAINT client_linkerd_identity_shape CHECK (
        linkerd_identity IS NULL
        OR (octet_length(linkerd_identity) <= 253
            AND linkerd_identity ~ '^[a-z0-9-]+(\.[a-z0-9-]+)+\.serviceaccount\.identity\.[a-z0-9-]+\.[a-z0-9._-]+$')),
    -- Each method holds the identity it takes, and no other: `spiffe_jwt`
    -- and `spiffe_x509` a SPIFFE identifier, `linkerd_identity` a Linkerd
    -- identity, `tls_client_auth` one of the two, any other method none.
    ADD CONSTRAINT client_identity_of_its_method CHECK (
        CASE authentication_method
            WHEN 'spiffe_jwt' THEN spiffe_id IS NOT NULL AND linkerd_identity IS NULL
            WHEN 'spiffe_x509' THEN spiffe_id IS NOT NULL AND linkerd_identity IS NULL
            WHEN 'linkerd_identity' THEN linkerd_identity IS NOT NULL AND spiffe_id IS NULL
            WHEN 'tls_client_auth' THEN (spiffe_id IS NULL) <> (linkerd_identity IS NULL)
            ELSE spiffe_id IS NULL AND linkerd_identity IS NULL
        END),
    ADD CONSTRAINT client_linkerd_identity_needs_principal CHECK (
        linkerd_identity IS NULL OR principal_id IS NOT NULL);

-- One client per Linkerd identity in a tenant, as per SPIFFE identifier;
-- two tenants may bind the same one.
CREATE UNIQUE INDEX client_linkerd_identity_unique ON oauth.client (tenant_id, linkerd_identity)
    WHERE linkerd_identity IS NOT NULL;
