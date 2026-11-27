-- SPIFFE client authentication with a JWT-SVID (`spiffe_jwt`,
-- draft-ietf-oauth-spiffe-client-auth-03): the one SPIFFE identifier a
-- client of a service account is bound to.
-- See docs/architecture/contexts/oauth.md, "The SPIFFE identifier of a
-- client", and docs/decisions/0055-spiffe-jwt-client-authentication.md.

-- The method joins the four; the identifier, compared byte for byte, is
-- `spiffe://`, a trust domain's name and a path without `.` or `..`
-- segments, and is there exactly with `spiffe_jwt`, and only with a
-- principal.
ALTER TABLE oauth.client
    DROP CONSTRAINT client_method_known,
    ADD CONSTRAINT client_method_known CHECK (authentication_method IN
        ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'spiffe_jwt', 'none')),
    ADD COLUMN spiffe_id text COLLATE "C",
    ADD CONSTRAINT client_spiffe_id_shape CHECK (
        spiffe_id IS NULL
        OR (octet_length(spiffe_id) <= 2048
            AND spiffe_id ~ '^spiffe://[a-z0-9._-]{1,255}(/[A-Za-z0-9._-]+)+$'
            AND spiffe_id !~ '/\.\.?(/|$)')),
    ADD CONSTRAINT client_spiffe_id_with_spiffe_jwt CHECK (
        (authentication_method = 'spiffe_jwt') = (spiffe_id IS NOT NULL)),
    ADD CONSTRAINT client_spiffe_id_needs_principal CHECK (
        spiffe_id IS NULL OR principal_id IS NOT NULL);

-- One client per identifier in a tenant; two tenants may bind the same one.
CREATE UNIQUE INDEX client_spiffe_id_unique ON oauth.client (tenant_id, spiffe_id)
    WHERE spiffe_id IS NOT NULL;
