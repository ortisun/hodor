-- Issue-108: access tokens bound to the certificate a trusted proxy
-- forwards (RFC 8705). A client asks for them; a public client's refresh
-- token family keeps the thumbprint of the certificate it is bound to.
-- See docs/architecture/contexts/oauth.md, "Certificate-bound access
-- tokens", and docs/decisions/0057-certificate-bound-access-tokens.md.

ALTER TABLE oauth.client
    ADD COLUMN certificate_bound_access_tokens boolean NOT NULL DEFAULT false,
    -- Linkerd forwards no certificate to bind a token to.
    ADD CONSTRAINT client_certificate_bound_not_linkerd CHECK (
        NOT certificate_bound_access_tokens
        OR authentication_method <> 'linkerd_identity');

ALTER TABLE oauth.refresh_token_family
    -- The SHA-256 of the certificate, or null for a family bound to none.
    ADD COLUMN certificate_thumbprint bytea,
    ADD CONSTRAINT refresh_token_family_certificate_thumbprint_shape CHECK (
        certificate_thumbprint IS NULL OR octet_length(certificate_thumbprint) = 32);
