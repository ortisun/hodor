-- An identity provider's issuer may be plain HTTP at a development host.
-- Which hosts those are is the installation's setting, checked by the
-- federation context when a provider is added or changed; the database
-- can only know that an issuer is an HTTP or HTTPS address.
-- See docs/security/outbound-http.md, "The exception for development".

ALTER TABLE federation.identity_provider
    DROP CONSTRAINT identity_provider_issuer_is_https;

ALTER TABLE federation.identity_provider
    ADD CONSTRAINT identity_provider_issuer_is_an_address
    CHECK (issuer ~ '^https?://');
