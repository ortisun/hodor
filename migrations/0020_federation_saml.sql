-- The federation context: SAML identity providers.
-- See docs/architecture/contexts/federation.md, "Signing in through a SAML
-- identity provider".

ALTER TABLE federation.identity_provider
    DROP CONSTRAINT identity_provider_kind_known;
ALTER TABLE federation.identity_provider
    ADD CONSTRAINT identity_provider_kind_known
    CHECK (kind IN ('openid_connect', 'github', 'ldap', 'saml'));

-- A SAML entity identifier names the identity provider and is never
-- fetched: an address of either scheme, or a `urn:` name.
ALTER TABLE federation.identity_provider
    DROP CONSTRAINT identity_provider_issuer_is_an_address;
ALTER TABLE federation.identity_provider
    ADD CONSTRAINT identity_provider_issuer_is_an_address
    CHECK (
        issuer ~ '^(https?|ldaps?)://'
        OR (kind = 'saml' AND issuer ~ '^urn:.')
    );

-- What only a SAML identity provider has: all present for one, all absent
-- for any other kind. The certificate is kept as PEM.
ALTER TABLE federation.identity_provider
    ADD COLUMN saml_single_sign_on_address text,
    ADD COLUMN saml_certificate            text,
    ADD COLUMN saml_email_attribute        text,
    ADD COLUMN saml_name_attribute         text,
    ADD CONSTRAINT identity_provider_saml_settings
    CHECK (
        CASE WHEN kind = 'saml' THEN
            saml_single_sign_on_address IS NOT NULL AND saml_certificate IS NOT NULL
            AND saml_email_attribute IS NOT NULL AND saml_name_attribute IS NOT NULL
            AND client_id = ''
        ELSE
            saml_single_sign_on_address IS NULL AND saml_certificate IS NULL
            AND saml_email_attribute IS NULL AND saml_name_attribute IS NULL
        END
    );

-- The response a SAML identity provider posted, unread, kept once.
ALTER TABLE federation.pending_authorization
    ADD COLUMN saml_response text,
    ADD CONSTRAINT pending_authorization_saml_response_size
    CHECK (saml_response IS NULL OR octet_length(saml_response) <= 393216);

-- A response is kept with the pending authorization its provider and state
-- name.
CREATE INDEX pending_authorization_state_idx
    ON federation.pending_authorization (tenant_id, provider_id, state_hash);
