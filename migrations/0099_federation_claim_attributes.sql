-- The federation context: which attribute of a directory or a SAML identity
-- provider gives which standard claim of a person it creates, and the claims
-- a SAML response gave, kept with its answer until the sign-in finishes.
-- See docs/architecture/contexts/federation.md, "Claim attributes", and
-- docs/decisions/0065-where-the-standard-claims-come-from.md.

ALTER TABLE federation.identity_provider
    ADD COLUMN claim_attributes jsonb NOT NULL DEFAULT '{}',
    ADD CONSTRAINT identity_provider_claim_attributes CHECK (
        jsonb_typeof(claim_attributes) = 'object'
        AND (kind IN ('ldap', 'saml') OR claim_attributes = '{}'::jsonb)
    );

ALTER TABLE federation.pending_authorization
    ADD COLUMN saml_claims jsonb,
    ADD CONSTRAINT pending_authorization_saml_claims CHECK (
        saml_claims IS NULL
        OR (jsonb_typeof(saml_claims) = 'object' AND saml_subject IS NOT NULL)
    );
