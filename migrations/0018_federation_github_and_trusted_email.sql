-- The federation context: a second kind of provider, GitHub, and a
-- setting for providers that do not say whether they vouch for an email
-- address.
-- See docs/architecture/contexts/federation.md, "Signing in through
-- GitHub" and "When a provider does not say whether it vouches".

ALTER TABLE federation.identity_provider
    DROP CONSTRAINT identity_provider_kind_known;

ALTER TABLE federation.identity_provider
    ADD CONSTRAINT identity_provider_kind_known
    CHECK (kind IN ('openid_connect', 'github'));

-- No provider is trusted with addresses unless an administrator says so.
ALTER TABLE federation.identity_provider
    ADD COLUMN trusts_email boolean NOT NULL DEFAULT false;
