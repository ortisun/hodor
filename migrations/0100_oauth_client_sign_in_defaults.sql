-- Issue-125: a client's defaults for a sign-in, its `default_max_age`,
-- `default_acr_values` and `require_auth_time` of OpenID Connect
-- Registration.
-- See docs/architecture/contexts/oauth.md, "Defaults for a sign-in".

ALTER TABLE oauth.client
    ADD COLUMN default_max_age integer,
    ADD COLUMN default_acr_values text[] NOT NULL DEFAULT '{}',
    ADD COLUMN require_auth_time boolean NOT NULL DEFAULT false;

ALTER TABLE oauth.client
    -- As `max_age` at the authorization endpoint: up to a year.
    ADD CONSTRAINT client_default_max_age_range CHECK (
        default_max_age BETWEEN 0 AND 31536000),
    ADD CONSTRAINT client_default_acr_values_count CHECK (
        cardinality(default_acr_values) <= 10),
    -- Only a client that signs people in with a code has a sign-in to
    -- default.
    ADD CONSTRAINT client_sign_in_defaults_need_code CHECK (
        (default_max_age IS NULL
            AND cardinality(default_acr_values) = 0
            AND NOT require_auth_time)
        OR 'authorization_code' = ANY (grant_types));
