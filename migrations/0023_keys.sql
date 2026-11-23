-- The keys context: key versions of a tenant's key sets.
-- See docs/architecture/contexts/keys.md.

CREATE SCHEMA keys;
GRANT USAGE ON SCHEMA keys TO hodor_app, hodor_platform;

-- A key set is not a row of its own: it is the versions of one tenant and
-- one use.
CREATE TABLE keys.key_version (
    tenant_id           uuid        NOT NULL,
    id                  uuid        NOT NULL,
    key_use             text        NOT NULL,
    algorithm           text        NOT NULL,
    state               text        NOT NULL,
    provider            text        NOT NULL,
    -- As the provider handed it back; never the key in the clear.
    key_material        bytea       NOT NULL,
    public_rsa_modulus  bytea,
    public_rsa_exponent bytea,
    public_p256_x       bytea,
    public_p256_y       bytea,
    created_at          timestamptz NOT NULL,
    activated_at        timestamptz,
    retiring_at         timestamptz,
    retire_after        timestamptz,
    retired_at          timestamptz,
    revoked_at          timestamptz,
    revocation_reason   text,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT key_version_use_known CHECK (key_use IN ('sig', 'enc', 'data')),
    -- The algorithm decides the use.
    CONSTRAINT key_version_algorithm_fits_use CHECK (
        (key_use = 'sig' AND algorithm IN ('ES256', 'RS256', 'PS256'))
        OR (key_use = 'data' AND algorithm = 'A256GCM')
    ),
    CONSTRAINT key_version_state_known
        CHECK (state IN ('pending', 'active', 'retiring', 'retired', 'revoked')),
    CONSTRAINT key_version_material_present CHECK (octet_length(key_material) > 0),
    CONSTRAINT key_version_provider_named CHECK (provider ~ '^[a-z0-9_]{1,32}$'),
    -- A signing key carries the public key of its kind; a data key none.
    CONSTRAINT key_version_public_key_fits_algorithm CHECK (
        CASE algorithm
            WHEN 'ES256' THEN octet_length(public_p256_x) = 32
                AND octet_length(public_p256_y) = 32
                AND public_rsa_modulus IS NULL AND public_rsa_exponent IS NULL
            WHEN 'A256GCM' THEN public_p256_x IS NULL AND public_p256_y IS NULL
                AND public_rsa_modulus IS NULL AND public_rsa_exponent IS NULL
            ELSE octet_length(public_rsa_modulus) >= 256
                AND octet_length(public_rsa_exponent) > 0
                AND public_p256_x IS NULL AND public_p256_y IS NULL
        END
    ),
    -- Each state has the times it needs, and no time of a later state.
    CONSTRAINT key_version_times_fit_state CHECK (
        CASE state
            WHEN 'pending' THEN activated_at IS NULL AND retiring_at IS NULL
                AND retire_after IS NULL AND retired_at IS NULL AND revoked_at IS NULL
            WHEN 'active' THEN activated_at IS NOT NULL AND retiring_at IS NULL
                AND retire_after IS NULL AND retired_at IS NULL AND revoked_at IS NULL
            WHEN 'retiring' THEN activated_at IS NOT NULL AND retiring_at IS NOT NULL
                AND retire_after IS NOT NULL AND retired_at IS NULL AND revoked_at IS NULL
            WHEN 'retired' THEN activated_at IS NOT NULL AND retiring_at IS NOT NULL
                AND retire_after IS NOT NULL AND retired_at IS NOT NULL AND revoked_at IS NULL
            ELSE revoked_at IS NOT NULL AND revocation_reason IS NOT NULL
        END
    ),
    CONSTRAINT key_version_retire_after_with_retiring
        CHECK ((retiring_at IS NULL) = (retire_after IS NULL))
);

SELECT platform.enable_tenant_rls('keys.key_version');

-- One active version per tenant, use and algorithm: two activations racing
-- each other cannot both succeed.
CREATE UNIQUE INDEX key_version_one_active
    ON keys.key_version (tenant_id, key_use, algorithm)
    WHERE state = 'active';

CREATE INDEX key_version_use_idx ON keys.key_version (tenant_id, key_use, created_at DESC);

-- A version is revoked, never removed, so that a signature can always be
-- traced to the key that made it.
REVOKE DELETE ON keys.key_version FROM hodor_app;
