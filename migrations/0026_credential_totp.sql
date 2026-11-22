-- The credential context: authenticator applications, whose codes are
-- time-based one-time passwords (RFC 6238).
-- See docs/architecture/contexts/credential.md, "Authenticator applications".

CREATE TABLE credential.totp (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    -- A user of the identity context; deliberately not a foreign key.
    user_id        uuid        NOT NULL,
    status         text        NOT NULL,
    -- The secret, sealed for the tenant and the purpose
    -- `credential.totp_secret`. The secret itself is stored nowhere.
    sealed_secret  bytea       NOT NULL,
    created_at     timestamptz NOT NULL,
    confirmed_at   timestamptz,
    -- The step of the last accepted code: a code of this step or an
    -- earlier one is refused.
    last_used_step bigint,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT totp_status_known CHECK (status IN ('pending', 'active')),
    -- Confirmed exactly when in use.
    CONSTRAINT totp_confirmed_when_active
        CHECK ((status = 'active') = (confirmed_at IS NOT NULL)),
    CONSTRAINT totp_step_not_negative CHECK (last_used_step >= 0),
    -- At most one application in use and one enrollment waiting per user.
    CONSTRAINT totp_one_per_status UNIQUE (tenant_id, user_id, status)
);

SELECT platform.enable_tenant_rls('credential.totp');
