-- The credential context: WebAuthn credentials, made by security keys and
-- platform authenticators, and the registrations of them in progress. The
-- authentication context keeps the challenge of a step with the sign-in.
-- See docs/architecture/contexts/credential.md, "Security keys and
-- platform authenticators", and
-- docs/architecture/contexts/authentication.md, "Steps that need a
-- challenge".

CREATE TABLE credential.webauthn_credential (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    -- A user of the identity context; deliberately not a foreign key.
    user_id         uuid        NOT NULL,
    -- As the authenticator made it.
    credential_id   bytea       NOT NULL,
    -- The COSE key, as the authenticator sent it.
    public_key      bytea       NOT NULL,
    algorithm       integer     NOT NULL,
    sign_count      bigint      NOT NULL,
    backup_eligible boolean     NOT NULL,
    backed_up       boolean     NOT NULL,
    -- Null when the browser did not say.
    discoverable    boolean,
    transports      text[]      NOT NULL,
    name            text        NOT NULL,
    created_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    PRIMARY KEY (tenant_id, id),
    -- A credential is found by tenant and identifier together, so a
    -- credential of one tenant is unknown in another.
    CONSTRAINT webauthn_credential_id_unique UNIQUE (tenant_id, credential_id),
    CONSTRAINT webauthn_credential_id_length
        CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    CONSTRAINT webauthn_credential_algorithm CHECK (algorithm IN (-7, -257)),
    CONSTRAINT webauthn_credential_sign_count
        CHECK (sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT webauthn_credential_backup CHECK (backup_eligible OR NOT backed_up)
);

SELECT platform.enable_tenant_rls('credential.webauthn_credential');

CREATE INDEX webauthn_credential_user_idx
    ON credential.webauthn_credential (tenant_id, user_id);

CREATE TABLE credential.webauthn_registration (
    tenant_id  uuid        NOT NULL,
    id         uuid        NOT NULL,
    user_id    uuid        NOT NULL,
    challenge  bytea       NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT webauthn_registration_challenge CHECK (octet_length(challenge) = 32),
    CONSTRAINT webauthn_registration_expires CHECK (expires_at > created_at)
);

SELECT platform.enable_tenant_rls('credential.webauthn_registration');

-- The challenge the current step of a sign-in asked for, if it needs one.
ALTER TABLE authentication.transaction
    ADD COLUMN challenge bytea
        CONSTRAINT transaction_challenge CHECK (octet_length(challenge) = 32);
