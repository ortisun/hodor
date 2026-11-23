-- The credential context: whether a WebAuthn registration in progress is
-- of a passkey, which is asked for as a discoverable credential with the
-- person verified, and checked for both when it is finished. See
-- docs/architecture/contexts/credential.md, "Passkeys".

ALTER TABLE credential.webauthn_registration
    ADD COLUMN passkey boolean NOT NULL DEFAULT false;
