-- The authentication context: what a sign-in began enrolling at its
-- enrollment step, a second factor for a person whose tenant requires one
-- and who has none.
-- See docs/architecture/contexts/authentication.md, "Enrolling a second
-- factor during a sign-in", and Decision 0039.

ALTER TABLE authentication.transaction
    ADD COLUMN enrollment_kind text,
    -- The enrollment of an authenticator application, or the registration
    -- of a security key or a passkey, in the credential context;
    -- deliberately not a foreign key, so that each context keeps its own
    -- rows. An identifier, never a secret.
    ADD COLUMN enrollment_id uuid,
    ADD CONSTRAINT transaction_enrollment_kind_known
        CHECK (enrollment_kind IN ('authenticator_application', 'security_key', 'passkey')),
    ADD CONSTRAINT transaction_enrollment_whole
        CHECK ((enrollment_kind IS NULL) = (enrollment_id IS NULL));
