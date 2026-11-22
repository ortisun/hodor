-- The federation context: directories reached over LDAP.
-- See docs/architecture/contexts/federation.md, "Signing in through a
-- directory".

ALTER TABLE federation.identity_provider
    DROP CONSTRAINT identity_provider_kind_known;
ALTER TABLE federation.identity_provider
    ADD CONSTRAINT identity_provider_kind_known
    CHECK (kind IN ('openid_connect', 'github', 'ldap'));

-- A directory's address is `ldaps://` or `ldap://`; which of those may be
-- used, and where, is checked by the federation context.
ALTER TABLE federation.identity_provider
    DROP CONSTRAINT identity_provider_issuer_is_an_address;
ALTER TABLE federation.identity_provider
    ADD CONSTRAINT identity_provider_issuer_is_an_address
    CHECK (issuer ~ '^(https?|ldaps?)://');

-- What only a directory has: all present for a directory, all absent for
-- any other kind.
ALTER TABLE federation.identity_provider
    ADD COLUMN directory_base              text,
    ADD COLUMN directory_filter            text,
    ADD COLUMN directory_subject_attribute text,
    ADD COLUMN directory_email_attribute   text,
    ADD COLUMN directory_name_attribute    text,
    ADD CONSTRAINT identity_provider_directory_settings
    CHECK (
        CASE WHEN kind = 'ldap' THEN
            directory_base IS NOT NULL AND directory_filter IS NOT NULL
            AND directory_subject_attribute IS NOT NULL
            AND directory_email_attribute IS NOT NULL
            AND directory_name_attribute IS NOT NULL
        ELSE
            directory_base IS NULL AND directory_filter IS NULL
            AND directory_subject_attribute IS NULL
            AND directory_email_attribute IS NULL
            AND directory_name_attribute IS NULL
        END
    );
