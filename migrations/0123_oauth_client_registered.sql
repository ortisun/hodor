-- Issue-133: the registration endpoint. A client's application type and
-- the addresses a person is shown, which a registration names; whether the
-- client registered itself, for good; and the SHA-256 of the address it
-- was registered from, to count the registrations of an address.
-- See docs/architecture/contexts/oauth.md, "The registration endpoint",
-- and Decision 0080.

ALTER TABLE oauth.client
    ADD COLUMN application_type text,
    -- Kept exactly as given; the person's browser loads or follows them,
    -- Hodor never calls them.
    ADD COLUMN client_uri text COLLATE "C",
    ADD COLUMN logo_uri text COLLATE "C",
    ADD COLUMN policy_uri text COLLATE "C",
    ADD COLUMN tos_uri text COLLATE "C",
    ADD COLUMN registered boolean NOT NULL DEFAULT false,
    ADD COLUMN registered_from bytea;

ALTER TABLE oauth.client
    -- Null for every client an administrator makes.
    ADD CONSTRAINT client_application_type_known CHECK (
        application_type IN ('web', 'native')),
    ADD CONSTRAINT client_display_uris_https CHECK (
        (client_uri IS NULL
            OR (client_uri LIKE 'https://%' AND char_length(client_uri) <= 2000))
        AND (logo_uri IS NULL
            OR (logo_uri LIKE 'https://%' AND char_length(logo_uri) <= 2000))
        AND (policy_uri IS NULL
            OR (policy_uri LIKE 'https://%' AND char_length(policy_uri) <= 2000))
        AND (tos_uri IS NULL
            OR (tos_uri LIKE 'https://%' AND char_length(tos_uri) <= 2000))),
    -- Only a registered client was registered from somewhere.
    ADD CONSTRAINT client_registered_from_shape CHECK (
        registered_from IS NULL
        OR (registered AND octet_length(registered_from) = 32));

-- The registrations of an address in the last minute, counted under the
-- lock of the tenant's registration settings.
CREATE INDEX client_registered_from_idx
    ON oauth.client (tenant_id, registered_from, created_at)
    WHERE registered;
