-- Ties a sign-in to the browser that started it: the SHA-256 hash of a
-- secret that only that browser holds.
-- See docs/architecture/contexts/authentication.md, "A sign-in in progress".
--
-- Sign-ins in progress live for ten minutes, so any that exist when this
-- runs are discarded rather than given a made-up binding.
DELETE FROM authentication.transaction;

ALTER TABLE authentication.transaction
    ADD COLUMN binding bytea NOT NULL,
    ADD CONSTRAINT transaction_binding_is_sha256 CHECK (octet_length(binding) = 32);
