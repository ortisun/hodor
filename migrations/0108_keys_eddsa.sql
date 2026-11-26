-- EdDSA signing keys on Ed25519 (RFC 8037), made by the local provider or
-- by OpenBao: the algorithm `EdDSA` in the signing key set, and the public
-- key's 32 bytes in a column of their own.
-- See docs/architecture/contexts/keys.md, "Storage".

ALTER TABLE keys.key_version ADD COLUMN public_ed25519 bytea;

ALTER TABLE keys.key_version DROP CONSTRAINT key_version_algorithm_fits_use;
ALTER TABLE keys.key_version ADD CONSTRAINT key_version_algorithm_fits_use CHECK (
    (key_use = 'sig' AND algorithm IN ('ES256', 'RS256', 'PS256', 'EdDSA'))
    OR (key_use = 'data' AND algorithm = 'A256GCM')
);

-- A signing key carries the public key of its kind and no other; a data key
-- none. A missing column counts as no bytes, so that a key that is not there
-- never passes for one (`octet_length` of null is null, which a check
-- would let through).
ALTER TABLE keys.key_version DROP CONSTRAINT key_version_public_key_fits_algorithm;
ALTER TABLE keys.key_version ADD CONSTRAINT key_version_public_key_fits_algorithm CHECK (
    CASE algorithm
        WHEN 'ES256' THEN coalesce(octet_length(public_p256_x), 0) = 32
            AND coalesce(octet_length(public_p256_y), 0) = 32
            AND public_rsa_modulus IS NULL AND public_rsa_exponent IS NULL
            AND public_ed25519 IS NULL
        WHEN 'EdDSA' THEN coalesce(octet_length(public_ed25519), 0) = 32
            AND public_p256_x IS NULL AND public_p256_y IS NULL
            AND public_rsa_modulus IS NULL AND public_rsa_exponent IS NULL
        WHEN 'A256GCM' THEN public_p256_x IS NULL AND public_p256_y IS NULL
            AND public_rsa_modulus IS NULL AND public_rsa_exponent IS NULL
            AND public_ed25519 IS NULL
        ELSE coalesce(octet_length(public_rsa_modulus), 0) >= 256
            AND coalesce(octet_length(public_rsa_exponent), 0) > 0
            AND public_p256_x IS NULL AND public_p256_y IS NULL
            AND public_ed25519 IS NULL
    END
);
