-- The federation context: a SAML response is checked when it arrives, and
-- only its answer is kept, never the response. See
-- docs/architecture/contexts/federation.md, "When the response arrives".

-- A response kept by the previous version is forgotten with its receipt:
-- the sign-in it was kept for finds no response, as if none had arrived,
-- and expires within ten minutes anyway.
UPDATE federation.pending_authorization
    SET saml_receipt_hash = NULL
    WHERE saml_response IS NOT NULL;

ALTER TABLE federation.pending_authorization
    DROP CONSTRAINT pending_authorization_saml_receipt,
    DROP CONSTRAINT pending_authorization_saml_response_size,
    DROP COLUMN saml_response;

-- Who the person is, as a response that passed every check said; or the
-- reason a response was refused. The hash of the receipt is set first, when
-- a response claims the pending authorization, and the answer, one or the
-- other, once that response is checked.
ALTER TABLE federation.pending_authorization
    ADD COLUMN saml_subject text,
    ADD COLUMN saml_email   text,
    ADD COLUMN saml_name    text,
    ADD COLUMN saml_refusal text,
    ADD CONSTRAINT pending_authorization_saml_answer_size
    CHECK (
        (saml_subject IS NULL OR char_length(saml_subject) BETWEEN 1 AND 255)
        AND (saml_email IS NULL OR char_length(saml_email) <= 254)
        AND (saml_name IS NULL OR char_length(saml_name) <= 200)
        AND (saml_refusal IS NULL OR char_length(saml_refusal) BETWEEN 1 AND 64)
    ),
    ADD CONSTRAINT pending_authorization_saml_answer
    CHECK (
        CASE
            WHEN saml_receipt_hash IS NULL THEN
                saml_subject IS NULL AND saml_email IS NULL AND saml_name IS NULL
                AND saml_refusal IS NULL
            ELSE
                octet_length(saml_receipt_hash) = 32
                AND (saml_subject IS NULL OR saml_refusal IS NULL)
                AND (saml_subject IS NOT NULL OR (saml_email IS NULL AND saml_name IS NULL))
        END
    );
