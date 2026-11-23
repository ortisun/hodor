-- Assurance levels and step-up. See docs/architecture/contexts/session.md,
-- "Raising a session", docs/architecture/contexts/authentication.md,
-- "Step-up", and docs/architecture/contexts/oauth.md, "Assurance and
-- step-up". The levels themselves live in the tenant's settings, which
-- read the default when they are missing.

-- A session can be phishing-resistant, and keeps when each of its methods
-- was last proven. Rows stored before this read every method as proven
-- when the person signed in.
ALTER TABLE session.session
    DROP CONSTRAINT session_assurance_known,
    ADD CONSTRAINT session_assurance_known
        CHECK (assurance IN ('single_factor', 'multi_factor', 'phishing_resistant')),
    ADD COLUMN method_proven_at timestamptz[],
    ADD CONSTRAINT session_method_proven_at_matches CHECK (
        method_proven_at IS NULL
        OR cardinality(method_proven_at) = cardinality(methods));

-- A sign-in that is a step-up carries the methods the session proved
-- earlier, the assurance the application asked for, and the session it
-- raises. Every other sign-in leaves them empty.
ALTER TABLE authentication.transaction
    ADD COLUMN carried_methods    text[] NOT NULL DEFAULT '{}',
    ADD COLUMN demanded_assurance text,
    ADD COLUMN raised_session_id  uuid,
    ADD CONSTRAINT transaction_demanded_assurance_known CHECK (
        demanded_assurance IS NULL
        OR demanded_assurance IN ('single_factor', 'multi_factor', 'phishing_resistant')),
    -- Only a step-up carries methods or demands an assurance.
    ADD CONSTRAINT transaction_step_up_parts CHECK (
        raised_session_id IS NOT NULL
        OR (cardinality(carried_methods) = 0 AND demanded_assurance IS NULL));

-- A code names the level of the tenant its methods reached, the `acr` of
-- its tokens; null when they reached none. A family of refresh tokens
-- keeps the code's, for the access tokens it issues.
ALTER TABLE oauth.authorization_code
    ADD COLUMN acr text,
    ADD CONSTRAINT authorization_code_acr_shape CHECK (
        acr IS NULL OR (acr ~ '^[!-~]{1,255}$'));
ALTER TABLE oauth.refresh_token_family
    ADD COLUMN acr text,
    ADD CONSTRAINT refresh_token_family_acr_shape CHECK (
        acr IS NULL OR (acr ~ '^[!-~]{1,255}$'));
