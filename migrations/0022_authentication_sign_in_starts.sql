-- The authentication context: counting the sign-ins started from a
-- network. See docs/architecture/contexts/authentication.md, "Starting
-- sign-ins".

ALTER TABLE authentication.attempt_counter
    DROP CONSTRAINT attempt_counter_kind_known;
ALTER TABLE authentication.attempt_counter
    ADD CONSTRAINT attempt_counter_kind_known
    CHECK (subject_kind IN ('identifier', 'address', 'start'));
