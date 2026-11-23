-- Conditions on attributes (Issue-74): a permission a role holds may carry
-- an expression in Common Expression Language that must also hold. The
-- context checks and compiles it before a row is written (Decision 0025);
-- the database keeps its text and bounds its length. The column goes with
-- its row, so removing the permission or the role removes the condition.
ALTER TABLE "authorization".role_permission
    ADD COLUMN condition text,
    ADD CONSTRAINT role_permission_condition_length
        CHECK (condition IS NULL OR char_length(condition) BETWEEN 1 AND 1000);
