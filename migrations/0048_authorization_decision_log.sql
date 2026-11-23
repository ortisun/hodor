-- The record of decisions: one row per decision Hodor made for an
-- application, whichever engine decided, with its input reduced by the
-- tenant's masks; and the tenant's settings for it.
-- See docs/architecture/contexts/authorization.md, "The record of decisions".

CREATE TABLE "authorization".decision_log_setting (
    tenant_id      uuid        NOT NULL,
    mode           text        NOT NULL,
    allow_percent  smallint,
    masks          text[]      NOT NULL DEFAULT '{}',
    retention_days smallint    NOT NULL,
    updated_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id),
    CONSTRAINT decision_log_setting_mode
        CHECK (mode IN ('full', 'sampled', 'deny_only', 'off')),
    -- A share of allows comes with sampled, and only then.
    CONSTRAINT decision_log_setting_share CHECK (
        (mode = 'sampled') = (allow_percent IS NOT NULL)
        AND (allow_percent IS NULL OR allow_percent BETWEEN 1 AND 99)),
    CONSTRAINT decision_log_setting_masks CHECK (cardinality(masks) <= 32),
    CONSTRAINT decision_log_setting_retention CHECK (retention_days BETWEEN 1 AND 400)
);

SELECT platform.enable_tenant_rls('"authorization".decision_log_setting');

-- Partitioned by day on the time of the decision. A partition holds every
-- tenant's records of its day; the worker prepares the partitions ahead,
-- drops those past the longest retention, and deletes each tenant's older
-- records itself.
CREATE TABLE "authorization".decision_log (
    tenant_id      uuid        NOT NULL,
    decided_at     timestamptz NOT NULL,
    decision_id    uuid        NOT NULL,
    namespace      text        NOT NULL,
    subject_kind   text        NOT NULL,
    subject_id     text        NOT NULL,
    action         text        NOT NULL,
    resource_type  text        NOT NULL,
    resource_id    text,
    effect         text        NOT NULL,
    reason         text        NOT NULL,
    engine         text,
    policy_version text,
    duration_us    bigint      NOT NULL,
    -- What the engine was given, after the tenant's masks.
    input          jsonb       NOT NULL,
    -- The masks that erased something; never what they erased.
    masked         text[]      NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, decided_at, decision_id),
    CONSTRAINT decision_log_subject_kind CHECK (subject_kind IN ('user', 'client')),
    CONSTRAINT decision_log_effect CHECK (effect IN ('allow', 'deny', 'indeterminate')),
    CONSTRAINT decision_log_duration CHECK (duration_us >= 0),
    CONSTRAINT decision_log_input_object CHECK (jsonb_typeof(input) = 'object'),
    CONSTRAINT decision_log_lengths CHECK (
        char_length(namespace) <= 2048
        AND char_length(subject_id) <= 255
        AND char_length(action) <= 255
        AND char_length(resource_type) <= 255
        AND char_length(resource_id) <= 1024
        AND char_length(reason) <= 255
        AND char_length(engine) <= 255
        AND char_length(policy_version) <= 255)
) PARTITION BY RANGE (decided_at);

-- Row-level security and the grants apply to the partitioned table. The
-- partitions are granted to nobody, so records are reached only through
-- it and its policy.
SELECT platform.enable_tenant_rls('"authorization".decision_log');
-- A record is never changed once written.
REVOKE UPDATE ON "authorization".decision_log FROM hodor_app, hodor_platform;

-- Catches a record whose day has no partition yet. Preparing that day
-- moves its rows out first.
CREATE TABLE "authorization".decision_log_default
    PARTITION OF "authorization".decision_log DEFAULT;

-- Prepares the partitions from the day before `today` to `days_ahead`
-- after it, and drops the partitions that end before `today` minus
-- `keep_days`. Returns how many partitions it created and dropped. Runs
-- with the rights of the schema's owner, so that the worker needs no right
-- to create or drop tables; only the platform role may call it.
CREATE FUNCTION "authorization".maintain_decision_log_partitions(
    today date,
    days_ahead integer,
    keep_days integer,
    OUT created integer,
    OUT dropped integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    day date;
    name text;
    partition record;
    upper_bound date;
BEGIN
    created := 0;
    dropped := 0;
    IF days_ahead NOT BETWEEN 0 AND 31 OR keep_days NOT BETWEEN 1 AND 400 THEN
        RAISE EXCEPTION 'days ahead is from 0 to 31 and days kept from 1 to 400'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR day IN SELECT generate_series(today - 1, today + days_ahead, interval '1 day')::date LOOP
        name := 'decision_log_' || to_char(day, 'YYYYMMDD');
        IF to_regclass(format('"authorization".%I', name)) IS NULL THEN
            -- Built apart, filled with that day's rows from the default
            -- partition, then attached: attaching would fail while the
            -- default partition still held rows of the day.
            EXECUTE format(
                'CREATE TABLE "authorization".%I (LIKE "authorization".decision_log INCLUDING DEFAULTS INCLUDING CONSTRAINTS)',
                name);
            EXECUTE format(
                'WITH moved AS (DELETE FROM "authorization".decision_log_default
                     WHERE decided_at >= %L::date AND decided_at < %L::date RETURNING *)
                 INSERT INTO "authorization".%I SELECT * FROM moved',
                day, day + 1, name);
            EXECUTE format(
                'ALTER TABLE "authorization".decision_log ATTACH PARTITION "authorization".%I
                     FOR VALUES FROM (%L) TO (%L)',
                name, day::timestamptz, (day + 1)::timestamptz);
            created := created + 1;
        END IF;
    END LOOP;
    FOR partition IN
        SELECT child.relname AS relname
        FROM pg_inherits
        JOIN pg_class child ON child.oid = pg_inherits.inhrelid
        JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
        JOIN pg_namespace ON pg_namespace.oid = parent.relnamespace
        WHERE pg_namespace.nspname = 'authorization'
          AND parent.relname = 'decision_log'
          AND child.relname ~ '^decision_log_[0-9]{8}$'
    LOOP
        upper_bound := to_date(substring(partition.relname FROM 14), 'YYYYMMDD') + 1;
        IF upper_bound < today - keep_days THEN
            EXECUTE format('DROP TABLE "authorization".%I', partition.relname);
            dropped := dropped + 1;
        END IF;
    END LOOP;
END
$$;

REVOKE ALL ON FUNCTION "authorization".maintain_decision_log_partitions(date, integer, integer)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "authorization".maintain_decision_log_partitions(date, integer, integer)
    TO hodor_platform;

-- The partitions of the day of the migration and the week after it, so
-- that records land in a partition of their own before the worker first
-- runs.
SELECT "authorization".maintain_decision_log_partitions(current_date, 7, 400);

-- Finds the oldest records of a tenant quickly for the retention job.
CREATE INDEX policy_agent_decision_decided
    ON "authorization".policy_agent_decision (tenant_id, decided_at);
