-- Platform foundation: database roles and the row-level security helpers
-- that every tenant table uses. See docs/architecture/multi-tenancy.md.

-- Group roles without login. Operators create login roles that are members
-- of these; the application never connects as the owner of the tables.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'holdor_app') THEN
        CREATE ROLE holdor_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'holdor_platform') THEN
        CREATE ROLE holdor_platform NOLOGIN;
    END IF;
END
$$;

CREATE SCHEMA platform;
GRANT USAGE ON SCHEMA platform TO holdor_app, holdor_platform;

-- The tenant of the current transaction, set by the application with a
-- transaction-local setting. NULL when unset, which matches no row.
CREATE FUNCTION platform.current_tenant_id() RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT nullif(current_setting('app.tenant_id', true), '')::uuid
$$;

-- Puts a table under tenant isolation. Every migration that creates a
-- tenant table calls this, so all tables carry the same policies.
--
--   * RLS is enabled and forced, so it also applies to the table owner.
--   * Any role sees and writes only rows of the current tenant.
--   * holdor_platform, used by cross-tenant jobs, sees all rows.
CREATE FUNCTION platform.enable_tenant_rls(target regclass) RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', target);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', target);
    EXECUTE format(
        'CREATE POLICY tenant_isolation ON %s
             USING (tenant_id = platform.current_tenant_id())
             WITH CHECK (tenant_id = platform.current_tenant_id())',
        target
    );
    EXECUTE format(
        'CREATE POLICY platform_access ON %s TO holdor_platform
             USING (true) WITH CHECK (true)',
        target
    );
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO holdor_app, holdor_platform',
        target
    );
END
$$;
