-- The tenant context. See docs/architecture/contexts/tenant.md.

CREATE SCHEMA tenant;
GRANT USAGE ON SCHEMA tenant TO hodor_app, hodor_platform;

CREATE TABLE tenant.tenant (
    tenant_id              uuid        NOT NULL,
    id                     uuid        NOT NULL,
    slug                   text        NOT NULL,
    display_name           text        NOT NULL,
    status                 text        NOT NULL,
    status_reason          text,
    settings               jsonb       NOT NULL,
    deletion_scheduled_for timestamptz,
    created_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL,
    version                integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    -- A tenant's own row is the one row whose tenant is itself.
    CONSTRAINT tenant_is_its_own_tenant CHECK (id = tenant_id),
    CONSTRAINT tenant_slug_unique UNIQUE (slug),
    CONSTRAINT tenant_status_known CHECK (
        status IN ('provisioning', 'active', 'suspended', 'pending_deletion', 'deleted')
    ),
    CONSTRAINT tenant_deletion_date_only_while_pending CHECK (
        (status = 'pending_deletion') = (deletion_scheduled_for IS NOT NULL)
    )
);

SELECT platform.enable_tenant_rls('tenant.tenant');

-- The directory: what is needed to route a request to a tenant, and nothing
-- else. It is deliberately outside row-level security, because a request
-- is resolved from a slug before any tenant is known. The application can
-- only read it; the trigger below is its only writer.
CREATE TABLE platform.tenant_directory (
    slug      text PRIMARY KEY,
    tenant_id uuid NOT NULL UNIQUE,
    status    text NOT NULL
);

GRANT SELECT ON platform.tenant_directory TO hodor_app, hodor_platform;

-- Runs with the rights of the schema owner, so that the application role
-- needs no write access to the directory.
CREATE FUNCTION platform.sync_tenant_directory() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    INSERT INTO platform.tenant_directory (slug, tenant_id, status)
    VALUES (NEW.slug, NEW.id, NEW.status)
    ON CONFLICT (tenant_id) DO UPDATE SET status = EXCLUDED.status;
    RETURN NEW;
END
$$;

CREATE TRIGGER tenant_directory_sync
    AFTER INSERT OR UPDATE OF status ON tenant.tenant
    FOR EACH ROW EXECUTE FUNCTION platform.sync_tenant_directory();

-- A slug never changes: addresses, issuer names and tokens are built from it.
CREATE FUNCTION tenant.forbid_slug_change() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.slug IS DISTINCT FROM OLD.slug THEN
        RAISE EXCEPTION 'a tenant slug cannot be changed'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER tenant_slug_is_immutable
    BEFORE UPDATE ON tenant.tenant
    FOR EACH ROW EXECUTE FUNCTION tenant.forbid_slug_change();
