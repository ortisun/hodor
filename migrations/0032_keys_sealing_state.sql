-- The keys context: whether a tenant still opens secrets of the first
-- format, the one 0.1.0 sealed directly with a root key.
-- See docs/architecture/contexts/keys.md, "Secrets under data keys", and
-- docs/security/secrets-at-rest.md.

-- No row: the first format still opens. A row: it no longer does.
CREATE TABLE keys.sealing_state (
    tenant_id               uuid        NOT NULL,
    first_format_refused_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id)
);

SELECT platform.enable_tenant_rls('keys.sealing_state');

-- Refusing is final: the application may record it, never undo it.
REVOKE UPDATE, DELETE ON keys.sealing_state FROM hodor_app;
