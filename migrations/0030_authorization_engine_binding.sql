-- The authorization context: which engine answers for a resource server.
-- See docs/architecture/contexts/authorization.md, "Bindings" and
-- "Storage".

-- `namespace` is a resource server's audience but deliberately not a
-- foreign key: contexts do not reference each other's tables. Hodor's
-- administration, `hodor:admin`, is answered by its own engine and is never
-- stored.
CREATE TABLE "authorization".engine_binding (
    tenant_id            uuid        NOT NULL,
    namespace            text        COLLATE "C" NOT NULL,
    engine               text        NOT NULL,
    timeout_milliseconds integer     NOT NULL,
    sensitive            boolean     NOT NULL,
    fail_open_actions    text[]      NOT NULL,
    trust_asserted       boolean     NOT NULL,
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, namespace),
    CONSTRAINT engine_binding_not_administration CHECK (namespace <> 'hodor:admin'),
    CONSTRAINT engine_binding_namespace_shape CHECK (
        char_length(namespace) <= 255
        AND (namespace LIKE 'https://_%' OR namespace LIKE 'urn:_%')),
    CONSTRAINT engine_binding_engine_shape CHECK (engine ~ '^[a-z][a-z0-9_-]{0,63}$'),
    CONSTRAINT engine_binding_timeout CHECK (timeout_milliseconds BETWEEN 1 AND 5000),
    -- Nothing fails open in a sensitive namespace.
    CONSTRAINT engine_binding_sensitive_fails_closed
        CHECK (NOT sensitive OR cardinality(fail_open_actions) = 0),
    CONSTRAINT engine_binding_fail_open_bounded CHECK (cardinality(fail_open_actions) <= 50)
);

SELECT platform.enable_tenant_rls('"authorization".engine_binding');
