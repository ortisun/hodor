-- A third built-in role of Hodor's administration, `certificate_signer`,
-- which holds only `certificate-authority:sign`: the role of the workload
-- that signs the intermediates of a tenant's meshes.
-- See docs/architecture/contexts/authorization.md, "Roles", and Decision
-- 0071.

ALTER TABLE "authorization".role_assignment
    DROP CONSTRAINT role_assignment_built_in,
    -- The built-in roles: only these three, only to users, for the whole
    -- tenant, without a start or an end.
    ADD CONSTRAINT role_assignment_built_in CHECK (
        namespace <> 'hodor:admin'
        OR (role IN ('tenant_administrator', 'tenant_auditor', 'certificate_signer')
            AND principal_kind = 'user'
            AND application = ''
            AND valid_from IS NULL
            AND valid_until IS NULL));
