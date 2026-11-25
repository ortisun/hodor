-- Issue-110: an identity binds the clients of one service account, so that
-- `hodor-ext-authz` holds a client in each application it protects with
-- its one mesh identity. Several clients of a tenant may now be bound to
-- one SPIFFE identifier or one Linkerd identity, as long as they all act
-- as the same principal; the client store checks that under a
-- transaction-scoped advisory lock on the tenant and the identity.
-- The indexes stay, no longer unique, to find the clients of an identity.
-- See docs/decisions/0058-hodor-ext-authz.md and
-- docs/architecture/contexts/oauth.md, "The SPIFFE identifier of a client".

DROP INDEX oauth.client_spiffe_id_unique;
CREATE INDEX client_spiffe_id_bound ON oauth.client (tenant_id, spiffe_id)
    WHERE spiffe_id IS NOT NULL;

DROP INDEX oauth.client_linkerd_identity_unique;
CREATE INDEX client_linkerd_identity_bound ON oauth.client (tenant_id, linkerd_identity)
    WHERE linkerd_identity IS NOT NULL;
