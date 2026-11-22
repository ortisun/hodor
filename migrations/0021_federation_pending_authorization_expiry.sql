-- The federation context: finding pending authorizations that expired, for
-- the cleanup job of hodor-worker. See docs/architecture/contexts/federation.md,
-- "The pending authorization".

CREATE INDEX pending_authorization_expiry_idx
    ON federation.pending_authorization (expires_at);
