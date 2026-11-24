-- Token exchange (RFC 8693): what an agent's client may exchange for
-- which audience, and the token an exchanged token came from.
-- See docs/architecture/contexts/oauth.md, "Token exchange".

-- A client with a principal has client credentials and may have token
-- exchange besides; token exchange needs a principal and its rules, and
-- only it has rules.
ALTER TABLE oauth.client
    DROP CONSTRAINT client_principal_only_client_credentials,
    ADD COLUMN exchange_rules jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT client_principal_grants CHECK (
        principal_id IS NULL
        OR ('client_credentials' = ANY (grant_types)
            AND grant_types <@ ARRAY[
                'client_credentials',
                'urn:ietf:params:oauth:grant-type:token-exchange'
            ]::text[])),
    ADD CONSTRAINT client_token_exchange_needs_principal CHECK (
        NOT ('urn:ietf:params:oauth:grant-type:token-exchange' = ANY (grant_types))
        OR principal_id IS NOT NULL),
    ADD CONSTRAINT client_exchange_rules_shape CHECK (
        jsonb_typeof(exchange_rules) = 'array'
        AND jsonb_array_length(exchange_rules) <= 20
        AND (jsonb_array_length(exchange_rules) = 0)
            = NOT ('urn:ietf:params:oauth:grant-type:token-exchange' = ANY (grant_types)));

-- The token an exchanged token came from. A record goes with its parent,
-- and the register finds a chain one record at a time.
ALTER TABLE oauth.access_token
    ADD COLUMN parent_token_id text COLLATE "C",
    ADD CONSTRAINT access_token_parent_fk
        FOREIGN KEY (tenant_id, parent_token_id)
        REFERENCES oauth.access_token (tenant_id, token_id) ON DELETE CASCADE;

CREATE INDEX access_token_parent_idx ON oauth.access_token (tenant_id, parent_token_id)
    WHERE parent_token_id IS NOT NULL;
