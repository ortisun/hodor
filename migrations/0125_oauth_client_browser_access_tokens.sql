-- Issue-128: an access token through the browser, for a client an
-- administrator marks. The mark is kept with the client, as the scopes the
-- token may carry beyond those of OpenID Connect, who set it and when; the
-- four response types that return an access token are allowed only with it.
-- No client made before has it.
-- See docs/architecture/contexts/oauth.md, "The mark for access tokens
-- through the browser", and
-- docs/decisions/0083-the-mark-for-access-tokens-through-the-browser.md.

ALTER TABLE oauth.client
    -- {"scopes": [...], "marked_by": {"kind": ..., "id": ...}, "marked_at": "..."}
    ADD COLUMN browser_access_tokens jsonb;

ALTER TABLE oauth.client
    DROP CONSTRAINT client_response_types_known,
    ADD CONSTRAINT client_response_types_known CHECK (
        response_types <@ ARRAY[
            'code', 'id_token', 'code id_token', 'none',
            'token', 'id_token token', 'code token', 'code id_token token'
        ]::text[]),
    -- A member left out reads as null, which the check would let pass:
    -- it is read as false instead.
    ADD CONSTRAINT client_browser_access_tokens_shape CHECK (
        browser_access_tokens IS NULL
        OR COALESCE(
            jsonb_typeof(browser_access_tokens) = 'object'
            AND jsonb_typeof(browser_access_tokens -> 'scopes') = 'array'
            AND jsonb_array_length(browser_access_tokens -> 'scopes') <= 50
            AND jsonb_typeof(browser_access_tokens -> 'marked_by') = 'object'
            AND jsonb_typeof(browser_access_tokens -> 'marked_at') = 'string',
            false)),
    -- Only a client that sends people to the authorization endpoint is
    -- marked, and never one whose access tokens are bound to its
    -- certificate: the browser brings no certificate of the client.
    ADD CONSTRAINT client_browser_access_tokens_need_code CHECK (
        browser_access_tokens IS NULL
        OR ('authorization_code' = ANY (grant_types)
            AND NOT certificate_bound_access_tokens)),
    -- A type that returns an access token is only for a marked client.
    ADD CONSTRAINT client_browser_access_tokens_for_token_types CHECK (
        browser_access_tokens IS NOT NULL
        OR NOT (response_types
            && ARRAY['token', 'id_token token', 'code token', 'code id_token token']::text[]));

-- The marked clients of a tenant, for its security posture.
CREATE INDEX client_marked_for_browser_access_tokens
    ON oauth.client (tenant_id)
    WHERE browser_access_tokens IS NOT NULL;
