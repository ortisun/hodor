-- The claims a grant gives through the `claims` parameter of its request:
-- those asked for the ID token and for UserInfo that a scope consented to
-- for the client covers, decided when the code is issued.
-- See docs/architecture/contexts/oauth.md, "The `claims` parameter", and
-- docs/decisions/0068-claims-of-every-consented-scope.md.

ALTER TABLE oauth.authorization_grant
    ADD COLUMN id_token_claims text[] NOT NULL DEFAULT '{}',
    ADD COLUMN userinfo_claims text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT authorization_grant_claims_bounded CHECK (
        cardinality(id_token_claims) <= 64 AND cardinality(userinfo_claims) <= 64
    );
