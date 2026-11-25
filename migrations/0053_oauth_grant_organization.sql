-- The organization a person signed in for, which every token of the grant
-- carries as `org_id`.
-- See docs/architecture/contexts/oauth.md, "The organization of a sign-in".

-- No reference to the organization: the OAuth context does not reach into
-- the identity context's tables, and a grant of an organization that was
-- deleted is refused at its next refresh, its person no longer a member.
ALTER TABLE oauth.authorization_grant
    ADD COLUMN organization uuid;
