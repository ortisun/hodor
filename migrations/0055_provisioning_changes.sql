-- What changing through SCIM needs to keep: the type of each email
-- address, and when a DELETE deprovisioned a user whom the tenant's policy
-- deactivates.
-- See docs/architecture/contexts/provisioning.md, "Storage".

ALTER TABLE provisioning.user_attribute
    ADD COLUMN email_types jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN removed_at  timestamptz,
    ADD CONSTRAINT user_attribute_email_types_object CHECK (jsonb_typeof(email_types) = 'object');
