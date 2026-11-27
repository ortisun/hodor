-- The identity context: a person's standard claims of OpenID Connect.
-- See docs/architecture/contexts/identity.md, "Standard claims", and
-- docs/decisions/0065-where-the-standard-claims-come-from.md.
--
-- The domain checks every rule; the database checks what it can of each, so
-- that a row written past the domain still holds the bounds every reader
-- counts on, such as the bound of a token a claim mapper writes into.

ALTER TABLE identity."user"
    ADD COLUMN given_name             text,
    ADD COLUMN family_name            text,
    ADD COLUMN middle_name            text,
    ADD COLUMN nickname               text,
    ADD COLUMN profile                text,
    ADD COLUMN picture                text,
    ADD COLUMN website                text,
    ADD COLUMN gender                 text,
    ADD COLUMN birthdate              text,
    ADD COLUMN zoneinfo               text,
    ADD COLUMN phone_number           text,
    ADD COLUMN phone_number_verified  boolean NOT NULL DEFAULT false,
    ADD COLUMN address_formatted      text,
    ADD COLUMN address_street_address text,
    ADD COLUMN address_locality       text,
    ADD COLUMN address_region         text,
    ADD COLUMN address_postal_code    text,
    ADD COLUMN address_country        text,
    ADD CONSTRAINT user_claims_length CHECK (
        char_length(given_name) BETWEEN 1 AND 200
        AND char_length(family_name) BETWEEN 1 AND 200
        AND char_length(middle_name) BETWEEN 1 AND 200
        AND char_length(nickname) BETWEEN 1 AND 200
        AND octet_length(profile) BETWEEN 1 AND 1024
        AND octet_length(picture) BETWEEN 1 AND 1024
        AND octet_length(website) BETWEEN 1 AND 1024
        AND char_length(gender) BETWEEN 1 AND 50
        AND octet_length(zoneinfo) BETWEEN 1 AND 64
        AND char_length(address_formatted) BETWEEN 1 AND 300
        AND char_length(address_street_address) BETWEEN 1 AND 200
        AND char_length(address_locality) BETWEEN 1 AND 100
        AND char_length(address_region) BETWEEN 1 AND 100
        AND char_length(address_postal_code) BETWEEN 1 AND 20
        AND char_length(address_country) BETWEEN 1 AND 100
    ),
    ADD CONSTRAINT user_birthdate_shape CHECK (
        birthdate ~ '^[0-9]{4}(-[0-9]{2}-[0-9]{2})?$'
    ),
    ADD CONSTRAINT user_phone_number_shape CHECK (
        phone_number ~ '^\+[0-9]{4,15}(;ext=[0-9]{1,10})?$'
    ),
    ADD CONSTRAINT user_phone_number_verified CHECK (
        phone_number IS NOT NULL OR NOT phone_number_verified
    );

-- The given and family names SCIM set move here from the provisioning
-- context, which stops keeping them. A name longer than the identity
-- context allows is left behind; SCIM gives it again with its next change.
-- Row-level security is forced on both tables, so it is lifted for the move
-- alone, in this transaction, and forced again.
ALTER TABLE identity."user" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE provisioning.user_attribute NO FORCE ROW LEVEL SECURITY;

UPDATE identity."user" AS person
    SET given_name = CASE
            WHEN char_length(attribute.given_name) <= 200 THEN attribute.given_name
        END,
        family_name = CASE
            WHEN char_length(attribute.family_name) <= 200 THEN attribute.family_name
        END
    FROM provisioning.user_attribute AS attribute
    WHERE attribute.tenant_id = person.tenant_id
      AND attribute.user_id = person.id
      AND person.status <> 'deleted'
      AND (attribute.given_name IS NOT NULL OR attribute.family_name IS NOT NULL);

ALTER TABLE identity."user" FORCE ROW LEVEL SECURITY;
ALTER TABLE provisioning.user_attribute FORCE ROW LEVEL SECURITY;

ALTER TABLE provisioning.user_attribute
    DROP CONSTRAINT user_attribute_text_length,
    DROP COLUMN given_name,
    DROP COLUMN family_name,
    ADD CONSTRAINT user_attribute_text_length CHECK (
        char_length(external_id) BETWEEN 1 AND 256
        AND char_length(name_formatted) BETWEEN 1 AND 256
        AND char_length(employee_number) BETWEEN 1 AND 256
        AND char_length(cost_center) BETWEEN 1 AND 256
        AND char_length(organization) BETWEEN 1 AND 256
        AND char_length(division) BETWEEN 1 AND 256
        AND char_length(department) BETWEEN 1 AND 256
        AND char_length(manager_id) BETWEEN 1 AND 256
    );
