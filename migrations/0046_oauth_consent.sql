-- Consent: what a person agreed to for a client, its history, the answer a
-- waiting request was given, and how long a consent lasts.
-- See docs/architecture/contexts/oauth.md, "Consent".

-- How long a person's consent to the client lasts: 1 to 730 days, 365 by
-- default.
ALTER TABLE oauth.client
    ADD COLUMN consent_seconds integer NOT NULL DEFAULT 31536000,
    ADD CONSTRAINT client_consent_bounded CHECK (
        consent_seconds >= 86400 AND consent_seconds <= 730 * 86400);

-- A request that waits for consent says for whom, in which session, and,
-- once answered, the answer.
ALTER TABLE oauth.authorization_request
    ADD COLUMN consent_user_id    uuid,
    ADD COLUMN consent_session_id uuid,
    ADD COLUMN consent_answer     text,
    ADD CONSTRAINT authorization_request_consent_whole CHECK (
        (consent_user_id IS NULL) = (consent_session_id IS NULL)),
    ADD CONSTRAINT authorization_request_consent_answer_known CHECK (
        consent_answer IS NULL
        OR (consent_answer IN ('agreed', 'refused') AND consent_user_id IS NOT NULL));

CREATE TABLE oauth.consent (
    tenant_id    uuid        NOT NULL,
    user_id      uuid        NOT NULL,
    client_id    uuid        NOT NULL,
    -- Never `offline_access`: it is asked every time.
    scopes       text[]      NOT NULL,
    audiences    text[]      COLLATE "C" NOT NULL,
    given_at     timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    withdrawn_at timestamptz,
    withdrawn_by text,
    PRIMARY KEY (tenant_id, user_id, client_id),
    CONSTRAINT consent_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT consent_offline_access_not_kept CHECK (NOT ('offline_access' = ANY (scopes))),
    CONSTRAINT consent_lifetime_bounded CHECK (
        expires_at > given_at AND expires_at <= given_at + interval '730 days'),
    -- A withdrawn consent says when and by whom; one that stands, neither.
    CONSTRAINT consent_withdrawal_whole CHECK (
        (withdrawn_at IS NULL) = (withdrawn_by IS NULL)),
    CONSTRAINT consent_withdrawn_by_known CHECK (
        withdrawn_by IS NULL OR withdrawn_by IN ('person', 'administrator'))
);

SELECT platform.enable_tenant_rls('oauth.consent');
CREATE INDEX consent_client_idx ON oauth.consent (tenant_id, client_id);

CREATE TABLE oauth.consent_history (
    tenant_id uuid        NOT NULL,
    id        uuid        NOT NULL,
    user_id   uuid        NOT NULL,
    client_id uuid        NOT NULL,
    action    text        NOT NULL,
    scopes    text[]      NOT NULL,
    audiences text[]      COLLATE "C" NOT NULL,
    by_whom   text        NOT NULL,
    at        timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT consent_history_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT consent_history_action_known CHECK (action IN ('given', 'refused', 'withdrawn')),
    CONSTRAINT consent_history_by_known CHECK (by_whom IN ('person', 'administrator'))
);

SELECT platform.enable_tenant_rls('oauth.consent_history');
CREATE INDEX consent_history_person_idx ON oauth.consent_history (tenant_id, user_id, at);

-- The history is added to and read; the application never changes it.
REVOKE UPDATE, DELETE ON oauth.consent_history FROM hodor_app;

-- A person's active grants for a client are found when a consent is
-- withdrawn.
CREATE INDEX authorization_grant_person_idx
    ON oauth.authorization_grant (tenant_id, user_id, client_id);
