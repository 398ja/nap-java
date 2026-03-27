CREATE TABLE nap_challenges (
    challenge_id     VARCHAR(24)  PRIMARY KEY,
    challenge        VARCHAR(64)  NOT NULL,
    npub             VARCHAR(64)  NOT NULL,
    pubkey           VARCHAR(64)  NOT NULL,
    auth_url         VARCHAR(512) NOT NULL,
    auth_method      VARCHAR(8)   NOT NULL DEFAULT 'POST',
    state            VARCHAR(16)  NOT NULL DEFAULT 'issued',
    issued_at        BIGINT       NOT NULL,
    expires_at       BIGINT       NOT NULL,
    redeemed_event_id VARCHAR(64),
    redeemed_session_id VARCHAR(48),
    result_cache_until BIGINT,
    CONSTRAINT uq_challenge_event UNIQUE (redeemed_event_id)
);
CREATE INDEX idx_nap_challenges_state_expiry ON nap_challenges (state, expires_at);

CREATE TABLE nap_sessions (
    session_id       VARCHAR(48)  PRIMARY KEY,
    challenge_id     VARCHAR(24)  NOT NULL UNIQUE,
    access_token     VARCHAR(64)  NOT NULL UNIQUE,
    principal_npub   VARCHAR(64)  NOT NULL,
    principal_pubkey VARCHAR(64)  NOT NULL,
    roles            JSONB        NOT NULL DEFAULT '[]',
    permissions      JSONB        NOT NULL DEFAULT '[]',
    issued_at        BIGINT       NOT NULL,
    expires_at       BIGINT       NOT NULL,
    revoked_at       BIGINT,
    step_up_token    VARCHAR(64),
    step_up_expires_at BIGINT,
    CONSTRAINT uq_session_challenge UNIQUE (challenge_id)
);
CREATE INDEX idx_nap_sessions_pubkey ON nap_sessions (principal_pubkey);
CREATE INDEX idx_nap_sessions_access_token ON nap_sessions (access_token);
CREATE INDEX idx_nap_sessions_expiry ON nap_sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE nap_acl (
    app_id           VARCHAR(64)  NOT NULL,
    pubkey           VARCHAR(64)  NOT NULL,
    role             VARCHAR(64)  NOT NULL,
    suspended        BOOLEAN      NOT NULL DEFAULT FALSE,
    PRIMARY KEY (app_id, pubkey)
);
CREATE INDEX idx_nap_acl_pubkey ON nap_acl (pubkey);
