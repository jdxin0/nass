CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE apps (
    name          TEXT PRIMARY KEY,
    enabled       INTEGER NOT NULL DEFAULT 0,
    settings_json TEXT    NOT NULL DEFAULT '{}',
    enabled_at    TIMESTAMP
);

CREATE TABLE oidc_clients (
    client_id          TEXT PRIMARY KEY,
    app_name           TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    redirect_uris      TEXT NOT NULL,
    scopes             TEXT NOT NULL DEFAULT '["openid","profile","email"]',
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_name) REFERENCES apps(name) ON DELETE CASCADE
);

CREATE TABLE oidc_auth_requests (
    id                    TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               INTEGER,
    redirect_uri          TEXT NOT NULL,
    state                 TEXT,
    nonce                 TEXT,
    scopes                TEXT NOT NULL,
    response_type         TEXT,
    code_challenge        TEXT,
    code_challenge_method TEXT,
    auth_time             TIMESTAMP,
    completed             INTEGER NOT NULL DEFAULT 0,
    created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at            TIMESTAMP NOT NULL
);

CREATE TABLE oidc_auth_codes (
    code       TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (request_id) REFERENCES oidc_auth_requests(id) ON DELETE CASCADE
);

CREATE TABLE oidc_refresh_tokens (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    client_id  TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    audience   TEXT NOT NULL DEFAULT '',
    auth_time  TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE portal_sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_oidc_auth_requests_expires ON oidc_auth_requests(expires_at);
CREATE INDEX idx_oidc_auth_codes_expires ON oidc_auth_codes(expires_at);
CREATE INDEX idx_oidc_refresh_tokens_user ON oidc_refresh_tokens(user_id);
CREATE INDEX idx_portal_sessions_user ON portal_sessions(user_id);
