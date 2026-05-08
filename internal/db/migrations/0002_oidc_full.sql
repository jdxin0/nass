-- Round out the OIDC schema for the auth-code flow.

ALTER TABLE oidc_auth_requests ADD COLUMN response_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_auth_requests ADD COLUMN prompt        TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_auth_requests ADD COLUMN ui_locales    TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_auth_requests ADD COLUMN login_hint    TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_auth_requests ADD COLUMN max_age       INTEGER;

ALTER TABLE oidc_clients ADD COLUMN application_type TEXT NOT NULL DEFAULT 'web';
ALTER TABLE oidc_clients ADD COLUMN auth_method      TEXT NOT NULL DEFAULT 'client_secret_basic';
ALTER TABLE oidc_clients ADD COLUMN grant_types      TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]';
ALTER TABLE oidc_clients ADD COLUMN response_types   TEXT NOT NULL DEFAULT '["code"]';
ALTER TABLE oidc_clients ADD COLUMN dev_mode         INTEGER NOT NULL DEFAULT 0;

CREATE TABLE oidc_access_tokens (
    id               TEXT PRIMARY KEY,
    client_id        TEXT NOT NULL,
    user_id          INTEGER NOT NULL,
    refresh_token_id TEXT,
    audience         TEXT NOT NULL,
    scopes           TEXT NOT NULL,
    expires_at       TIMESTAMP NOT NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_oidc_access_tokens_expires ON oidc_access_tokens(expires_at);
CREATE INDEX idx_oidc_access_tokens_refresh ON oidc_access_tokens(refresh_token_id);
