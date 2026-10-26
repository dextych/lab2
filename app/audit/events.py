#Константы имён аудит-событий

USER_CREATED = "user.created"
USER_LOGIN_SUCCESS = "user.login.success"
USER_LOGIN_FAILURE = "user.login.failure"
USER_DISABLED = "user.disabled"

CLIENT_CREATED = "client.created"
CLIENT_SECRET_ROTATED = "client.secret_rotated"
CLIENT_DISABLED = "client.disabled"
CLIENT_ENABLED = "client.enabled"

# === OAuth: authorize ===
OAUTH_AUTHORIZE_SUCCESS = "oauth.authorize.success"
OAUTH_AUTHORIZE_FAILURE = "oauth.authorize.failure"

# === OAuth: tokens ===
TOKEN_ISSUED = "token.issued"
TOKEN_REFRESHED = "token.refreshed"
TOKEN_REUSE_DETECTED = "token.reuse_detected"
TOKEN_REVOKED = "token.revoked"

# === OAuth: auth code ===
AUTH_CODE_REUSE_DETECTED = "auth_code.reuse_detected"

# === Сессии ===
SESSION_REVOKED = "session.revoked"
