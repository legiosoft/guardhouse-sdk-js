export const DEFAULT_ENDPOINTS = {
  token: "/connect/token",
  userInfo: "/connect/userinfo",
  introspection: "/connect/introspect",
  revocation: "/connect/revoke",
};

export const RESERVED_TOKEN_BODY_PARAM_KEYS = new Set([
  "grant_type",
  "code",
  "refresh_token",
  "client_id",
  "client_secret",
  "code_verifier",
  "redirect_uri",
  "scope",
  "resource",
  "audience",
]);

export const TOKEN_PARAM_KEY_PATTERN = /^[A-Za-z0-9._~-]+$/;
export const REGISTRATION_METADATA_KEY_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

export const BLOCKED_REGISTRATION_METADATA_KEYS = new Set([
  "registration_properties",
  "sdk_version",
  "environment",
  "internal_capabilities",
]);

export const DISCOVERY_ENDPOINT_KEYS = [
  "authorization_endpoint",
  "token_endpoint",
  "userinfo_endpoint",
  "jwks_uri",
  "revocation_endpoint",
  "introspection_endpoint",
  "registration_endpoint",
  "end_session_endpoint",
  "pushed_authorization_request_endpoint",
] as const;

export const SAFE_HTTP_METHODS = new Set(["GET", "HEAD", "POST"]);
export const ALLOWED_HTTP_METHODS = new Set(["GET", "HEAD", "POST"]);

// Only standardized, non-secret OAuth/OIDC error identifiers may cross the
// network trust boundary into exceptions or logs. An authorization server can
// otherwise echo a submitted credential in its `error` member.
export const SAFE_OAUTH_ERROR_CODES = new Set([
  "access_denied",
  "account_selection_required",
  "authorization_pending",
  "consent_required",
  "expired_token",
  "insufficient_scope",
  "interaction_required",
  "invalid_binding_message",
  "invalid_client",
  "invalid_client_metadata",
  "invalid_dpop_proof",
  "invalid_grant",
  "invalid_request",
  "invalid_request_object",
  "invalid_request_uri",
  "invalid_redirect_uri",
  "invalid_scope",
  "invalid_software_statement",
  "invalid_target",
  "invalid_token",
  "login_required",
  "registration_not_supported",
  "request_not_supported",
  "request_uri_not_supported",
  "server_error",
  "slow_down",
  "temporarily_unavailable",
  "transaction_failed",
  "unauthorized_client",
  "unapproved_software_statement",
  "unsupported_grant_type",
  "unsupported_response_type",
  "unsupported_token_type",
  "use_dpop_nonce",
]);

export const PKCE_CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]+$/;
export const STATE_PATTERN = /^[A-Za-z0-9-._~]{8,128}$/;
export const DPOP_NONCE_PATTERN = /^[A-Za-z0-9-_.~+]+$/;
export const SAFE_COOKIE_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;

export const SILENT_AUTH_ERROR_CODES = new Set([
  "interaction_required",
  "login_required",
  "consent_required",
  "account_selection_required",
]);

export const DEFAULT_MAX_AUTH_HEADER_BYTES = 4096;
export const DEFAULT_SESSION_STORAGE_KEY_PREFIX = "guardhouse:session:v3";
export const LEGACY_V2_SESSION_STORAGE_KEY_PREFIX = "guardhouse:session:v2";
export const LEGACY_DEFAULT_SESSION_STORAGE_KEY = "guardhouse:session:v1";
export const MAX_DPOP_PROOF_LENGTH = 8192;
export const MAX_TOKEN_PARAM_KEY_LENGTH = 128;
export const MAX_TOKEN_PARAM_VALUE_LENGTH = 4096;
export const DEFAULT_MAX_SILENT_AUTH_ATTEMPTS = 3;
export const DEFAULT_DISCOVERY_CACHE_TTL_MS = 60 * 60 * 1000;
export const MAX_DISCOVERY_CACHE_TTL_MS = 60 * 60 * 1000;
