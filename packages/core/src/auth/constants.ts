export const RESERVED_AUTH_PARAM_KEYS = new Set([
  "client_id",
  "client_secret",
  "redirect_uri",
  "request_uri",
  "request",
  "response_type",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
  "code_verifier",
  "nonce",
  "prompt",
  "display",
  "registration",
  "id_token_hint",
  "acr_values",
  "ui_locales",
  "login_hint",
  "claims",
  "audience",
  "response_mode",
  "max_age",
  "guardhouse_form_post_csrf",
]);

export const REDIRECT_LIKE_PARAM_KEYS = new Set([
  "redirect",
  "redirect_to",
  "return_to",
  "returnurl",
  "next",
  "continue",
  "url",
  "destination",
  "callback",
  "callback_url",
  "post_login_redirect",
  "post_auth_redirect",
]);

export const AUTH_PARAM_KEY_PATTERN = /^[A-Za-z0-9._~-]+$/;
// State should be a cryptographically secure random value.
export const STATE_TOKEN_PATTERN = /^[A-Za-z0-9._~-]{16,512}$/;
// Allow HTTPS URLs, local loopback HTTP for development, and PAR request_uri URNs.
export const REQUEST_URI_PATTERN =
  /^(?:https:\/\/[^\s\\]{1,2048}|http:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|10\.0\.2\.2)(?::\d{1,5})?(?:\/[^\s\\]{0,2048})?|urn:ietf:params:oauth:request_uri:[A-Za-z0-9._~!$&'()*+,;=:@/?%-]{1,2048})$/i;
// Per OIDC, prompt=none must not be combined with any other prompt value.
export const PROMPT_PATTERN =
  /^(?:none|(?:login|consent|select_account)(?: (?:login|consent|select_account)){0,2})$/;
export const ACR_VALUE_PATTERN = /^[A-Za-z0-9._:/-]{1,128}$/;
export const UI_LOCALE_PATTERN = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/;
export const LOGIN_HINT_PATTERN = /^[^\s<>"'`()\\]{1,256}$/;
export const CLAIMS_KEY_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;

export const MAX_TRACKED_STATE_TOKENS = 1024;
export const MAX_AUTH_EXTRA_PARAM_KEY_LENGTH = 128;
export const MAX_AUTH_EXTRA_PARAM_VALUE_LENGTH = 4096;
export const MAX_STATE_BINDINGS = 1024;
export const MAX_UI_LOCALE_COUNT = 10;
export const MAX_ACR_VALUE_COUNT = 10;
export const MAX_CLAIMS_DEPTH = 5;
export const MAX_CLAIMS_KEYS = 128;

export const SILENT_AUTH_ERROR_CODES = new Set([
  "interaction_required",
  "login_required",
  "consent_required",
  "account_selection_required",
]);

export const OAUTH_CALLBACK_SENSITIVE_KEYS = new Set([
  "code",
  "state",
  "response",
  "error",
  "error_description",
  "error_uri",
  "access_token",
  "id_token",
  "refresh_token",
  "token_type",
  "expires_in",
  "scope",
  "session_state",
]);

export const AUTHORIZATION_URL_SENSITIVE_KEYS = new Set([
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "id_token_hint",
  "guardhouse_form_post_csrf",
]);

export const POST_LOGOUT_SENSITIVE_KEYS = new Set([
  "id_token_hint",
  "post_logout_redirect_uri",
]);

export const UNSAFE_FRAGMENT_VALUE_PATTERN =
  /[\r\n]|<|>|javascript:|data:|vbscript:|file:/i;
export const MAX_CALLBACK_URL_LENGTH = 8192;
