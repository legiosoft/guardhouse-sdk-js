export interface GuardhouseLogger {
  debug: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
}

let globalDebugEnabled = false;

const REDACTED_VALUE = "[REDACTED]";
const SENSITIVE_KEY_PATTERN =
  /authorization|token|secret|password|assertion|cookie|code_verifier/i;
const BEARER_OR_BASIC_PATTERN = /^(?:Bearer|Basic)\s+/i;
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const QUERY_SECRET_PATTERN =
  /([?&](?:access_token|refresh_token|id_token|client_secret|code_verifier|authorization|token)=)[^&#\s]*/gi;
const ASSIGNMENT_SECRET_PATTERN =
  /((?:access_token|refresh_token|id_token|client_secret|code_verifier|authorization|password|secret)\s*[=:]\s*)[^,\s]*/gi;

function shouldRedactKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

function sanitizeString(value: string): string {
  const trimmed = value.trim();

  if (BEARER_OR_BASIC_PATTERN.test(trimmed) || JWT_PATTERN.test(trimmed)) {
    return REDACTED_VALUE;
  }

  return value
    .replace(QUERY_SECRET_PATTERN, `$1${REDACTED_VALUE}`)
    .replace(ASSIGNMENT_SECRET_PATTERN, `$1${REDACTED_VALUE}`);
}

function sanitizeLogValue(
  value: unknown,
  seen: WeakSet<object> = new WeakSet<object>(),
  depth = 0,
): unknown {
  if (depth > 6) {
    return "[Truncated]";
  }

  if (
    value === null ||
    value === undefined ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    return value;
  }

  if (typeof value === "string") {
    return sanitizeString(value);
  }

  if (typeof value === "function") {
    return `[Function ${value.name || "anonymous"}]`;
  }

  if (value instanceof URL) {
    return `${value.origin}${value.pathname}`;
  }

  if (typeof Headers !== "undefined" && value instanceof Headers) {
    const sanitizedHeaders: Record<string, string> = {};
    value.forEach((headerValue, headerKey) => {
      sanitizedHeaders[headerKey] = shouldRedactKey(headerKey)
        ? REDACTED_VALUE
        : sanitizeString(headerValue);
    });
    return sanitizedHeaders;
  }

  if (value instanceof Error) {
    const errorWithCause = value as Error & { cause?: unknown };
    return {
      name: errorWithCause.name,
      message: sanitizeString(errorWithCause.message),
      cause: sanitizeLogValue(errorWithCause.cause, seen, depth + 1),
    };
  }

  if (typeof value !== "object") {
    return value;
  }

  if (seen.has(value)) {
    return "[Circular]";
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeLogValue(entry, seen, depth + 1));
  }

  if (ArrayBuffer.isView(value)) {
    return `[${value.constructor.name}(${value.byteLength})]`;
  }

  const sanitizedObject: Record<string, unknown> = {};

  for (const [key, entryValue] of Object.entries(
    value as Record<string, unknown>,
  )) {
    if (shouldRedactKey(key)) {
      sanitizedObject[key] = REDACTED_VALUE;
      continue;
    }

    sanitizedObject[key] = sanitizeLogValue(entryValue, seen, depth + 1);
  }

  return sanitizedObject;
}

export function setGuardhouseDebug(enabled: boolean): void {
  globalDebugEnabled = Boolean(enabled);
}

export function isGuardhouseDebugEnabled(debugOverride?: boolean): boolean {
  if (typeof debugOverride === "boolean") {
    return debugOverride;
  }

  return globalDebugEnabled;
}

function emitLog(
  level: "debug" | "info" | "warn" | "error",
  namespace: string,
  args: unknown[],
  debugOverride?: boolean,
): void {
  if (!isGuardhouseDebugEnabled(debugOverride)) {
    return;
  }

  const prefix = `[Guardhouse ${namespace}]`;
  const logger = console[level] ?? console.log;
  const safeArgs = args.map((arg) => sanitizeLogValue(arg));
  logger(prefix, ...safeArgs);
}

export function createGuardhouseLogger(
  namespace: string,
  debugOverride?: boolean,
): GuardhouseLogger {
  return {
    debug: (...args: unknown[]) =>
      emitLog("debug", namespace, args, debugOverride),
    info: (...args: unknown[]) =>
      emitLog("info", namespace, args, debugOverride),
    warn: (...args: unknown[]) =>
      emitLog("warn", namespace, args, debugOverride),
    error: (...args: unknown[]) =>
      emitLog("error", namespace, args, debugOverride),
  };
}
