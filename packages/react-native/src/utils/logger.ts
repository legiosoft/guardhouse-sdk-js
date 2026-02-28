type LoggerLevel = "debug" | "info" | "warn" | "error";

interface LoggerMetadata {
  [key: string]: unknown;
}

function emit(
  level: LoggerLevel,
  scope: string,
  message: string,
  metadata?: LoggerMetadata,
): void {
  const payload = metadata ? ` ${JSON.stringify(metadata)}` : "";
  const line = `[guardhouse:${scope}] ${message}${payload}`;

  switch (level) {
    case "debug":
      console.debug(line);
      return;
    case "info":
      console.info(line);
      return;
    case "warn":
      console.warn(line);
      return;
    case "error":
      console.error(line);
      return;
    default:
      return;
  }
}

/**
 * Internal SDK logger interface.
 */
export interface GuardhouseLogger {
  debug(message: string, metadata?: LoggerMetadata): void;
  info(message: string, metadata?: LoggerMetadata): void;
  warn(message: string, metadata?: LoggerMetadata): void;
  error(message: string, metadata?: LoggerMetadata): void;
}

/**
 * Creates a scoped logger. Debug/info are no-op when disabled.
 */
export function createLogger(
  scope: string,
  enabled: boolean,
): GuardhouseLogger {
  return {
    debug(message: string, metadata?: LoggerMetadata) {
      if (!enabled) {
        return;
      }

      emit("debug", scope, message, metadata);
    },
    info(message: string, metadata?: LoggerMetadata) {
      if (!enabled) {
        return;
      }

      emit("info", scope, message, metadata);
    },
    warn(message: string, metadata?: LoggerMetadata) {
      emit("warn", scope, message, metadata);
    },
    error(message: string, metadata?: LoggerMetadata) {
      emit("error", scope, message, metadata);
    },
  };
}
