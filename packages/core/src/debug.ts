export interface GuardhouseLogger {
  debug: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
}

let globalDebugEnabled = false;

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
  logger(prefix, ...args);
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
