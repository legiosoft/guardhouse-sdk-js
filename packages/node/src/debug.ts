type LoggerMethod = (...args: unknown[]) => void;

interface NodeLogger {
  debug: LoggerMethod;
  info: LoggerMethod;
  warn: LoggerMethod;
  error: LoggerMethod;
}

export function createNodeLogger(
  namespace: string,
  debug?: boolean,
): NodeLogger {
  const emit =
    (level: "debug" | "info" | "warn" | "error") =>
    (...args: unknown[]) => {
      if (!debug) {
        return;
      }

      const logger = console[level] ?? console.log;
      logger(`[Guardhouse Node:${namespace}]`, ...args);
    };

  return {
    debug: emit("debug"),
    info: emit("info"),
    warn: emit("warn"),
    error: emit("error"),
  };
}
