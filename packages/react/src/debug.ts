type LoggerMethod = (...args: unknown[]) => void;

interface ReactLogger {
  debug: LoggerMethod;
  info: LoggerMethod;
  warn: LoggerMethod;
  error: LoggerMethod;
}

export function createReactLogger(
  namespace: string,
  debug?: boolean,
): ReactLogger {
  const emit =
    (level: "debug" | "info" | "warn" | "error") =>
    (...args: unknown[]) => {
      if (!debug) {
        return;
      }

      const logger = console[level] ?? console.log;
      logger(`[Guardhouse React:${namespace}]`, ...args);
    };

  return {
    debug: emit("debug"),
    info: emit("info"),
    warn: emit("warn"),
    error: emit("error"),
  };
}
