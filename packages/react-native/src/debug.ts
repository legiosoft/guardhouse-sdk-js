type LoggerMethod = (...args: unknown[]) => void;

interface ReactNativeLogger {
  debug: LoggerMethod;
  info: LoggerMethod;
  warn: LoggerMethod;
  error: LoggerMethod;
}

export function createReactNativeLogger(
  namespace: string,
  debug?: boolean,
): ReactNativeLogger {
  const emit =
    (level: "debug" | "info" | "warn" | "error") =>
    (...args: unknown[]) => {
      if (!debug) {
        return;
      }

      const logger = console[level] ?? console.log;
      logger(`[Guardhouse ReactNative:${namespace}]`, ...args);
    };

  return {
    debug: emit("debug"),
    info: emit("info"),
    warn: emit("warn"),
    error: emit("error"),
  };
}
