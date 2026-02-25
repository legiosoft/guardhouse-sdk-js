type NodeRequireFunction = (moduleId: string) => any;

export function tryLoadNodeCrypto(): any | null {
  try {
    const dynamicRequire = Function(
      "return typeof require !== 'undefined' ? require : null;",
    )() as NodeRequireFunction | null;

    if (typeof dynamicRequire !== "function") {
      return null;
    }

    return dynamicRequire("crypto");
  } catch {
    return null;
  }
}
