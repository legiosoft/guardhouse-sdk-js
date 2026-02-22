const path = require("path");
const { getDefaultConfig } = require("expo/metro-config");

const projectRoot = __dirname;
const workspaceRoot = path.resolve(projectRoot, "../..");

const config = getDefaultConfig(projectRoot);

function pathToRegex(pathname) {
  return pathname
    .split(path.sep)
    .map((segment) => segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("[/\\\\]");
}

config.watchFolders = [
  path.resolve(workspaceRoot, "packages/react-native"),
  path.resolve(workspaceRoot, "packages/core"),
];

config.resolver.nodeModulesPaths = [
  path.resolve(projectRoot, "node_modules"),
  path.resolve(workspaceRoot, "node_modules"),
];

config.resolver.extraNodeModules = {
  react: path.resolve(projectRoot, "node_modules/react"),
  "react-native": path.resolve(projectRoot, "node_modules/react-native"),
};

config.resolver.blockList = [
  new RegExp(
    `^${pathToRegex(path.resolve(workspaceRoot, "packages/react-native/node_modules"))}[/\\\\].*$`,
  ),
  new RegExp(
    `^${pathToRegex(path.resolve(workspaceRoot, "packages/core/node_modules"))}[/\\\\].*$`,
  ),
];

module.exports = config;
