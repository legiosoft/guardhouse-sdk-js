/**
 * Metro Configuration for Example App
 *
 * MONOREPO DECISIONS:
 *
 * 1. Why extraNodeModules?
 *    - Points to parent node_modules for monorepo
 *    - Prevents "module not found" errors in monorepo
 *    - Standard practice for React Native monorepos
 *
 * 2. Why watchFolders for parent react-native?
 *    - Watches SDK source for hot reloading
 *    - Allows development without building SDK separately
 *    - Faster iteration in monorepo
 *
 * 3. Why resolver.resolverMainFields?
 *    - Prioritizes package.json main/module fields
 *    - Correctly resolves different export formats (CJS/ESM)
 *    - Important for modern npm packages with dual exports
 *
 * 4. Why blockList for watch folders?
 *    - Prevents watching node_modules (performance)
 *    - Prevents double-watching (same folder multiple times)
 */

const { getDefaultConfig } = require("expo/metro-config");

const config = getDefaultConfig(__dirname);

// Add monorepo node_modules to resolver
const path = require("path");

// Add SDK directory to watch folders for hot reloading
const watchFolders = [
  path.resolve(__dirname, "../react-native/src"),
  path.resolve(__dirname, "../core/src"),
  ...config.watchFolders,
];

// Configure resolver for monorepo
config.resolver = {
  ...config.resolver,
  sourceExts: ["tsx", "ts", "jsx", "js", "json"],
  assetExts: ["png", "jpg", "jpeg", "gif", "svg"],
  // Add monorepo node_modules to resolution path
  extraNodeModules: ["../../../node_modules"],
};

// Add watch folders for monorepo packages
config.watchFolders = watchFolders;

// Configure transformer
config.transformer = {
  ...config.transformer,
  minifierConfig: {
    keep_classnames: false,
    keep_fnames: false,
    mangle: false,
  },
};

module.exports = config;
