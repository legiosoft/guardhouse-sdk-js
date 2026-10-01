import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npmCli = process.env.npm_execpath;

if (!npmCli) {
  throw new Error("Run this check with npm run test:package");
}

const temporaryRoot = mkdtempSync(join(tmpdir(), "guardhouse-sdk-package-"));
const packages = [
  ["@guardhouse/core", "core", "GuardhouseClient"],
  ["@guardhouse/react", "react", "GuardhouseProvider"],
  ["@guardhouse/node", "node", "GuardhouseNodeClient"],
  ["@guardhouse/react-native", "react-native", "GuardhouseClient"],
];
const expectedFiles = [
  "LICENSE",
  "README.md",
  "dist/index.d.mts",
  "dist/index.d.ts",
  "dist/index.js",
  "dist/index.mjs",
  "package.json",
].sort();

function runNode(file, args, cwd = root) {
  const result = spawnSync(process.execPath, [file, ...args], {
    cwd,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.error || result.status !== 0) {
    throw new Error(
      `${file} ${args.join(" ")} failed:\n${result.stderr || result.error || result.stdout}`,
    );
  }

  return result.stdout;
}

try {
  const archives = [];

  for (const [name, directory] of packages) {
    const output = runNode(npmCli, [
      "pack",
      "--json",
      "--workspace",
      name,
      "--pack-destination",
      temporaryRoot,
    ]);
    const [report] = JSON.parse(output);
    const manifest = JSON.parse(
      readFileSync(join(root, "packages", directory, "package.json"), "utf8"),
    );
    const files = report.files.map((file) => file.path).sort();

    if (report.name !== name || report.version !== manifest.version) {
      throw new Error(
        `${name}: packed name or version does not match its manifest`,
      );
    }
    if (JSON.stringify(files) !== JSON.stringify(expectedFiles)) {
      throw new Error(`${name}: unexpected package files: ${files.join(", ")}`);
    }
    if (name !== "@guardhouse/core") {
      const coreVersion = JSON.parse(
        readFileSync(join(root, "packages", "core", "package.json"), "utf8"),
      ).version;
      if (manifest.dependencies?.["@guardhouse/core"] !== coreVersion) {
        throw new Error(
          `${name}: Core dependency must match the packed version`,
        );
      }
    }

    archives.push(join(temporaryRoot, report.filename));
  }

  writeFileSync(
    join(temporaryRoot, "package.json"),
    JSON.stringify({
      name: "guardhouse-package-smoke",
      private: true,
      type: "module",
    }),
  );
  runNode(npmCli, [
    "install",
    "--prefix",
    temporaryRoot,
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--legacy-peer-deps",
    "--package-lock=false",
    ...archives,
    "react@18.3.1",
    "@types/react@18.3.28",
    "typescript@5.9.3",
  ]);

  const requireConsumer = createRequire(join(temporaryRoot, "smoke.cjs"));
  const esmChecks = [];
  for (const [name, , exportName] of packages) {
    const cjsPath = requireConsumer.resolve(name);
    if (
      !existsSync(cjsPath) ||
      !existsSync(join(dirname(cjsPath), "index.mjs"))
    ) {
      throw new Error(`${name}: a published JavaScript entry is missing`);
    }

    // Native modules cannot execute in plain Node, but their declarations and
    // both published entry files still have to resolve in a clean install.
    if (name === "@guardhouse/react-native") {
      continue;
    }

    if (typeof requireConsumer(name)[exportName] !== "function") {
      throw new Error(`${name}: CommonJS ${exportName} export is missing`);
    }
    const index = esmChecks.length / 2;
    esmChecks.push(
      `import { ${exportName} as export${index} } from ${JSON.stringify(name)};`,
      `if (typeof export${index} !== "function") throw new Error(${JSON.stringify(`${name}: ESM export is missing`)});`,
    );
  }

  writeFileSync(join(temporaryRoot, "smoke.mjs"), esmChecks.join("\n"));
  runNode(join(temporaryRoot, "smoke.mjs"), [], temporaryRoot);

  writeFileSync(
    join(temporaryRoot, "smoke.ts"),
    [
      'import { GuardhouseClient as CoreClient } from "@guardhouse/core";',
      'import { GuardhouseProvider } from "@guardhouse/react";',
      'import { GuardhouseNodeClient } from "@guardhouse/node";',
      'import { GuardhouseClient as NativeClient } from "@guardhouse/react-native";',
      "void [CoreClient, GuardhouseProvider, GuardhouseNodeClient, NativeClient];",
    ].join("\n"),
  );
  writeFileSync(
    join(temporaryRoot, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        module: "NodeNext",
        moduleResolution: "NodeNext",
        target: "ES2022",
        strict: true,
        skipLibCheck: true,
        noEmit: true,
      },
      files: ["smoke.ts"],
    }),
  );
  runNode(
    join(temporaryRoot, "node_modules", "typescript", "bin", "tsc"),
    ["--project", join(temporaryRoot, "tsconfig.json")],
    temporaryRoot,
  );

  console.log(
    "All four packed SDKs install and expose their public entry points.",
  );
} finally {
  if (
    dirname(temporaryRoot) === tmpdir() &&
    basename(temporaryRoot).startsWith("guardhouse-sdk-package-")
  ) {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
