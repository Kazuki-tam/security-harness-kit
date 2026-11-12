#!/usr/bin/env node
"use strict";

// Launcher for the `shk` CLI installed from npm.
//
// The prebuilt binary ships in a per-platform package that the package manager
// selects through `optionalDependencies` and each package's `os` / `cpu` /
// `libc` fields. This file only locates that binary and runs it: it has no
// dependencies, downloads nothing, and the packages define no install scripts.

const { spawnSync } = require("child_process");
const path = require("path");

const manifest = require("../package.json");

const INSTALL_DOCS =
  "https://github.com/Kazuki-tam/security-harness-kit/blob/main/docs/installation.md";
// Exit code 2 is shk's "runtime or config error" code. Blocking AI pre-hooks
// treat it as a deny, so a broken install fails closed instead of open.
const EXIT_LAUNCH_ERROR = 2;

function fail(lines) {
  process.stderr.write(`shk: ${lines.join("\n     ")}\n`);
  process.exit(EXIT_LAUNCH_ERROR);
}

function supportedPlatforms() {
  const prefix = `${manifest.name}-`;
  return Object.keys(manifest.optionalDependencies || {})
    .map((name) => name.slice(prefix.length))
    .sort()
    .join(", ");
}

function resolveBinary() {
  const platformPackage = `${manifest.name}-${process.platform}-${process.arch}`;
  if (!Object.prototype.hasOwnProperty.call(manifest.optionalDependencies || {}, platformPackage)) {
    fail([
      `no prebuilt binary for ${process.platform}-${process.arch}.`,
      `Supported npm platforms: ${supportedPlatforms()}.`,
      `Other install methods: ${INSTALL_DOCS}`,
    ]);
  }

  let packageJson;
  try {
    packageJson = require.resolve(`${platformPackage}/package.json`);
  } catch (error) {
    const lines = [
      `the platform package ${platformPackage}@${manifest.version} is not installed.`,
      "It is an optional dependency, so it is skipped when optional dependencies are",
      "omitted (--omit=optional, --no-optional) or the install was copied from another platform.",
      `Reinstall with optional dependencies enabled: npm install -g ${manifest.name}`,
    ];
    if (process.platform === "linux") {
      lines.push("Linux binaries need glibc; musl-based systems such as Alpine are not supported.");
    }
    lines.push(`Other install methods: ${INSTALL_DOCS}`);
    fail(lines);
  }

  const binaryName = process.platform === "win32" ? "shk.exe" : "shk";
  return path.join(path.dirname(packageJson), "bin", binaryName);
}

const binary = resolveBinary();
const result = spawnSync(binary, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});

if (result.error) {
  const lines = [`failed to run ${binary}: ${result.error.message}`];
  if (process.platform === "linux" && result.error.code === "ENOENT") {
    lines.push("Linux binaries need glibc; musl-based systems such as Alpine are not supported.");
  }
  fail(lines);
}

if (result.signal) {
  // Re-raise the signal so the caller sees the same termination as the binary.
  process.kill(process.pid, result.signal);
} else {
  process.exit(result.status === null ? EXIT_LAUNCH_ERROR : result.status);
}
