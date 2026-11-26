#!/usr/bin/env node

const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@brokenapp/brokenapp-darwin-arm64",
  "darwin-x64": "@brokenapp/brokenapp-darwin-x64",
  "linux-x64": "@brokenapp/brokenapp-linux-x64",
  "linux-arm64": "@brokenapp/brokenapp-linux-arm64",
  "win32-x64": "@brokenapp/brokenapp-win32-x64",
};

function getBinaryPath() {
  const platform = os.platform();
  const arch = os.arch();

  // Normalize arch names
  let normalizedArch = arch;
  if (arch === "x64" || arch === "amd64") normalizedArch = "x64";
  if (arch === "arm64" || arch === "aarch64") normalizedArch = "arm64";

  const key = `${platform}-${normalizedArch}`;
  const pkg = PLATFORM_PACKAGES[key];

  if (!pkg) {
    console.error(
      `Unsupported platform: ${platform}-${arch}. ` +
        `Supported: ${Object.keys(PLATFORM_PACKAGES).join(", ")}`
    );
    process.exit(1);
  }

  try {
    const pkgDir = path.dirname(require.resolve(`${pkg}/package.json`));
    const ext = platform === "win32" ? ".exe" : "";
    return path.join(pkgDir, `brokenapp${ext}`);
  } catch {
    console.error(
      `Platform package ${pkg} is not installed.\n` +
        `Try reinstalling: npm install -g brokenapp\n` +
        `Or install from source: cargo install brokenapp`
    );
    process.exit(1);
  }
}

const binPath = getBinaryPath();

try {
  execFileSync(binPath, process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
  });
} catch (err) {
  if (err.status !== null) {
    process.exit(err.status);
  }
  throw err;
}
