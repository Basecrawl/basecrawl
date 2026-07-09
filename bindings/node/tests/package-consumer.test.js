const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "../../..");
const ignoredDirectories = new Set([
  ".git",
  ".pytest_cache",
  ".ruff_cache",
  ".venv",
  "__pycache__",
  "build",
  "node_modules",
  "target",
]);

function run(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  });
}

function cleanCheckoutFilter(source) {
  const relativePath = path.relative(root, source);
  if (!relativePath) {
    return true;
  }

  if (relativePath.split(path.sep).some((segment) => ignoredDirectories.has(segment))) {
    return false;
  }

  return !source.endsWith(".node") && !source.endsWith(".so");
}

test("packed SDK installs and scrapes in an empty consumer", () => {
  const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), "basecrawl-node-package-"));
  const checkout = path.join(temporaryRoot, "basecrawl");
  const packageDirectory = path.join(checkout, "bindings", "node");
  const packDirectory = path.join(temporaryRoot, "package");
  const consumerDirectory = path.join(temporaryRoot, "consumer");

  try {
    cpSync(root, checkout, { filter: cleanCheckoutFilter, recursive: true });
    assert.equal(existsSync(path.join(packageDirectory, "basecrawl_sdk.node")), false);

    run("pnpm", ["install", "--frozen-lockfile"], packageDirectory);
    run("pnpm", ["pack", "--pack-destination", packDirectory], packageDirectory);

    const tarballs = readdirSync(packDirectory).filter((entry) => entry.endsWith(".tgz"));
    assert.deepEqual(tarballs.length, 1);

    mkdirSync(consumerDirectory);
    writeFileSync(
      path.join(consumerDirectory, "package.json"),
      JSON.stringify({ name: "basecrawl-sdk-consumer", private: true, version: "0.0.0" }),
    );
    run(
      "pnpm",
      ["add", "--ignore-scripts", "--offline", path.join(packDirectory, tarballs[0])],
      consumerDirectory,
    );

    const proof = JSON.parse(
      run(
        process.execPath,
        [
          "-e",
          [
            'const sdk = require("@basecrawl/sdk");',
            'console.log(JSON.stringify(sdk.scrape("https://example.com", {',
            '  formats: ["rawHtml"],',
            "  renderEnabled: false,",
            "})));",
          ].join("\n"),
        ],
        consumerDirectory,
      ),
    );
    assert.equal(proof.request.url, "https://example.com/");
    assert.equal(typeof proof.result.formats_produced.rawHtml, "string");
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
});
