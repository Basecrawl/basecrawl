const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

const { scrape } = require("..");

const root = path.resolve(__dirname, "../../..");
const exampleOptions = {
  formats: ["markdown", "links", "metadata"],
  renderEnabled: false,
};
const quoteOptions = {
  formats: ["markdown", "links"],
  renderEnabled: false,
};

function cliProof(url, formats) {
  return JSON.parse(
    execFileSync(
      "cargo",
      [
        "run",
        "--quiet",
        "--manifest-path",
        path.join(root, "Cargo.toml"),
        "--package",
        "basecrawl-core",
        "--bin",
        "basecrawl",
        "--",
        url,
        "--formats",
        formats.join(","),
        "--no-js",
        "--output",
        "json",
      ],
      { encoding: "utf8" },
    ),
  );
}

test("Node matches CLI content digests and outputs", () => {
  const nodeExample = scrape("https://example.com", exampleOptions);
  const cliExample = cliProof("https://example.com", exampleOptions.formats);

  assert.equal(nodeExample.result.result_hash, cliExample.result.result_hash);
  assert.equal(nodeExample.tls.cert_chain_hash, cliExample.tls.cert_chain_hash);

  const nodeQuotes = scrape("https://quotes.toscrape.com", quoteOptions);
  const cliQuotes = cliProof("https://quotes.toscrape.com", quoteOptions.formats);

  assert.equal(
    nodeQuotes.result.formats_produced.markdown,
    cliQuotes.result.formats_produced.markdown,
  );
  assert.deepEqual(nodeQuotes.result.formats_produced.links, cliQuotes.result.formats_produced.links);
});
