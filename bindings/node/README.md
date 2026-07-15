# `@basecrawl/sdk`

Node.js binding for [basecrawl](https://github.com/BaseIntelligence/basecrawl) (canonical ScrapeProof scraper).

## Install (linux-x64 only for this release)

```bash
npm install @basecrawl/sdk
# or: pnpm add @basecrawl/sdk
```

### Platform residual (M25 honesty)

The published package ships a **single native binary** built on the Linux x86_64 publish host:

| Constraint | Value |
|------------|--------|
| `package.json` `os` | `["linux"]` |
| `package.json` `cpu` | `["x64"]` |
| Native artifact | `basecrawl_sdk.node` (ELF linux-x64) |

- **linux-x64 only.** Multi-OS / multi-arch napi prebuilds (Darwin, Windows, arm64) are **not** part of this package line.
- Installing on other platforms is expected to fail package platform matching or fail loading the native `.node` artifact. That is intentional, not a hidden universal SDK claim.
- From source monorepo checkout on other hosts you can still rebuild the native addon locally via `pnpm run build` after installing a Rust toolchain; that path is development-only and is distinct from the npm registry tarball.

Also residual for hard/JS targets regardless of language: basecrawl may require a system Chromium/Chrome for render. Soft rustls scrapes do not.

## Usage

```js
const { scrape, version } = require("@basecrawl/sdk");

console.log(version()); // e.g. "0.1.0"

const proof = scrape("https://example.com", {
  formats: ["rawHtml"],
  renderEnabled: false,
});
console.log(proof.request.url, proof.result.formats_produced);
```

TypeScript types ship as `index.d.ts`.

## Publish / registry notes

- Package name: **`@basecrawl/sdk`** (npm org scope `@basecrawl`).
- Tag-driven release: repository tags matching `v*` run `.github/workflows/publish.yml` (crates.io ordered chain first, then this npm job on `ubuntu-latest`).
- Package scripts: `prepack` runs `build`, which produces `basecrawl_sdk.node` from the Rust `cdylib` on that Linux host; a smoke require/version runs in CI before `npm publish --access public`.
- Live publish secrets: GitHub Actions secret name **`NPM_TOKEN`** (mapped to `NODE_AUTH_TOKEN` only; never commit token values).
- If the npm org/scope `@basecrawl` is missing or the token is not authorized for that scope, publish records a **typed blocker** (`TYPED_BLOCKER=npm_org_or_scope`) **after** the crates.io job has already succeeded. Crates remain the primary public install path; npm is not silently claimed shipped when blocked by org setup. Token rotation is out of M25 scope.

## License

Apache-2.0
