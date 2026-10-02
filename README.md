# Pines Verifier

A Chrome extension that proves a paid ChatGPT, Claude or Grok subscription to [Pines](https://pines.family) with a
[TLSNotary](https://tlsnotary.org) (zkTLS) proof.

The extension replays one fixed provider request from your own signed-in browser through a TLSNotary verifier in Proxy
mode. You review exactly what will be shared before anything leaves the browser. Session cookies and authorization
headers are hidden with TLSNotary's native selective disclosure, and they are never shown to the Pines page or stored.

---

## Requirements

- **Node.js** version **22.18** or higher
- **npm**
- **Chrome 141** or later (or another Chromium browser with the side panel `close()` API)

---

## Install Dependencies

```
npm ci --ignore-scripts
```

---

## Development Build

```
npm run build
```

This creates a `dist/` folder containing the extension. By default it is a non-claimable pilot build that proves a
public fixture (`GET https://httpbingo.org/json`) and needs no account.

The build is configured with environment variables; nothing is read from a `.env` file and no secrets are required.

| Variable | Purpose |
|---|---|
| `PINES_TLSN_PROVIDER=chatgpt` | Prove a ChatGPT account instead of the public fixture |
| `PINES_TLSN_CHATGPT_IDENTITY=1` | Use the wallet identity schema (`pines.chatgpt.plan@3`) |
| `PINES_TLSN_CLAUDE=1`, `PINES_TLSN_GROK=1` | Also carry the Claude and Grok schemas (identity build only) |
| `PROVER_FUNNEL_ORIGINS` | Comma-separated exact page origins allowed to talk to the extension |
| `PROVER_FUNNEL_ORIGINS_EXCLUSIVE=1` | Use only those origins, without the loopback defaults |
| `PINES_TLSN_VERIFIER_ORIGIN`, `PINES_TLSN_VERIFIER_REVISION` | The pinned verifier and the release it must report |
| `PINES_TLSN_APPLICATION`, `PINES_TLSN_CHAIN_ID` | The audience the API's tickets must name |
| `PINES_TLSN_TEST_BUILD=1` | Allow loopback HTTP verifiers, for local development only |

To build against a local API and verifier:

```
PINES_TLSN_TEST_BUILD=1 \
PROVER_FUNNEL_ORIGINS=http://127.0.0.1:5391 \
PINES_TLSN_VERIFIER_ORIGIN=http://127.0.0.1:17447 \
PINES_TLSN_VERIFIER_REVISION=your-local-revision \
PINES_TLSN_APPLICATION=pines-local \
PINES_TLSN_CHAIN_ID=4664 \
npm run build
```

The extension checks the verifier's `/info` (protocol, mode, WASM version and revision) before it opens a proof session,
and refuses to prove when the API, verifier and extension disagree.

---

## Production Build

```
npm run release
```

This builds the production configuration in [`config/release.json`](config/release.json) and writes two reproducible
archives to `release/`, each with a SHA-256 checksum:

- `pines-tlsn-extension-<version>.zip`: for unpacked installs. It keeps the manifest `key`, so the extension ID is
  `lanmbpkmblcijblbllbikenpnceidmpj`, the Chrome Web Store item's own (from the public key in
  [`config/identity.json`](config/identity.json)). Unpacked and published builds answer on the same ID.
- `pines-tlsn-extension-<version>-store.zip`: for the Chrome Web Store, without `key`.

A release needs a clean checkout (`node release.mjs --allow-dirty` for a rehearsal). Two runs from the same commit
produce byte-identical archives. The script never uploads or publishes anything.

### Load into Browser

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **"Load unpacked"**
4. Select the generated `dist/` folder

---

## How it works

1. The Pines page calls the extension through `externally_connectable`, from an exact allowed origin. The page adapter
   is [`client.mjs`](client.mjs) (types in [`client.d.mts`](client.d.mts)); bundle it with the page.
2. The Pines API admits an attempt and returns a short-lived ticket naming the schema, the verifier and the recipient
   wallet. The extension validates the ticket against its packaged policy ([`src/policy.js`](src/policy.js)).
3. With your permission, the extension opens the provider in a new tab and captures the one request the schema allows,
   using Chrome's native `webRequest` events. Only the schema's allowlisted headers are kept, in memory, once.
4. The side panel shows what Pines will receive. Nothing is sent until you press **Share and verify**.
5. An offscreen document runs `tlsn-wasm` in a dedicated worker and proves the fixed request through the verifier.
   Credentials are hidden with native selective disclosure; the verifier sees the authenticated response.
6. The verifier delivers the result to the API, and the page polls the API for its receipt.

The schemas that define each request, what may be captured, what is disclosed and what counts as a paid plan are in
[`verification-schemas/`](verification-schemas/README.md). Their content is pinned by digest and must match the API's.

Permissions: `offscreen`, `storage`, `sidePanel`, `alarms` and, for provider builds, `webRequest`. Provider site access
(`https://chatgpt.com/*`, `https://claude.ai/*`, `https://grok.com/*`) is optional and requested from the side panel
when a verification needs it. There are no content scripts and no remotely loaded code.

---

## Tests

```
npm test                  # unit and controller tests, plus the schema package's tests
npm run registry:check    # verify the pinned schema digests
```

Browser tests need Playwright's Chromium (`npx playwright install chromium`):

```
npm run test:capture      # native request capture against a disposable synthetic HTTPS origin
npm run test:permissions  # the packaged panel's optional provider permissions (needs Google Chrome)
```

`capture/` also holds read-only diagnostics (`npm run probe:claude`, `npm run probe:grok`, `npm run measure:capture`)
that attach over CDP (`TLSN_BROWSER_CDP`, default `http://127.0.0.1:9222`) to a browser you have signed in yourself.
Their reports hold key names, sizes and salted equality tags only, never values.

---

## Project layout

| Path | What |
|---|---|
| `src/` | The extension: background worker, side panel, offscreen prover, capture and policy |
| `client.mjs` | The page adapter a website bundles to talk to the extension |
| `verification-schemas/` | Versioned provider schemas, request replay, disclosure planning and evaluation |
| `capture/` | The native capture session and read-only diagnostics |
| `config/` | The extension's public key and the production release configuration |
| `build.mjs`, `release.mjs` | The build and the reproducible release packaging |

---

## License

[MIT](LICENSE). The prover worker and offscreen design are adapted from
[BringID/tlsn-extension](https://github.com/BringID/tlsn-extension) (MIT or Apache-2.0); see
[PROVENANCE.md](PROVENANCE.md) and [UPSTREAM_LICENSE.md](UPSTREAM_LICENSE.md). The loading orb bundles
[thinking-orbs](https://www.npmjs.com/package/thinking-orbs) (MIT), and the panel uses the Geist font
(SIL Open Font License 1.1, [`src/fonts/OFL.txt`](src/fonts/OFL.txt)).
