# Provenance

The worker/offscreen design adapts the maintained `BringID/tlsn-extension` fork at
`604694d8da50aab76a4d5d477ad8142cd8de6127`:

- [ProveManager worker](https://github.com/BringID/tlsn-extension/blob/604694d8da50aab76a4d5d477ad8142cd8de6127/packages/extension/src/offscreen/ProveManager/worker.ts):
  WASM initialization, a worker-owned `Prover`, WebSocket `IoChannel`, explicit Proxy
  `send_request(undefined, …)`, transcript/disclosure and prover cleanup.
- [ProveManager](https://github.com/BringID/tlsn-extension/blob/604694d8da50aab76a4d5d477ad8142cd8de6127/packages/extension/src/offscreen/ProveManager/index.ts):
  offscreen ownership, separate control/proof channels, per-run progress and cleanup.
- [Background entry](https://github.com/BringID/tlsn-extension/blob/604694d8da50aab76a4d5d477ad8142cd8de6127/packages/extension/src/entries/Background/index.ts):
  a creation mutex around `runtime.getContexts()` and the offscreen `WORKERS` lifecycle.

The fork's MIT OR Apache-2.0 declaration is retained in
[UPSTREAM_LICENSE.md](UPSTREAM_LICENSE.md). The older BringID AGPL browser extension,
plugin interpreter, demo/mobile app, all-site interception, console progress parser,
relay transports and Semaphore dependencies are not imported. This adaptation uses
a fresh dedicated worker per attempt and terminates it on cancellation instead of
reusing a WASM instance with an unfinished asynchronous borrow.

The registry and disclosure helpers are compiled from
[verification-schemas](verification-schemas/README.md). Build-time exact-origin
configuration and Chrome match-pattern conversion live in `src/funnel-origins.mjs`.
The runtime keeps the origin/port guard and adds explicit tab/window/document/run
ownership.

Runtime `tlsn-wasm@0.1.0-alpha.15` is copied locally from the integrity-pinned npm
package. esbuild 0.28.2, Playwright 1.63.0 and TypeScript 6.0.3 are build/test
dependencies.

Every build uses the stock TLSNotary Proxy prover and its native disclosure ranges.
The private fixture captures a synthetic browser Bearer value; provider builds capture
the real schema-selected request. Both mask credentials in the review. There are no
custom circuits, proving keys or additional proof systems.

Chrome behavior was checked against the primary
[offscreen API](https://developer.chrome.com/docs/extensions/reference/api/offscreen),
[side panel API](https://developer.chrome.com/docs/extensions/reference/api/sidePanel),
[message sender](https://developer.chrome.com/docs/extensions/reference/api/runtime#type-MessageSender),
[service-worker module restrictions](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/basics),
[COEP](https://developer.chrome.com/docs/extensions/reference/manifest/cross-origin-embedder-policy)
and [COOP](https://developer.chrome.com/docs/extensions/reference/manifest/cross-origin-opener-policy)
documentation, plus real Chromium integration tests. Requalify these behaviors when
changing browser/WASM versions; a manifest minimum version is not a test matrix.
The build embeds the registry's JSON as parsed data in the compiled local module,
avoiding unsupported JSON imports in the service worker while retaining the original
schema validation and digest checks. Neither test instrumentation nor the debugger
permission is included in the extension artifact.

The native capture capability and its separate diagnostic reuse BringID's concept of
browser-owned request interception, implemented with Pines' immutable header
allowlists and shared `prepareReplay`. They do not copy BringID's all-site request
history or content-script bridge. Capture uses Chrome's
[webRequest](https://developer.chrome.com/docs/extensions/reference/api/webRequest)
API (the diagnostic also uses
[webNavigation](https://developer.chrome.com/docs/extensions/reference/api/webNavigation))
with exact URL/tab/document ownership, one private request and a bounded
lifetime. A disposable HTTPS fixture tests real Authorization/User-Agent events in
headed and headless Chromium. The diagnostic runners use
[CDP Extensions](https://chromedevtools.github.io/devtools-protocol/tot/Extensions/)
only to install and uninstall the diagnostic in a browser you control.

Third-party assets in the side panel:

- `src/orb.js`: the loading orb, bundled by `build.mjs` with the thinking-orbs 0.3.2
  engine (MIT); its notice is at the top of `dist/orb.js`.
- `src/fonts/geist-latin.woff2`: Geist (SIL Open Font License 1.1, The Geist Project
  Authors); license in `src/fonts/OFL.txt`.
