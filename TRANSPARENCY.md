# Pines — Transparency

> What Pines can see, what it keeps, what your wallet signs, who controls the contracts, and where to check each claim — written for reviewers, human or AI.

Read against the code on October 12, 2026. The page: https://app.pines.family/transparency (behind a password until launch). The same text, with no password: https://github.com/PinesFamily/pines-verifier/blob/main/TRANSPARENCY.md

The Base contracts below enforce creator-selected 1–7 day claim windows, subscription plans, 10–90% claim allocations, claim caps, and one successful claim per wallet every rolling 24 hours.

This page is for anyone deciding whether Pines is safe to use, and for the assistant they ask. It says what the software can see, what it keeps, what your wallet is asked to sign, which contracts are live and who controls them, and where each statement can be checked without taking our word for it.

The enclave’s image names the chain and the application, not a contract deployment. Which Pines contracts a verification counts toward is chosen by the identity service, the same service that holds the claim-signing key. The identity signs the deployment hash into every ticket; each enclave-signed receipt commits to that ticket, and /verification-config publishes the current deployment hash. The web checks that hash against its own contract artifact. Saved verifications carry over across contract redeployments by default and use the current deployment’s revocation policy; a fresh ledger namespace starts verification and wallet quotas afresh.

Every address, digest, figure and quoted string on this page is pinned to the code by a test: when the code moves and this page does not, the build fails. The date above is when it was last read against the code.

This release supports proving your subscription and saving and reloading its record; claim signing is disabled. Request credentials and response header values other than content and transfer framing stay hidden. The full authenticated JSON body is read inside the measured AWS Nitro enclave and can contain personal or billing details. The host, relay and API receive encrypted traffic and a minimal result containing the plan and a keyed pseudonym; the API salts that pseudonym. The enclave’s source is public with a reproducible build, so anyone can rebuild its image and compare the measurement with the one the extension pins; the extension’s source is public for review, though its package cannot yet be rebuilt byte for byte. Your wallet signs one message and ordinary transactions, never a blanket permission. The contracts run on Base mainnet with real assets, are owned by a single operator key, have their source verified on Basescan, and have not been audited by a third party.

## 1. Check it yourself

None of these needs the site password. While the site keeps it, this page is also published, word for word, beside the source.

**The live verification policy** — https://id.pines.family/verification-config: engine, mode, chain id, the enclave’s measured context, the identity’s current deployment hash and the three schema digests the API accepts; the digests on this page must match it. It is served with `Cache-Control: no-store`: a copy listing `pines.*.plan` schemas or `claimable: true` is a cached one from before the enclave. **The enclave’s state** — https://id.pines.family/tee/health: whether it is ready, the context it was measured for, how many verifications it can take now and how many are in use, and whether results are being delivered. It is the API’s own report, not signed evidence: the signed attestation reaches the extension with each verification (see “The enclave, and what it proves”). **The source** — https://github.com/PinesFamily/pines-verifier: every file the enclave image is built from, with `tools/tee-native/reproduce/enclave.sh`, which rebuilds it twice and compares PCR0, PCR1 and PCR2 with the values below; the reproducible builds of the attestation validator and the TLSNotary prover the extension loads; the sources of the extension the site installs; [the installed package’s manifest.json, config.js and build.json as text, with the SHA-256 of every file in it](https://github.com/PinesFamily/pines-verifier/tree/main/extension-package), for anyone who cannot open the ZIP; and [this page as TRANSPARENCY.md](https://github.com/PinesFamily/pines-verifier/blob/main/TRANSPARENCY.md) ([plain text](https://raw.githubusercontent.com/PinesFamily/pines-verifier/main/TRANSPARENCY.md)). **The store listing** — https://chromewebstore.google.com/detail/pines-verifier/lanmbpkmblcijblbllbikenpnceidmpj: the site talks to this extension id and no other. The listing still carries an earlier, pre-enclave version, which the site turns away: the current version is not yet published in the store. **The Launchpad on the explorer** — https://basescan.org/address/0xDdaAEdFa05F5Ea24942a69e3c18Be8e5427B0718, and [its verified source](https://basescan.org/address/0xDdaAEdFa05F5Ea24942a69e3c18Be8e5427B0718#code) on Basescan, where every contract below is verified the same way. **The protocols we use** — [TLSNotary’s Proxy mode](https://tlsnotary.org/docs/protocol/proxy-mode) and [AWS Nitro Enclaves’ attestation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html), which are not ours.

On this site, behind the preview password until launch: [the extension’s install page](https://app.pines.family/verification/tee-install), which serves the package; [its metadata](https://app.pines.family/verification/tee-package.json) — its version, id, SHA-256 and the commit it was built from; and this page as text, https://app.pines.family/llms.txt and https://app.pines.family/llms-full.txt.

## 2. Which network, which assets

Everything runs on Base mainnet, chain id 8453. It is not a testnet: every coin, every stock token and every fee is real value, and your wallet should show chain 8453 on every request.

A coin is quoted in a tokenized stock: one of Coinbase’s stock tokens on Base, a permissioned asset issued by Coinbase, not a share in the company. Coinbase can pause a stock token’s transfers, stop an address from sending or receiving it through its transfer policies (held in Base’s policy registry, [`0x8453000000000000000000000000000000000002`](https://basescan.org/address/0x8453000000000000000000000000000000000002)), and take the balance of an address it has blocked. A paused stock freezes every pool quoted in it and the dividends paid in it; a blocked dividend contract cannot pay out until the block lifts. Pines has no control over any of this and no relationship with Coinbase beyond building on Base.

One stock token is not always one share: after a split or a similar corporate action Coinbase applies a multiplier to the token, so the number of tokens and the shares they stand for can differ. The prices on this site are per token, as the token’s price feed reports them.

The people who operate Pines, and people connected to them, may hold, launch, buy, sell or stake coins that appear here, at the same time as you and on the other side of your trade, and may earn a share of the protocol fee on what you do; the Terms of Use say so.

A pairing is a market, not backing. The coin’s price in the stock is whatever the pool’s liquidity says at the moment you trade, and nothing entitles a coin to any amount of the stock. A coin can go to zero.

## 3. The browser extension

Pines Verifier 1.16.0 is a Chrome extension, id `lanmbpkmblcijblbllbikenpnceidmpj`, for Chrome 141 or later. The site installs it from [its own install page](https://app.pines.family/verification/tee-install), not from the Chrome Web Store, whose listing under the same id still carries an earlier version that the site now turns away. The package’s SHA-256 is `6e7db007959197d6fb3d51bbff0f42671fcee5818734573b11310960843e49eb`. Its `build.json` names the two commits of Pines’ private development repository it was built and packaged from; the public repository is a path-for-path export of that repository, and its extension sources are those commits’ files. The version number is set by the release packaging, not by `build.mjs`, and the package cannot yet be rebuilt byte for byte from the published source. Chrome loads it unpacked from the folder you extract, so it never updates on its own: what is in that folder is what runs. The site detects it by its id and talks to no other extension.

Its permissions are `offscreen`, `storage`, `sidePanel`, `alarms`, `webRequest`. It asks for access to a provider’s site (`https://chatgpt.com/*`, `https://claude.ai/*`, `https://grok.com/*`) only when a verification needs it, from the side panel, and you can withdraw that access in Chrome at any time. It has no content scripts and loads no remote code, and its content security policy lets it open connections to `https://id.pines.family` and nowhere else.

Only pages on these origins can talk to it: `https://app.pines.family`, `https://front.pines.family`, `https://pines.family`, `http://localhost:5270`, `http://localhost:5180`, `http://127.0.0.1:5180`. Chrome’s manifest patterns cannot name a port, so its `externally_connectable` admits `https://app.pines.family/*`, `https://front.pines.family/*`, `https://pines.family/*`, `http://localhost/*`, `http://127.0.0.1/*`; the extension itself then answers only a top-level, non-incognito page whose exact origin is in that list. A page anywhere else cannot call it.

With your permission it opens the provider in a tab and, with Chrome’s native request events, captures the one request the schema names — nothing else you do on that site is read. It keeps only the headers the schema allows, in memory, once. Those headers are your session credentials: whoever holds them can act as you on that provider until the session ends. The content security policy keeps them from any third party, but the one origin it allows, `https://id.pines.family`, is Pines’ own, so what keeps them from Pines is the extension’s code, published for review as described above. While the site permission is granted, Chrome lets the extension observe request metadata on that site; the code acts on the one schema path and discards the rest, and the permission can be removed afterwards.

After you consent, the extension checks the enclave and opens an encrypted HPKE channel to it. TLSNotary’s WebAssembly prover (0.1.0-alpha.15) replays the permitted provider request in Proxy mode. Outgoing Authorization, complete Cookie and other secret request header values stay hidden in the proof. Response header values also stay hidden, except Content-Type, Content-Length, Transfer-Encoding and Content-Encoding. Header names and lengths remain visible. The enclave authenticates and decodes the response body, checks the plan and returns a signed result. The extension checks that result and its account-confirmation MAC. A failed attestation or identity check stops disclosure.

It requests only the listed account or subscription endpoint, not conversation or file endpoints. The response can still include personal or billing details beyond the plan fields.

## 4. The enclave, and what it proves

The response is read in one place: an AWS Nitro Enclave, an isolated virtual machine with no disk, no interactive access and no network of its own, on an AWS EC2 host in the Sydney region (ap-southeast-2). Its only connections run through that host: the encrypted channel to your browser, and fixed routes to the three providers. Pines runs the host, which relays encrypted bytes and cannot read the enclave’s memory; Railway, which runs Pines’ API, relays the same encrypted bytes.

AWS’s hardware signs a measurement of the code the enclave booted: PCR0 (the image), PCR1 (its kernel and boot) and PCR2 (its application). The extension discloses only to this measurement, which is compiled into it: PCR0 `1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4`, PCR1 `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`, PCR2 `1b38ddf5ed6fed44572e5187608a5c32bdb59c536c61adbb2e13450a149fa4a0b0c0af63425621845c98e96fee05f427`.

Before each verification the extension checks, in your browser, that the attestation chains to AWS’s Nitro root certificate, was made within the last 60 seconds for this attempt, comes from an enclave not running in debug mode, carries exactly those three values, and vouches for the channel key and for the key that will sign the result. Pines’ API checks the same attestation independently. Neither the page nor the API can change what the extension expects.

What that proves, if you trust the extension you installed and AWS: your account response becomes readable only inside an enclave running exactly that image, under a key made for your attempt. Pines’ web page, its API and the host relaying the traffic cannot read it, cannot swap the image for another, and cannot turn the check off.

What the image does is public. A measurement identifies code without describing it, so the source every file of the image is built from is published at https://github.com/PinesFamily/pines-verifier, and `tools/tee-native/reproduce/enclave.sh` rebuilds the image from it, twice and from clean, and compares the result with the three values above. Rebuilt that way, it matches them. Reading that source is how you check that the enclave reads the response, signs the short result the next section lists and keeps nothing else; the extension’s own check is what ties the image you read to the one your browser talks to.

The extension is published differently. The sources of 1.16.0 are in the same repository for review, and the two binaries it loads — the attestation validator and TLSNotary’s prover — rebuild there byte for byte, but its package does not yet: what runs is the folder you installed, and the package’s SHA-256 above is what identifies it. Its `config.js` carries the PCR values above in plain text, so you can read what your copy pins.

Also outside the guarantee: AWS itself — its hardware, its hypervisor and the keys that sign attestations; the traffic metadata Pines’ servers see — when you verify, how much is sent and from which address; availability, since Pines can stop the host; and anyone other than you, because the attestation is checked off-chain (see “What a claim puts on chain”). To check a session yourself, open the developer tools of the extension’s offscreen page from `chrome://extensions` during a verification: the attestation arrives in the response to `/tee/admission` as the hex string `offer.evidence.cose`, and any Nitro attestation verifier can check it against [AWS’s published root certificate](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

## 5. What a proof reveals, per provider

The proof authenticates one HTTPS exchange with the provider. Native selective disclosure hides request credentials and response header values other than content and transfer framing, including Set-Cookie and opaque provider headers. The full response body is revealed inside the enclave, where it is decoded and checked. Body fields can still contain personal or billing information. These are the three release schemas, each identified by a digest you can compare with the live policy.

- ChatGPT — pines.chatgpt.tee.native v6 (sha256:cd5e6039d98ecc181ca5f965515cf6eaa5a8dbc621ecd7673c492143f5fe223d): GET https://chatgpt.com/backend-api/wham/usage. Judged: plan_type (Plus, Pro, Pro Lite or Pro Max) and user_id (the account). Hidden from the enclave and from Pines: outgoing authorization, the complete outgoing cookie value, other secret request header values and all response header values except content and transfer framing. Also revealed to the enclave: the full authenticated JSON body, including any personal fields, the request user-agent and response framing. Decoded JSON body limit: 16 KiB.
- Claude — pines.claude.tee.native v3 (sha256:b8209443cbf6aa759e9bef8b808de111e0de7837773612facb7387f4726738e2): GET https://claude.ai/api/organizations/{org_uuid}. Judged: the personal organisation’s uuid (the account), its rate_limit_tier and capabilities (Pro or Max). Hidden from the enclave and from Pines: outgoing session cookie values, other secret request header values and all response header values except content and transfer framing. Also revealed to the enclave: the selected organisation’s full JSON body, including its name, the request user-agent and response framing. Decoded JSON body limit: 12 KiB.
- Grok — pines.grok.tee.native v3 (sha256:72127c492d778072c103b374177cc6d71f60e0a49ccac7aa1b23fb6da80aff75): GET https://grok.com/rest/subscriptions?status=SUBSCRIPTION_STATUS_ACTIVE. Judged: xaiUserId (the account), tier (a paid plan) and status, which must be SUBSCRIPTION_STATUS_ACTIVE. Hidden from the enclave and from Pines: outgoing session cookie values, other secret request header values and all response header values except content and transfer framing. Also revealed to the enclave: the active subscription response’s full JSON body, including billing fields, the request user-agent and response framing. Decoded JSON body limit: 8 KiB.

The enclave reads the whole JSON body in memory to decide the plan, then signs a short result: the plan, a domain-separated keyed pseudonym of the account id, your wallet, the provider, the attempt, the enclave’s measurement and the byte counts of the exchange. Pines’ API receives that result — never the response, the raw account id or the email. The provider sees your own request from your browser, then one replay of it from Pines’ AWS host. The encoded body is capped at 3.5 KiB; gzip and identity encoding are accepted within the decoded limits above. The response must be a 200 with JSON.

The enclave reads the whole JSON body because the plan check also needs the account identity and the provider’s surrounding data structure. Only the short signed result leaves it. Hiding response headers does not hide fields inside that body.

The site calls this zkTLS. The zero-knowledge part of the proof is what lets the enclave check the exchange without learning your credentials or the hidden header values. The response body is revealed to the enclave in full, so what keeps it from Pines is the enclave, not a zero-knowledge proof.

## 6. What Pines keeps

From a successful verification, the durable record holds: the provider and the schema id and version, your wallet address, when it was verified and when it expires, the one plan value, and a salted one-way identifier of the account. The enclave computes an HMAC over the canonical provider and account identity using one stable Sydney KMS-backed key held by a native helper. The API derives its identifier from that pseudonym with a secret salt. The raw account id, the email, the response body, the headers and the cookies never reach Pines’ servers.

Per attempt, for rate limiting and support: your wallet, the admission ticket, the enclave’s attestation and the signed grant, a status and error code, a hash of the enclave’s signed result, a keyed one-way hash of your IP address (HMAC-SHA256 under a server secret, so it cannot be reversed by trying every address without that secret), and timestamps. Attempt rows are retained for about 7 days.

The identifier binds the account to your wallet for 30 days, so a subscription cannot feed an unlimited number of wallets, and counts toward a budget of 3 successful verifications per wallet per rolling 30 days.

Separately, as with any web service, the servers’ request logs record the IP address and user agent of each request. The Privacy Policy says they are kept for a short period for security and debugging; no fixed number of days is promised.

Operations see a verification trace with a closed set of fields — identifiers, the schema, the assigned verifier, states, fixed error codes and timings — and never provider facts, receipt records, tickets, disclosed bytes or addresses. Transcripts are not stored anywhere.

The records live in a managed PostgreSQL database in the United States, readable by the operators who run the service. The salt and the attestor key below live in that service’s configuration, not on the machines that serve this site.

In your browser, the site uses local storage for the wallet you last connected, the filters you chose and a claim in progress. Analytics, where enabled, are cookieless page counts proxied through this domain; browser error reports carry no wallet address and no identifier that follows you.

## 7. What a claim puts on chain

Claim signing is disabled in this release. Saving a verification does not submit a claim or authorize a transaction. The following describes the deployed contracts when claim signing is enabled.

When you claim, the API signs an attestation with the attestor key (`0x6CCe04827d6b689FC512b5A5f3912862CAf54925`); the launch’s claim contract checks that signature through the verifier contract [`0xD4B59A7C2CD93Ec31dC6101b6275528A3030330b`](https://basescan.org/address/0xD4B59A7C2CD93Ec31dC6101b6275528A3030330b).

The attestation names your wallet, the launch’s claim contract and a nullifier: keccak256(domain ‖ account id ‖ secret salt ‖ claim contract). It is a per-launch, salted hash of the account: without the salt it cannot be reversed or linked across launches, and the chain records it as consumed so that one account claims once per launch. As with any wallet, anyone who knows which address is yours can see which launches it claimed from.

Claimed coins arrive staked in the launch’s dividend distributor and earn from the first trade; leaving a staked claim has a 72-hour cooldown. You pay the claim’s gas in ETH on chain 8453.

The verifier contract says so about itself: it is named `DevAttestationVerifier`, and `IS_PRODUCTION_VERIFIER()` returns `false`. It checks one ECDSA signature by the attestor key and no proof of any kind; the name and the flag mark it as the single-key verifier, not a trust-minimised one.

The trust assumption, stated plainly: the claim path trusts Pines’ attestor. The enclave’s attestation is checked off-chain, by the extension and the API; the chain sees only the attestor’s signature, so the enclave protects what you disclose but does not prove to anyone else that a given claim followed a verification. If the attestor key were misused or stolen, claims could be minted without a real proof, bounded per launch by the drop’s cap and its nullifiers. It cannot move anything in your wallet, change a trade, or touch a stake.

## 8. What your wallet is asked to sign

One message, before a verification, signed as plain text (EIP-191). Its text is exactly this, with the bracketed values filled in:

- Pines verification wallet sign-in
- Application: pines
- Chain ID: 8453
- Wallet: [your address]
- Verifier: [the verifier release the policy names]
- Nonce: [a one-time challenge]
- Expires: [a few minutes from now]
- Authorize verification and receipt access for this wallet for 30 minutes. This does not authorize a transaction.

It proves you control the wallet for 30 minutes of verification and receipt access and authorises nothing on chain; a wallet shows it as a message, not a transaction.

Transactions, each shown by your wallet before it is sent: `approve` — an exact amount of the stock to the dev-buy router `0xD87167a7bdC1d72bd473990960BbC8f90ed7f8E6` when you launch, and — the one open-ended approval — the first time you stake a coin, an unlimited allowance of that coin to that launch’s own distributor, so later stakes need no second approval; revoke it with any allowance tool whenever you like. Then the ordinary calls: `launch`, `stake`, `beginUnstake`, `cancelUnstake`, `withdrawUnstaked`, `getReward`, `pull` to start a launch’s reward stream, and `claim` on the launch’s claim contract. Gas is your own ETH. Pines has no trading contract: Buy opens Uniswap’s own app, which asks for its own approvals and may ask for a Permit2 signature; that request is Uniswap’s, made after you leave Pines.

A typed-data signature exists in the contracts for claims relayed and paid by Pines: `ClaimIntent(bytes32 attestationHash,address ref,uint64 deadline)` under the EIP-712 domain `PinesAirdrop` version 4. This deployment does not relay claims, so you are not asked for it; were it signed, it could only ever pay its own recipient.

Never: a Permit or Permit2 signature, setApprovalForAll, a transfer “to activate”, a console command, your private key or your recovery phrase. Anyone asking for those is not Pines.

## 9. The contracts and who controls them

One world of contracts, deployed on 2026-10-12, with scan start block 52,487,321: Launchpad: [`0xDdaAEdFa05F5Ea24942a69e3c18Be8e5427B0718`](https://basescan.org/address/0xDdaAEdFa05F5Ea24942a69e3c18Be8e5427B0718); attestation verifier: [`0xD4B59A7C2CD93Ec31dC6101b6275528A3030330b`](https://basescan.org/address/0xD4B59A7C2CD93Ec31dC6101b6275528A3030330b); claim contract implementation, cloned per launch: [`0x38c6762529a712B206e1fDB46f60f43dBA6235fA`](https://basescan.org/address/0x38c6762529a712B206e1fDB46f60f43dBA6235fA); dividend distributor implementation, cloned per launch: [`0x43d715D92110FB87144BC59579231944f4D87911`](https://basescan.org/address/0x43d715D92110FB87144BC59579231944f4D87911); dev-buy router: [`0xD87167a7bdC1d72bd473990960BbC8f90ed7f8E6`](https://basescan.org/address/0xD87167a7bdC1d72bd473990960BbC8f90ed7f8E6); treasury Safe: [`0xEdF07E72Dd1d80e85A2320C44Ae88684aF18AfA2`](https://basescan.org/address/0xEdF07E72Dd1d80e85A2320C44Ae88684aF18AfA2); cohort registry: [`0x822B0b9cf49742d9a4AD9B89F234f205Aafb0a5A`](https://basescan.org/address/0x822B0b9cf49742d9a4AD9B89F234f205Aafb0a5A); nullifier registry: [`0x56F412704F57c178865AD832c6120Be74FD81A27`](https://basescan.org/address/0x56F412704F57c178865AD832c6120Be74FD81A27); provider control: [`0xEe2D01B6ADA41DA5bD0D39dA243ED917fCFE49cd`](https://basescan.org/address/0xEe2D01B6ADA41DA5bD0D39dA243ED917fCFE49cd).

Pines is a Doppler integrator: a launch calls Doppler’s Airlock ([`0x660eAaEdEBc968f8f3694354FA8EC0b4c5Ba8D12`](https://basescan.org/address/0x660eAaEdEBc968f8f3694354FA8EC0b4c5Ba8D12)) to mint the supply and open a Uniswap v4 pool quoted in the chosen stock. Doppler’s beneficiary table fixes the fee split at launch and no migration path exists, so the split can never change.

Fixed per launch, by code: a supply of 1,000,000,000, never minted again; 10–90% of it carved out to the claim contract when the launch has a drop, and whatever nobody claims burns; a 1% pool fee split 75% to stakers, 20% to the Pines treasury, a Safe smart account, and 5% to Whetstone, Doppler’s maker; a drop open for 1–7 whole days; one successful claim per wallet every 24 hours across all tokens; and a dividend stream that cannot be redirected by anyone, released over twelve hours from each crank.

Who controls what: the owner and guardian roles are one address, [`0x830f00c8346047e05BEB4Ec2645295F147B48228`](https://basescan.org/address/0x830f00c8346047e05BEB4Ec2645295F147B48228), an externally owned account held by the operator. At once, it can pause launches and claiming together, pause claims for one provider or all of them and revoke a provider’s earlier evidence, allow or disallow which stocks a launch may quote in, switch the dev-buy router off, and register, list and unlist cohorts. Only after a two-day delay that anyone can watch on chain can it rotate the attestor, replace the dev-buy router, or point the treasury share of launches made after that at another address. One exception, at setup only: the first dev-buy router could be set without the delay while none was set and nothing had launched, and the deployment used it. It can also hand the owner role to another address, which takes effect only when that address accepts it, or renounce the role; neither waits for the delay. The guardian address is fixed at deployment. It cannot move tokens from a wallet, change a launch’s fee split once it is made, redirect or stop dividends or change their twelve-hour stream, mint supply, take a staked position, pause one launch alone or stop trading — pools are permissionless, except that Coinbase can pause its stock tokens.

The source of every contract above is published and verified on Basescan ([the Launchpad’s, for one](https://basescan.org/address/0xDdaAEdFa05F5Ea24942a69e3c18Be8e5427B0718#code)), compiled with the same settings the deployment used. Not yet true, as of October 12, 2026: no third party has audited them, and the operator’s own line-by-line review of them is still to come. What does hold today is mechanical: every assumption about Doppler, Uniswap and the stock tokens is asserted against the live chain in continuous integration, and the figures and addresses on this page are checked against the deployed artifact. That review and an audit are open work, and this sentence changes when they land.

The world names no snipe-tax hook: no launch is taxed, and adding one later would be a new world of contracts.

## 10. Services involved

Netlify serves this site and holds its password. Railway runs the identity API (which also relays the enclave’s encrypted traffic), the read service, the media service and their PostgreSQL database. AWS runs the verification enclave, on an EC2 host in its Sydney region. DigitalOcean runs the monitoring server. Alchemy answers the chain reads the page makes, through a same-origin proxy on this site, so your browser never contacts Alchemy. Goldsky indexes the chain for the read service, server-side. Token art and metadata are pinned to content-addressed storage through the media service.

Plausible counts page views without cookies, through this domain, where a site enables it. Browser error reports go to our own monitoring server through this domain and carry no wallet address. A token page embeds a GeckoTerminal chart in a frame, so GeckoTerminal sees your address and browser when such a page loads. The buy dialog behind every Get button is KyberSwap’s swap widget: your browser asks KyberSwap’s aggregator API for quotes with the tokens and the amount, and sends it your wallet address when you press Swap, so it can build the route. Its chain reads go through this site’s same-origin proxy, and it loads its Ether icon from CoinMarketCap’s image host. Pairing a mobile wallet goes through the WalletConnect relay. And the provider you prove sees one request from your own browser, then one replay of it from Pines’ AWS host.

## 11. Limits

- 3 successful verifications per wallet per rolling 30 days.
- A verification is valid for 30 days, and binds the provider account to that wallet for the same 30 days.
- One claim per provider account per launch, enforced on chain by the nullifier.
- A drop is open for 1–7 whole days; a staked claim leaves after a 72-hour cooldown.
- A verification has 120 seconds from start to signed result, your review included.
- The enclave runs a limited number of verifications at once. When every place is taken, a new one is refused while its channel is set up, before anything is disclosed, and the extension says the verifier is busy; try again shortly.

## 12. What Pines does not do

- Take custody of anything, or hold a key that can move your assets.
- Ask for your private key, your recovery phrase, a password, a session cookie or an API key.
- Ask who you are: no name, no date of birth, no document.
- Read your conversations, files, prompts or payment details on any provider.
- Use the proven session to act as you — it never holds the credential.
- Sell personal information or build an advertising profile.
- Ask for an open-ended approval beyond the staking allowance named above, or any Permit signature.

## 13. If this page is wrong

The statements above are pinned by a test that reads the deployment artifact, the schema registry, the enclave’s pinned policy and measured context, the extension’s build configuration and package metadata, the contracts’ parameters and the API’s quotas, and fails when any of them disagrees with this page. A statement that is nonetheless wrong is a defect; tell us and we will record and fix it in the open.

Open work this page names: a byte-reproducible build of the extension’s package; the operator’s own review of the contracts; and an independent audit.

## 14. Contact

Write to [support@pines.family](mailto:support@pines.family). Security reports go to the same address; [security.txt](https://app.pines.family/.well-known/security.txt) says so in the standard form.
