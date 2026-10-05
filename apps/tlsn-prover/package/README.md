# Pines Verifier

A Chrome extension that checks a paid ChatGPT, Claude or Grok subscription for [Pines](https://pines.family). It proves
one fixed provider request with a native [TLSNotary](https://tlsnotary.org) Proxy-mode proof and discloses the result
only to an attested AWS Nitro enclave.

Source, build recipe and reproduction scripts: https://github.com/PinesFamily/pines-verifier

## Install

Chrome 141 or later. Open `chrome://extensions`, turn on Developer mode, choose **Load unpacked** and select this
folder (the one containing `manifest.json`). Chrome does not update an unpacked extension on its own: the files in this
folder are the code that runs.

## What it checks before it shares anything

Before any TLSNotary traffic, the extension asks the Pines API for an attempt and receives an AWS Nitro attestation
document from the enclave. It checks, in the browser:

- the COSE signature and certificate chain up to the AWS Nitro Enclaves root certificate;
- that the attestation is fresh and bound to this attempt;
- that the enclave is not running in debug mode;
- that PCR0, PCR1 and PCR2 equal the values in `build.json` (`tee.policySet.providers[].policy.pcrTuples`);
- that the attested keys are the ones the encrypted channel and the signed result use.

Only then does it open an encrypted (HPKE) channel to a key held by that enclave and run the proof through it. Login
tokens and cookies stay hidden from Pines and from the enclave through TLSNotary's selective disclosure. The page that
calls the extension cannot change these checks; the measurement is compiled into this package.

`build.json` also names the page origins allowed to call the extension, the API origin it connects to, the TLSNotary
version and the source commit this package was built from.

See [PROVENANCE.md](PROVENANCE.md) for third-party components and [UPSTREAM_LICENSE.md](UPSTREAM_LICENSE.md) for the
upstream license notice.
