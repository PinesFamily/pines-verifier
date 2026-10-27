# Pines Verifier 1.20.3: the installed package as text

The site serves Pines Verifier 1.20.3 (extension id `lanmbpkmblcijblbllbikenpnceidmpj`) as a ZIP for a manual, unpacked
install; its SHA-256 is `8355b5fe8d3822e4d90908b80254f84324f92a98e503799de90f4a97ab6d36a8`. The site's Install buttons lead to its ZIP install page until the Chrome Web Store publishes this version under
the same id, which is uploaded separately, so the store's version can trail this package's.

For a reader who cannot open the ZIP, this directory holds three of its files verbatim and the SHA-256 of every file in it:

- `manifest.json`: the permissions, the content security policy (its allowed connection origins) and the pages allowed to call it.
- `config.js`: the enclave policy the extension pins, with its PCR0/PCR1/PCR2, and the provider schemas.
- `build.json`: the build record, naming the commits of the private development repository it was built and packaged from; this repository is a path-for-path export of that repository.
- `SHA256SUMS`: every file in the package.

To check a downloaded copy:

```sh
sha256sum tee-package.zip   # must print the SHA-256 above
unzip -q tee-package.zip -d pines-verifier && (cd pines-verifier && sha256sum -c ../extension-package/SHA256SUMS)
```

The package cannot yet be rebuilt byte for byte from this repository. Its two binaries can:
`nitro-validation.wasm` (`tools/tee-native/reproduce/attestation-wasm.sh`) and `wasm/tlsn_wasm_bg.wasm`
(`tools/tee-native/reproduce/prover-wasm.py`).
