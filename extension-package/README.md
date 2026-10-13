# Pines Verifier 1.17.0: the installed package as text

The site serves Pines Verifier 1.17.0 (extension id `lanmbpkmblcijblbllbikenpnceidmpj`) as a ZIP for a manual, unpacked
install; its SHA-256 is `d73ce18752e14d66906a42679bf94758f1849bdbf928f14eac12b1e552cad846`. The site's Install buttons lead to the Chrome Web Store listing under
the same id, which is uploaded separately, so the store's version can trail this package's.

For a reader who cannot open the ZIP, this directory holds three of its files verbatim and the SHA-256 of every file in it:

- `manifest.json`: the permissions, the content security policy (the one origin it may connect to) and the pages allowed to call it.
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
