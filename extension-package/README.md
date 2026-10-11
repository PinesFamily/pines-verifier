# Pines Verifier 1.13.14: the installed package as text

The site installs Pines Verifier 1.13.14 (extension id `lanmbpkmblcijblbllbikenpnceidmpj`) as an unpacked ZIP whose SHA-256 is
`4a8f7a04c072c055783d074e97536978e04c8f8a50d5b12b3a32077d8d503512`. It is not yet published in the Chrome Web Store, whose listing under the same id carries an
earlier, pre-enclave version that the site turns away.

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
