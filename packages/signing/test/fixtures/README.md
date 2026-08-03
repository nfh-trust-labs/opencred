# Test fixtures — throwaway keys only

The `.pfx` (PKCS#12) files in this directory are **synthetic test fixtures**:
keystores generated solely for exercising the PFX parser and multi-algorithm
signer tests. They were created with freshly generated throwaway keys, have
never been used to sign a real credential, anchor no trust, and protect
nothing. The import passphrase is the string `test123` (used openly in
`src/__tests__/pfx-parser.test.ts`).

| File | Contents |
|---|---|
| `test-ec256.pfx` | EC P-256 key + self-signed cert |
| `test-ec384.pfx` | EC P-384 key + self-signed cert |
| `test-rsa2048.pfx` | RSA-2048 key + self-signed cert |
| `test-rsa-chain.pfx` | RSA key + multi-cert chain (chain-parsing test) |

To regenerate an equivalent fixture:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/CN=OpenCred Test"
openssl pkcs12 -export -inkey key.pem -in cert.pem \
  -out test-ec256.pfx -passout pass:test123
```
