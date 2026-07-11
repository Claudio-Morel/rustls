# kemtls-handshake-bench

Minimal TCP client/server pair used to exercise and instrument the KEMTLS
handshake implemented by the `rustls` crate in this repository. It replaces
an earlier, separately hosted project that targeted a QUIC transport before
settling on plain TCP for the key exchange; this crate keeps that TCP-only
scope and lives directly alongside `rustls`/`rustls-mio` instead of as a
standalone repository.

It is a standalone Cargo workspace (see the `[workspace]` table in
`Cargo.toml`) so it keeps its own `target/` output, independent of the
`rustls`/`rustls-mio` workspace above it.

## Binaries

- `server` (`src/bin/server.rs`): KEMTLS/mutual-auth or plain RSA test
  server, listening on `0.0.0.0:4433`.
- `client` (`src/bin/client.rs`): connects, runs the handshake, and (when
  `KEMTLS_METRICS_JSON` is set) writes handshake timing/byte-count metrics
  as JSON.

Environment variables: `USE_RSA` (switch to the RSA test certs, no mutual
auth), `SERVER_ADDR` (client-side connect target, default
`127.0.0.1:4433`), `KEMTLS_SERVER_CERT_PATH` (pre-load a server certificate
for PDK-style proactive encapsulation), `KEMTLS_METRICS_JSON` (client-side
metrics output path).

Certificates in this directory (`kem.chain.crt`, `kem.key`, `kem-ca.crt`,
`client.crt`, `client.key`, `client-ca.crt`, `test_rsa.*`, `test_server.*`)
are pre-generated PKI material consumed by both binaries at runtime.
