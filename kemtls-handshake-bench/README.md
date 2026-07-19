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
  server, listening on `0.0.0.0:4433`; when `KEMTLS_SERVER_METRICS_JSON` is
  set it atomically writes the server-side `ClientFinished validated` mark.
- `client` (`src/bin/client.rs`): connects, runs the handshake, and (when
  `KEMTLS_METRICS_JSON` is set) atomically writes client timing/byte-count
  metrics as JSON.

Environment variables: `USE_RSA` (switch to the RSA test certs, no mutual
auth), `SERVER_ADDR` (client-side connect target, default
`127.0.0.1:4433`), `KEMTLS_SERVER_CERT_PATH` (pre-load a server certificate
for PDK-style proactive encapsulation), `KEMTLS_CRYPTO_VARIANT` (variant label
used in reports; canonical PDK labels are `kyber512-mutual-pdk[-lo]`, with
`kyber512-pdk[-lo]` retained as historical aliases), `KEMTLS_METRICS_JSON`
(client-side metrics output path), and
`KEMTLS_SERVER_METRICS_JSON` (server-side metrics output path). Both reports
use absolute host `CLOCK_MONOTONIC` nanoseconds; the client mark is
`ServerFinished validated` for mutual and `ClientFinished emitted` for PDK,
while the server mark is always `ClientFinished validated`.

For mutual KEMTLS, the client mark is the bilateral boundary consumed by the
testbed. For PDK, the client mark is diagnostic and the server's first
observation after validating `ClientFinished` is authoritative. The reports do
not treat `NewSessionTicket` or application data as part of the handshake.

## Build and validation

Run Cargo from this directory so `.cargo/config.toml` applies the compatibility
lint cap required by the historical `ring`, `webpki`, and `rustls` forks:

```console
cargo fmt -- --check
cargo test --locked
cargo build --locked --bin server --bin client
```

The binaries are intended for Linux because the cross-process marks use the
host's `CLOCK_MONOTONIC` domain.

Certificates in this directory (`kem.chain.crt`, `kem.key`, `kem-ca.crt`,
`client.crt`, `client.key`, `client-ca.crt`, `test_rsa.*`, `test_server.*`)
are pre-generated PKI material consumed by both binaries at runtime.
