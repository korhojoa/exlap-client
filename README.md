# exlap-client

A [WASM hook](https://github.com/aa-proxy/aa-proxy-rs) for [aa-proxy-rs](https://github.com/aa-proxy/aa-proxy-rs) that implements the ExLAP protocol client for VW Group MIB2 head units.

ExLAP is the proprietary in-car data bus protocol used by VW/Audi/Skoda/Seat MIB2 head units to expose vehicle telemetry (speed, RPM, temperatures, EV battery level, etc.) over the Android Auto vendor channel.

## What it does

- Authenticates with the head unit over the Android Auto vendor channel (`com.vwag.infotainment.gal.exlap`, channel `0x7E`)
- Fixes the auth bug present in earlier implementations: sends `useHash="sha256"` in the challenge request so the HU knows which digest algorithm to use
- Discovers available data URLs and subscribes to EV-relevant ones
- Pushes live data updates to the aa-proxy-rs web UI via WebSocket
- Persists the working credential index so subsequent connections skip failed attempts
- Injects EV battery/range data into aa-proxy-rs's `/battery` endpoint for Google Maps EV routing

## Building

Requires [`cargo-component`](https://github.com/bytecodealliance/cargo-component) and the `wasm32-wasip1` target:

```sh
rustup target add wasm32-wasip1
cargo install cargo-component
cargo component build --release
```

Output: `target/wasm32-wasip1/release/exlap_hook.wasm`

## Deployment

Copy the `.wasm` to the aa-proxy-rs device:

```sh
scp target/wasm32-wasip1/release/exlap_hook.wasm root@10.0.0.1:/data/wasm-hooks/exlap_hook/exlap_hook.wasm
```

Enable in aa-proxy-rs config (`/etc/aa-proxy-rs/config.toml`):
```toml
exlap = true
```

## WIT interface

The hook implements the `packet-hook` world from aa-proxy-rs's `wit/world.wit`. The copy in `wit/world.wit` must stay in sync with the host when the interface changes.
