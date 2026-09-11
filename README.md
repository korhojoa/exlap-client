# exlap-client

A [WebAssembly hook](https://github.com/aa-proxy/aa-proxy-rs) for
[aa-proxy-rs](https://github.com/aa-proxy/aa-proxy-rs). It runs an ExLAP client
for VW Group MIB2 head units.

ExLAP is the in-car data protocol of VW, Audi, Skoda and Seat MIB2 head units.
The head unit gives vehicle data through it. Examples are the speed, the RPM,
the temperatures, and the electric battery level. The data comes over the
Android Auto vendor channel.

## What it does

- It authenticates with the head unit on the Android Auto vendor channel (`com.vwag.infotainment.gal.exlap`, channel `0x7E`).
- It brings up each credential as a separate ExLAP session on the one channel. Each credential gives a different set of URLs. The first credential that offers a URL subscribes to it. No URL is subscribed more than once.
- It reads each credential's URL directory. It subscribes at an interval you set. The protocol default is "on every change", which floods the channel, so the hook does not use it.
- It parses each `<Dat>` into typed values. It lifts out the `unit` and `state` fields. It removes the fields that the head unit reports as absent.
- It can call functions and query interfaces at run time from the web UI (`call`, `interface`, `subscribe`, `unsubscribe`, `get`).
- It sends the live data and the connection state to the aa-proxy-rs web UI through WebSocket.
- It sends the electric battery and range data to the aa-proxy-rs `/battery` endpoint for Google Maps route planning.

## Shared protocol core

This hook does not hold the ExLAP protocol itself. The protocol is the
[`exlap`](https://crates.io/crates/exlap) crate. Its `Machine` holds the
handshake, the authentication, the request numbers, the `<Dir>` directory, the
subscriptions, `<Call>` and `<Interface>`, the `<Dat>` parser, and the
keepalive answers.

This hook drives that `Machine` over the Android Auto vendor channel. The same
`Machine` also runs over a TCP socket. A protocol change is made once, for both
transports.

## Configuration (aa-proxy-rs web UI, ExLAP section)

- `exlap_channel`: the fallback channel id if the SDR does not give one (default 126 = `0x7E`)
- `exlap_creds`: the credential indices to bring up, in preference order (default `2,1,3,0`)
- `exlap_subscribe_urls`: the URLs to subscribe to, or `*` for all that the credentials give (default `tankLevelPrimary,outsideTemperature`)
- `exlap_subscribe_ival_ms`: the minimum interval between pushes for each subscription (default `2000`)
- `exlap_battery_capacity_wh`: the total capacity in Wh, sent with each `POST /battery` (default `0` = model default)
- `exlap_debug`: the verbose log (default `false`)

## Building

This hook needs [`cargo-component`](https://github.com/bytecodealliance/cargo-component) and the `wasm32-wasip1` target.

```sh
rustup target add wasm32-wasip1
cargo install cargo-component
cargo component build --release
```

The output is `target/wasm32-wasip1/release/exlap_hook.wasm`.

## Deployment

Copy the `.wasm` file to the aa-proxy-rs device:

```sh
scp -O target/wasm32-wasip1/release/exlap_hook.wasm root@<aa-proxy-rs-address>:/data/wasm-hooks/exlap_hook.wasm
```

Then turn on the hook in the aa-proxy-rs web UI.

## WIT interface

The hook uses the `packet-hook` world from the aa-proxy-rs `wit/world.wit`
file. The copy in `wit/world.wit` must agree with the host when the interface
changes.
