# hep-rs

[HEP3](https://github.com/sipcapture/HEP) (Homer Encapsulation Protocol v3)
codec and transport for Rust.

HEP3 is the wire format [Homer](https://sipcapture.io/), HEPIC, and
HEPlify-Server collectors expect for ingesting SIP signaling, RTCP, RTP-QoS
summaries, logs, and CDRs from VoIP infrastructure. Every serious VoIP
platform in the OSS world emits HEP — FreeSWITCH (`mod_sofia` HEP),
Kamailio (`siptrace`), OpenSIPS (`proto_hep`), Asterisk (`res_hep`),
rtpengine. This crate brings the same capability to Rust-based stacks.

## Status

Early. v0.0.1 ships the codec, a `HepSink` trait, and a non-blocking UDP
transport. TCP, TLS, RTP-QoS chunk encoding, and HEPlify-Server auth
round-trip are deferred to follow-up releases.

## What's in the box

- **Codec.** `HepPacket::encode` / `HepPacket::decode` covering the
  standard HEP3 chunk types: IP family, IP protocol, IPv4/v6 src/dst
  addresses, src/dst ports, timestamps, protocol type, capture agent
  ID, auth key, correlation ID, and the captured payload.
- **`HepSink` trait.** The integration point a SIP stack, RTP engine,
  or application uses. Implementations must be non-blocking; a slow or
  unreachable collector must not stall the call path.
- **`UdpHepSink`.** A non-blocking UDP transport with a bounded
  producer queue, a spawned worker that owns the socket, a drop-on-
  full counter, and rate-limited "collector unreachable" warnings.

## Why HEP3?

Native HEP emission ships richer correlation data than packet-sniffing
agents (`heplify`, `captagent`) and works in containers/cloud where
promiscuous capture isn't available. With the SIP Call-ID (or your
internal call_id) plumbed in as the correlation chunk, Homer stitches
SIP + RTCP + logs + CDRs into one call view in the UI.

## Quick start

```rust,no_run
use std::sync::Arc;
use hep_rs::{HepPacket, HepProtocol, HepSink, IpProto, UdpHepSink, UdpHepSinkConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let collector = "127.0.0.1:9060".parse()?;
    let (sink, _worker) = UdpHepSink::start(UdpHepSinkConfig::new(collector)).await?;
    let sink: Arc<dyn HepSink> = Arc::new(sink);

    // Whenever you parse / serialize a SIP message, RTCP report, etc:
    sink.send(HepPacket {
        capture_id: 2001,
        capture_password: None,
        protocol: HepProtocol::Sip,
        transport: IpProto::Udp,
        src: "10.0.0.1:5060".parse()?,
        dst: "10.0.0.2:5060".parse()?,
        timestamp: std::time::SystemTime::now(),
        correlation_id: Some("call-abc-123".into()),
        payload: b"INVITE sip:bob@example.com SIP/2.0\r\n...".to_vec(),
    });
    Ok(())
}
```

## Supported chunk types

| Chunk ID | Field on `HepPacket`            | Notes                                                  |
|---------:|---------------------------------|--------------------------------------------------------|
| `0x0001` | `src.ip()` (derived)            | IP family — `2` IPv4, `10` IPv6                        |
| `0x0002` | `transport`                     | `6` TCP, `17` UDP, `132` SCTP                          |
| `0x0003` | `src.ip()`                      | IPv4 source                                            |
| `0x0004` | `dst.ip()`                      | IPv4 destination                                       |
| `0x0005` | `src.ip()`                      | IPv6 source                                            |
| `0x0006` | `dst.ip()`                      | IPv6 destination                                       |
| `0x0007` | `src.port()`                    | Source port                                            |
| `0x0008` | `dst.port()`                    | Destination port                                       |
| `0x0009` | `timestamp` (seconds)           | Unix seconds                                           |
| `0x000A` | `timestamp` (microseconds)      | Microseconds within the second                         |
| `0x000B` | `protocol`                      | `HepProtocol` — SIP, RTCP, Log, CDR, RTP-QoS, …        |
| `0x000C` | `capture_id`                    | Homer agent ID                                         |
| `0x000E` | `capture_password`              | HEPlify-Server shared password (optional)              |
| `0x000F` | `payload`                       | Captured packet bytes                                  |
| `0x0011` | `correlation_id`                | Per-call ID for cross-protocol correlation             |

Vendor-specific chunks (e.g., RTP-QoS at vendor `0x0063`) are skipped
gracefully on decode and will be addable via a vendor-chunk extension
API in a follow-up.

## Design

- **Zero-cost when disabled.** Consumers integrate as
  `Option<Arc<dyn HepSink>>`; `None` is a noop.
- **Non-blocking producer.** `HepSink::send` is `try_send` on an mpsc
  channel. On full, the drop counter ticks and the call site moves on.
- **Encoding off the producer path.** The UDP worker owns encoding and
  `send_to`, so the SIP / RTP / log site never pays the encoder cost.
- **Drop-and-count beats back-pressure.** HEP is observability; head-
  of-line blocking is unacceptable. Operators monitor the drop counter.

## Features

| Feature        | Default? | What it adds                  |
|----------------|----------|-------------------------------|
| `transport-udp`| yes      | `UdpHepSink` + worker          |

Disabling `transport-udp` (`default-features = false`) leaves you with
just the codec + `HepSink` trait — useful if you want to embed a
custom transport (TCP, TLS, message-queue, etc.).

## Roadmap

- TCP transport
- TLS transport (rustls)
- Vendor-chunk extension API (RTP-QoS, custom logs)
- HEPlify-Server auth handshake polish
- Benchmarks

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Issues and PRs welcome. The codec is intentionally small and hand-
rolled; please keep new code allocation-conscious and document the
*why* in comments.
