//! HEP3 (Homer Encapsulation Protocol v3) codec and transport.
//!
//! HEP3 is the wire format Homer/HEPIC/HEPlify-Server collectors expect
//! for ingesting SIP signaling, RTCP, RTP-QoS, logs, and CDRs from
//! VoIP infrastructure. This crate provides:
//!
//! * A codec ([`HepPacket::encode`] / [`HepPacket::decode`]) that handles
//!   the chunk-based HEP3 envelope.
//! * A [`HepSink`] trait — the integration point a SIP stack, an RTP
//!   engine, or an application uses to ship observability data.
//! * [`UdpHepSink`], a non-blocking UDP transport (enabled by the
//!   default `transport-udp` feature) with a bounded queue, batching
//!   worker, and drop-on-full counter so emission never stalls the
//!   call path.
//!
//! # Wire format (HEP3)
//!
//! Every packet starts with the 4-byte magic `HEP3` followed by a
//! 2-byte big-endian total length. The body is a sequence of TLV
//! chunks:
//!
//! ```text
//! +--------+--------+--------+--------+
//! |   'H'  |   'E'  |   'P'  |   '3'  |
//! +--------+--------+--------+--------+
//! |     total length (u16 BE)         |
//! +--------+--------+--------+--------+
//! |  chunk 1 (vendor=2, type=2, len=2, payload=variable)
//! |  chunk 2 ...
//! +--------+--------+--------+--------+
//! ```
//!
//! The standard chunk types (vendor `0x0000`) are documented at
//! <https://github.com/sipcapture/HEP> and enumerated in [`StandardChunk`].
//!
//! # Quick start
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use std::time::SystemTime;
//! use hep_rs::{HepPacket, HepProtocol, IpProto};
//!
//! let pkt = HepPacket {
//!     capture_id: 2001,
//!     capture_password: None,
//!     protocol: HepProtocol::Sip,
//!     transport: IpProto::Udp,
//!     src: "10.0.0.1:5060".parse::<SocketAddr>().unwrap(),
//!     dst: "10.0.0.2:5060".parse::<SocketAddr>().unwrap(),
//!     timestamp: SystemTime::now(),
//!     correlation_id: Some("call-abc-123".into()),
//!     payload: b"INVITE sip:bob@example.com SIP/2.0\r\n...".to_vec(),
//! };
//! let bytes = pkt.encode();
//! let round_trip = HepPacket::decode(&bytes).unwrap();
//! assert_eq!(pkt, round_trip);
//! ```

#![deny(missing_docs)]

mod codec;
mod packet;

#[cfg(feature = "transport-udp")]
mod udp;

pub use codec::{DecodeError, StandardChunk};
pub use packet::{HepPacket, HepProtocol, IpProto};

#[cfg(feature = "transport-udp")]
pub use udp::{UdpHepSink, UdpHepSinkConfig, UdpHepSinkError};

use std::sync::Arc;

/// Where HEP-emitting libraries (siphon-rs, forge-media, …) ship
/// packets. Implementations MUST be non-blocking: a slow or
/// unreachable collector must not block the audio or signaling path.
///
/// The convention in this ecosystem is `Option<Arc<dyn HepSink>>` —
/// `None` means "HEP is disabled at this site" with zero cost; `Some`
/// means "fire and forget."
pub trait HepSink: Send + Sync {
    /// Enqueue a packet for shipping. MUST return immediately. Drops
    /// silently when the underlying queue is full (the sink's job is
    /// to surface drops via metrics, not to back-pressure the caller).
    fn send(&self, packet: HepPacket);
}

/// Convenience alias matching the dev-plan integration shape.
pub type HepSinkHandle = Arc<dyn HepSink>;
