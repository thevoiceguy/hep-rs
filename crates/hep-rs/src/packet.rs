//! [`HepPacket`] — the in-memory representation of one HEP3 message.

use std::net::SocketAddr;
use std::time::SystemTime;

/// One HEP3 packet ready to be encoded.
///
/// Fields map 1:1 onto the standard chunk types so encoding is a
/// straight serialization and decoding produces this exact shape.
/// Optional fields correspond to chunks the spec marks optional
/// (correlation ID, auth password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HepPacket {
    /// Chunk 0x000C — Capture Agent ID. The collector uses this to
    /// disambiguate multiple agents reporting into the same Homer.
    pub capture_id: u32,

    /// Chunk 0x000E — Authenticate Key (HEPlify-Server's shared
    /// password). `None` when the collector doesn't require auth;
    /// pass-through on the wire — the collector hashes/compares.
    pub capture_password: Option<String>,

    /// Chunk 0x000B — Protocol Type. Tells the collector how to
    /// parse `payload`.
    pub protocol: HepProtocol,

    /// Chunk 0x0002 — IP Protocol ID (UDP/TCP). The *transport*
    /// that carried the captured payload, not the HEP transport.
    pub transport: IpProto,

    /// Source of the captured packet (chunks 0x0001 + 0x0003/0x0005 + 0x0007).
    pub src: SocketAddr,

    /// Destination of the captured packet (chunks 0x0001 + 0x0004/0x0006 + 0x0008).
    pub dst: SocketAddr,

    /// Chunks 0x0009 + 0x000A — wall-clock timestamp split into
    /// seconds + microseconds since the Unix epoch. The encoder
    /// derives both from this value; if the SystemTime is earlier
    /// than the Unix epoch the encoder treats it as `UNIX_EPOCH`.
    pub timestamp: SystemTime,

    /// Chunk 0x0011 — Correlation ID. The string Homer uses to
    /// stitch SIP + RTCP + log + CDR records into one call view.
    /// Convention: the SIP Call-ID (or SiphonAI's internal call_id).
    pub correlation_id: Option<String>,

    /// Chunk 0x000F — the captured payload itself. For SIP, the raw
    /// message bytes; for RTCP, the RTCP packet; for logs, UTF-8
    /// text.
    pub payload: Vec<u8>,
}

/// Chunk 0x000B values, from the HEP3 spec. The numeric values are
/// wire-stable — do not renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum HepProtocol {
    /// 0x01 — SIP signaling. Most common type.
    Sip = 1,
    /// 0x02 — XMPP.
    Xmpp = 2,
    /// 0x03 — SDP (rarely used standalone; usually inside SIP).
    Sdp = 3,
    /// 0x04 — RTP. Captured payload is the RTP packet.
    Rtp = 4,
    /// 0x05 — RTCP report.
    Rtcp = 5,
    /// 0x06 — MGCP.
    Mgcp = 6,
    /// 0x07 — Megaco / H.248.
    Megaco = 7,
    /// 0x08 — M2UA / SS7.
    M2ua = 8,
    /// 0x09 — M3UA / SS7.
    M3ua = 9,
    /// 0x0A — IAX.
    Iax = 10,
    /// 0x0B — H.323/H.225.
    H323 = 11,
    /// 0x0C — H.321 Q.931.
    H321 = 12,
    /// 0x0D — M2PA / SS7.
    M2pa = 13,
    /// 0x22 (34) — MOS / call-quality report. Vendor convention.
    Mos = 34,
    /// 0x20 (32) — RTP-QoS summary. Vendor convention used by Homer.
    RtpQos = 32,
    /// 0x64 (100) — Application log line. Used by siphon-ai for
    /// significant lifecycle events.
    Log = 100,
    /// 0x65 (101) — Call Detail Record. Vendor convention used by
    /// siphon-ai for end-of-call summaries.
    Cdr = 101,
    /// 0x66 (102) — STIR/SHAKEN verification verdict (`verstat`). Vendor
    /// convention used by siphon-ai: one chunk emitted per inbound call when
    /// verification is enabled, payload is the verdict as JSON, correlated by
    /// call_id so Homer threads it through the same SIP + RTCP view.
    Verstat = 102,
}

impl HepProtocol {
    /// Convert from the wire byte. Unknown values are accepted as
    /// [`HepProtocol::Sip`] would be over-strict; the codec returns
    /// `None` so the caller can decide whether to discard or surface
    /// the raw byte. Use [`HepProtocol::from_u8_lossy`] for the
    /// best-effort form.
    pub fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Sip,
            2 => Self::Xmpp,
            3 => Self::Sdp,
            4 => Self::Rtp,
            5 => Self::Rtcp,
            6 => Self::Mgcp,
            7 => Self::Megaco,
            8 => Self::M2ua,
            9 => Self::M3ua,
            10 => Self::Iax,
            11 => Self::H323,
            12 => Self::H321,
            13 => Self::M2pa,
            32 => Self::RtpQos,
            34 => Self::Mos,
            100 => Self::Log,
            101 => Self::Cdr,
            102 => Self::Verstat,
            _ => return None,
        })
    }

    /// Wire byte.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Chunk 0x0002 values. Subset of IANA — only what HEP carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum IpProto {
    /// IPPROTO_TCP.
    Tcp = 6,
    /// IPPROTO_UDP.
    Udp = 17,
    /// IPPROTO_SCTP. Rare but valid.
    Sctp = 132,
}

impl IpProto {
    /// Convert from the wire byte.
    pub fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            6 => Self::Tcp,
            17 => Self::Udp,
            132 => Self::Sctp,
            _ => return None,
        })
    }

    /// Wire byte.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hep_protocol_roundtrips_through_wire_byte() {
        for p in [
            HepProtocol::Sip,
            HepProtocol::Rtcp,
            HepProtocol::RtpQos,
            HepProtocol::Mos,
            HepProtocol::Log,
            HepProtocol::Cdr,
            HepProtocol::Verstat,
        ] {
            assert_eq!(HepProtocol::from_u8(p.as_u8()), Some(p));
        }
    }

    #[test]
    fn verstat_is_wire_value_102() {
        // Wire-stable: 0x66. Locked so a future renumber is a visible diff.
        assert_eq!(HepProtocol::Verstat.as_u8(), 102);
        assert_eq!(HepProtocol::from_u8(102), Some(HepProtocol::Verstat));
    }

    #[test]
    fn unknown_protocol_byte_is_none() {
        assert_eq!(HepProtocol::from_u8(250), None);
    }
}
