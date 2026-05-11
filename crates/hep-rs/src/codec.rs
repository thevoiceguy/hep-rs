//! HEP3 wire-format encoder + decoder.
//!
//! See <https://github.com/sipcapture/HEP> for the canonical spec.
//! The format is small enough that we hand-roll the encoder rather
//! than pulling in a derive-based codec crate; this keeps zero deps
//! on the hot encoder path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::packet::{HepPacket, HepProtocol, IpProto};

// ─── Wire constants ─────────────────────────────────────────────────

/// HEP3 magic: ASCII `H` `E` `P` `3`.
pub(crate) const MAGIC: &[u8; 4] = b"HEP3";

/// Bytes consumed by the fixed packet header (magic + total length).
const HEADER_LEN: usize = 6;
/// Bytes consumed by each chunk's TLV header (vendor + type + length).
const CHUNK_HEADER_LEN: usize = 6;

/// Vendor ID for the standard chunk types defined by the spec
/// itself. Custom chunks use other IANA-assigned or community-
/// chosen vendor IDs.
const VENDOR_GENERIC: u16 = 0x0000;

/// Standard chunk type IDs (vendor `0x0000`). The values are
/// wire-stable and documented in the HEP3 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StandardChunk {
    /// IP protocol family — `2` for IPv4, `10` for IPv6.
    IpFamily = 0x0001,
    /// IP protocol ID — `6` TCP, `17` UDP, `132` SCTP.
    IpProtocolId = 0x0002,
    /// IPv4 source address (4 bytes, big-endian).
    Ipv4Src = 0x0003,
    /// IPv4 destination address (4 bytes, big-endian).
    Ipv4Dst = 0x0004,
    /// IPv6 source address (16 bytes).
    Ipv6Src = 0x0005,
    /// IPv6 destination address (16 bytes).
    Ipv6Dst = 0x0006,
    /// Source port (u16 BE).
    SrcPort = 0x0007,
    /// Destination port (u16 BE).
    DstPort = 0x0008,
    /// Timestamp seconds since Unix epoch (u32 BE).
    TimestampSec = 0x0009,
    /// Timestamp microseconds within the second (u32 BE).
    TimestampUsec = 0x000A,
    /// Protocol type — see [`crate::HepProtocol`].
    ProtocolType = 0x000B,
    /// Capture Agent ID (u32 BE).
    CaptureAgentId = 0x000C,
    /// HEPlify-Server shared-password chunk (variable-length string).
    AuthKey = 0x000E,
    /// Captured payload (variable length).
    Payload = 0x000F,
    /// Internal Correlation ID (variable-length string).
    CorrelationId = 0x0011,
}

const FAMILY_IPV4: u8 = 2;
const FAMILY_IPV6: u8 = 10;

// ─── Errors ─────────────────────────────────────────────────────────

/// All the ways [`HepPacket::decode`] can fail. Aimed at giving the
/// operator enough context to triage a bad collector packet without
/// drowning them in detail.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// Too few bytes to even hold a HEP3 header.
    #[error("packet too short ({0} bytes; needed at least {HEADER_LEN})")]
    Truncated(usize),

    /// First four bytes were not `HEP3`.
    #[error("bad magic: expected 'HEP3', got {0:?}")]
    BadMagic([u8; 4]),

    /// `total_length` header doesn't agree with the buffer size.
    #[error("length mismatch: header says {claimed}, buffer has {actual}")]
    LengthMismatch {
        /// Length the packet header claimed.
        claimed: usize,
        /// Buffer length we actually have.
        actual: usize,
    },

    /// A chunk's TLV header ran past the packet boundary.
    #[error("truncated chunk at offset {offset}")]
    TruncatedChunk {
        /// Byte offset where the bad chunk started.
        offset: usize,
    },

    /// A chunk's `length` field was smaller than its 6-byte header.
    #[error("chunk length {0} smaller than the 6-byte header")]
    UndersizedChunk(u16),

    /// Required chunk for a complete packet was missing.
    #[error("missing required chunk: {0:?}")]
    MissingChunk(StandardChunk),

    /// Chunk payload size didn't match what its type requires.
    #[error("chunk {kind:?} has wrong size: {got} (expected {expected})")]
    BadSize {
        /// Which chunk was malformed.
        kind: StandardChunk,
        /// Bytes received.
        got: usize,
        /// Bytes the spec mandates.
        expected: usize,
    },

    /// IP family chunk wasn't 2 (v4) or 10 (v6).
    #[error("unsupported IP family: {0}")]
    UnsupportedIpFamily(u8),

    /// IP protocol byte wasn't one we recognize.
    #[error("unsupported IP protocol: {0}")]
    UnsupportedIpProtocol(u8),

    /// Protocol type chunk carried a value not in [`HepProtocol`].
    #[error("unsupported HEP protocol type: {0}")]
    UnsupportedHepProtocol(u8),

    /// A string-typed chunk (correlation id, auth key) wasn't UTF-8.
    #[error("chunk {0:?} payload was not UTF-8")]
    NotUtf8(StandardChunk),
}

// ─── Encoder ────────────────────────────────────────────────────────

impl HepPacket {
    /// Encode the packet to a freshly-allocated buffer ready for the
    /// wire. Always succeeds — every field maps directly onto a
    /// chunk; oversize payloads are bounded by the underlying
    /// `Vec`/`String` types.
    pub fn encode(&self) -> Vec<u8> {
        // Best-guess capacity; the encoder grows as needed.
        let mut out = Vec::with_capacity(HEADER_LEN + 96 + self.payload.len());

        // Reserve the 6-byte fixed header. We backfill the total
        // length at the end once we know what it is.
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&[0u8, 0u8]); // placeholder length

        // IP family is derived from src; src and dst MUST share a
        // family in a real capture, but we don't enforce it here —
        // an aware caller can fabricate weird packets if they want.
        let family = match self.src.ip() {
            IpAddr::V4(_) => FAMILY_IPV4,
            IpAddr::V6(_) => FAMILY_IPV6,
        };
        write_chunk_u8(&mut out, StandardChunk::IpFamily, family);
        write_chunk_u8(
            &mut out,
            StandardChunk::IpProtocolId,
            self.transport.as_u8(),
        );

        write_ip_chunk(&mut out, self.src.ip(), true);
        write_ip_chunk(&mut out, self.dst.ip(), false);

        write_chunk_u16(&mut out, StandardChunk::SrcPort, self.src.port());
        write_chunk_u16(&mut out, StandardChunk::DstPort, self.dst.port());

        let (sec, usec) = unix_split(self.timestamp);
        write_chunk_u32(&mut out, StandardChunk::TimestampSec, sec);
        write_chunk_u32(&mut out, StandardChunk::TimestampUsec, usec);

        write_chunk_u8(&mut out, StandardChunk::ProtocolType, self.protocol.as_u8());
        write_chunk_u32(&mut out, StandardChunk::CaptureAgentId, self.capture_id);

        if let Some(pw) = self.capture_password.as_ref() {
            write_chunk_bytes(&mut out, StandardChunk::AuthKey, pw.as_bytes());
        }
        if let Some(corr) = self.correlation_id.as_ref() {
            write_chunk_bytes(&mut out, StandardChunk::CorrelationId, corr.as_bytes());
        }

        // Payload last — collectors that want to log the envelope
        // first read it before the (potentially large) payload.
        write_chunk_bytes(&mut out, StandardChunk::Payload, &self.payload);

        // Backfill the total length. HEP3 caps at u16 — payloads
        // larger than ~65 KiB are clamped down by the spec, not by
        // us. We trust the caller to keep payloads sane (SIP MTU is
        // <2KiB; RTCP <1KiB; CDR/log <8KiB in practice).
        let len = u16::try_from(out.len()).unwrap_or(u16::MAX);
        out[4..6].copy_from_slice(&len.to_be_bytes());

        out
    }

    /// Decode a single HEP3 packet from `buf`. Returns the parsed
    /// packet on success, or [`DecodeError`] describing what was
    /// wrong with the wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::Truncated(buf.len()));
        }
        let magic = <[u8; 4]>::try_from(&buf[..4]).expect("4 bytes");
        if &magic != MAGIC {
            return Err(DecodeError::BadMagic(magic));
        }
        let total = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        if total != buf.len() {
            return Err(DecodeError::LengthMismatch {
                claimed: total,
                actual: buf.len(),
            });
        }

        let mut parts = PartialPacket::default();
        let mut cursor = HEADER_LEN;
        while cursor < total {
            if cursor + CHUNK_HEADER_LEN > total {
                return Err(DecodeError::TruncatedChunk { offset: cursor });
            }
            let vendor = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
            let kind = u16::from_be_bytes([buf[cursor + 2], buf[cursor + 3]]);
            let chunk_len = u16::from_be_bytes([buf[cursor + 4], buf[cursor + 5]]) as usize;
            if chunk_len < CHUNK_HEADER_LEN {
                return Err(DecodeError::UndersizedChunk(chunk_len as u16));
            }
            if cursor + chunk_len > total {
                return Err(DecodeError::TruncatedChunk { offset: cursor });
            }
            let payload = &buf[cursor + CHUNK_HEADER_LEN..cursor + chunk_len];

            // Vendor-specific chunks aren't handled in v1 — they're
            // not invalid, just unknown. Skip and keep parsing so a
            // forge-hep RTP-QoS chunk in the same packet doesn't kill
            // SIP decoding.
            if vendor == VENDOR_GENERIC {
                parts.absorb(kind, payload)?;
            }

            cursor += chunk_len;
        }

        parts.finish()
    }
}

// ─── Decoder helpers ────────────────────────────────────────────────

/// Accumulator the decoder fills in chunk-by-chunk. We use raw
/// integer fields for the IP/port pieces so we can reconstruct the
/// `SocketAddr`s only once both halves of a v4/v6 pair land.
#[derive(Default)]
struct PartialPacket {
    ip_family: Option<u8>,
    ip_proto: Option<u8>,
    ipv4_src: Option<[u8; 4]>,
    ipv4_dst: Option<[u8; 4]>,
    ipv6_src: Option<[u8; 16]>,
    ipv6_dst: Option<[u8; 16]>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    ts_sec: Option<u32>,
    ts_usec: Option<u32>,
    protocol: Option<HepProtocol>,
    capture_id: Option<u32>,
    capture_password: Option<String>,
    correlation_id: Option<String>,
    payload: Option<Vec<u8>>,
}

impl PartialPacket {
    fn absorb(&mut self, kind: u16, payload: &[u8]) -> Result<(), DecodeError> {
        match kind {
            x if x == StandardChunk::IpFamily as u16 => {
                self.ip_family = Some(read_u8(StandardChunk::IpFamily, payload)?);
            }
            x if x == StandardChunk::IpProtocolId as u16 => {
                self.ip_proto = Some(read_u8(StandardChunk::IpProtocolId, payload)?);
            }
            x if x == StandardChunk::Ipv4Src as u16 => {
                self.ipv4_src = Some(read_array::<4>(StandardChunk::Ipv4Src, payload)?);
            }
            x if x == StandardChunk::Ipv4Dst as u16 => {
                self.ipv4_dst = Some(read_array::<4>(StandardChunk::Ipv4Dst, payload)?);
            }
            x if x == StandardChunk::Ipv6Src as u16 => {
                self.ipv6_src = Some(read_array::<16>(StandardChunk::Ipv6Src, payload)?);
            }
            x if x == StandardChunk::Ipv6Dst as u16 => {
                self.ipv6_dst = Some(read_array::<16>(StandardChunk::Ipv6Dst, payload)?);
            }
            x if x == StandardChunk::SrcPort as u16 => {
                self.src_port = Some(read_u16(StandardChunk::SrcPort, payload)?);
            }
            x if x == StandardChunk::DstPort as u16 => {
                self.dst_port = Some(read_u16(StandardChunk::DstPort, payload)?);
            }
            x if x == StandardChunk::TimestampSec as u16 => {
                self.ts_sec = Some(read_u32(StandardChunk::TimestampSec, payload)?);
            }
            x if x == StandardChunk::TimestampUsec as u16 => {
                self.ts_usec = Some(read_u32(StandardChunk::TimestampUsec, payload)?);
            }
            x if x == StandardChunk::ProtocolType as u16 => {
                let byte = read_u8(StandardChunk::ProtocolType, payload)?;
                self.protocol = Some(
                    HepProtocol::from_u8(byte).ok_or(DecodeError::UnsupportedHepProtocol(byte))?,
                );
            }
            x if x == StandardChunk::CaptureAgentId as u16 => {
                self.capture_id = Some(read_u32(StandardChunk::CaptureAgentId, payload)?);
            }
            x if x == StandardChunk::AuthKey as u16 => {
                self.capture_password = Some(
                    std::str::from_utf8(payload)
                        .map_err(|_| DecodeError::NotUtf8(StandardChunk::AuthKey))?
                        .to_string(),
                );
            }
            x if x == StandardChunk::CorrelationId as u16 => {
                self.correlation_id = Some(
                    std::str::from_utf8(payload)
                        .map_err(|_| DecodeError::NotUtf8(StandardChunk::CorrelationId))?
                        .to_string(),
                );
            }
            x if x == StandardChunk::Payload as u16 => {
                self.payload = Some(payload.to_vec());
            }
            // Unknown standard chunk type — ignore and keep going.
            // The spec evolves; new chunks shouldn't poison decoding.
            _ => {}
        }
        Ok(())
    }

    fn finish(self) -> Result<HepPacket, DecodeError> {
        let family = self
            .ip_family
            .ok_or(DecodeError::MissingChunk(StandardChunk::IpFamily))?;
        let proto_id = self
            .ip_proto
            .ok_or(DecodeError::MissingChunk(StandardChunk::IpProtocolId))?;
        let src_port = self
            .src_port
            .ok_or(DecodeError::MissingChunk(StandardChunk::SrcPort))?;
        let dst_port = self
            .dst_port
            .ok_or(DecodeError::MissingChunk(StandardChunk::DstPort))?;
        let ts_sec = self
            .ts_sec
            .ok_or(DecodeError::MissingChunk(StandardChunk::TimestampSec))?;
        let ts_usec = self
            .ts_usec
            .ok_or(DecodeError::MissingChunk(StandardChunk::TimestampUsec))?;
        let protocol = self
            .protocol
            .ok_or(DecodeError::MissingChunk(StandardChunk::ProtocolType))?;
        let capture_id = self
            .capture_id
            .ok_or(DecodeError::MissingChunk(StandardChunk::CaptureAgentId))?;
        let payload = self
            .payload
            .ok_or(DecodeError::MissingChunk(StandardChunk::Payload))?;

        let transport =
            IpProto::from_u8(proto_id).ok_or(DecodeError::UnsupportedIpProtocol(proto_id))?;

        let (src_ip, dst_ip) = match family {
            FAMILY_IPV4 => {
                let s = self
                    .ipv4_src
                    .ok_or(DecodeError::MissingChunk(StandardChunk::Ipv4Src))?;
                let d = self
                    .ipv4_dst
                    .ok_or(DecodeError::MissingChunk(StandardChunk::Ipv4Dst))?;
                (IpAddr::V4(Ipv4Addr::from(s)), IpAddr::V4(Ipv4Addr::from(d)))
            }
            FAMILY_IPV6 => {
                let s = self
                    .ipv6_src
                    .ok_or(DecodeError::MissingChunk(StandardChunk::Ipv6Src))?;
                let d = self
                    .ipv6_dst
                    .ok_or(DecodeError::MissingChunk(StandardChunk::Ipv6Dst))?;
                (IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)))
            }
            other => return Err(DecodeError::UnsupportedIpFamily(other)),
        };

        let timestamp =
            UNIX_EPOCH + std::time::Duration::new(u64::from(ts_sec), ts_usec.saturating_mul(1000));

        Ok(HepPacket {
            capture_id,
            capture_password: self.capture_password,
            protocol,
            transport,
            src: SocketAddr::new(src_ip, src_port),
            dst: SocketAddr::new(dst_ip, dst_port),
            timestamp,
            correlation_id: self.correlation_id,
            payload,
        })
    }
}

fn read_u8(kind: StandardChunk, p: &[u8]) -> Result<u8, DecodeError> {
    if p.len() != 1 {
        return Err(DecodeError::BadSize {
            kind,
            got: p.len(),
            expected: 1,
        });
    }
    Ok(p[0])
}

fn read_u16(kind: StandardChunk, p: &[u8]) -> Result<u16, DecodeError> {
    if p.len() != 2 {
        return Err(DecodeError::BadSize {
            kind,
            got: p.len(),
            expected: 2,
        });
    }
    Ok(u16::from_be_bytes([p[0], p[1]]))
}

fn read_u32(kind: StandardChunk, p: &[u8]) -> Result<u32, DecodeError> {
    if p.len() != 4 {
        return Err(DecodeError::BadSize {
            kind,
            got: p.len(),
            expected: 4,
        });
    }
    Ok(u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
}

fn read_array<const N: usize>(kind: StandardChunk, p: &[u8]) -> Result<[u8; N], DecodeError> {
    <[u8; N]>::try_from(p).map_err(|_| DecodeError::BadSize {
        kind,
        got: p.len(),
        expected: N,
    })
}

// ─── Encoder helpers ────────────────────────────────────────────────

fn write_chunk_header(out: &mut Vec<u8>, kind: StandardChunk, payload_len: usize) {
    out.extend_from_slice(&VENDOR_GENERIC.to_be_bytes());
    out.extend_from_slice(&(kind as u16).to_be_bytes());
    let len = u16::try_from(CHUNK_HEADER_LEN + payload_len).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
}

fn write_chunk_u8(out: &mut Vec<u8>, kind: StandardChunk, val: u8) {
    write_chunk_header(out, kind, 1);
    out.push(val);
}

fn write_chunk_u16(out: &mut Vec<u8>, kind: StandardChunk, val: u16) {
    write_chunk_header(out, kind, 2);
    out.extend_from_slice(&val.to_be_bytes());
}

fn write_chunk_u32(out: &mut Vec<u8>, kind: StandardChunk, val: u32) {
    write_chunk_header(out, kind, 4);
    out.extend_from_slice(&val.to_be_bytes());
}

fn write_chunk_bytes(out: &mut Vec<u8>, kind: StandardChunk, val: &[u8]) {
    write_chunk_header(out, kind, val.len());
    out.extend_from_slice(val);
}

fn write_ip_chunk(out: &mut Vec<u8>, ip: IpAddr, is_src: bool) {
    match ip {
        IpAddr::V4(v4) => {
            let kind = if is_src {
                StandardChunk::Ipv4Src
            } else {
                StandardChunk::Ipv4Dst
            };
            write_chunk_bytes(out, kind, &v4.octets());
        }
        IpAddr::V6(v6) => {
            let kind = if is_src {
                StandardChunk::Ipv6Src
            } else {
                StandardChunk::Ipv6Dst
            };
            write_chunk_bytes(out, kind, &v6.octets());
        }
    }
}

fn unix_split(t: SystemTime) -> (u32, u32) {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = u32::try_from(dur.as_secs()).unwrap_or(u32::MAX);
    let usecs = dur.subsec_micros();
    (secs, usecs)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn sample_pkt(family_v6: bool) -> HepPacket {
        let (src, dst): (SocketAddr, SocketAddr) = if family_v6 {
            (
                "[fd00::1]:5060".parse().unwrap(),
                "[fd00::2]:5060".parse().unwrap(),
            )
        } else {
            (
                "10.1.2.3:5060".parse().unwrap(),
                "10.4.5.6:5060".parse().unwrap(),
            )
        };
        HepPacket {
            capture_id: 2001,
            capture_password: Some("hunter2".into()),
            protocol: HepProtocol::Sip,
            transport: IpProto::Udp,
            src,
            dst,
            timestamp: UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000),
            correlation_id: Some("call-abc".into()),
            payload: b"INVITE sip:a@b SIP/2.0\r\n\r\n".to_vec(),
        }
    }

    #[test]
    fn round_trip_v4() {
        let pkt = sample_pkt(false);
        let bytes = pkt.encode();
        let decoded = HepPacket::decode(&bytes).expect("decode");
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn round_trip_v6() {
        let pkt = sample_pkt(true);
        let bytes = pkt.encode();
        let decoded = HepPacket::decode(&bytes).expect("decode");
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn round_trip_no_optional_chunks() {
        let mut pkt = sample_pkt(false);
        pkt.capture_password = None;
        pkt.correlation_id = None;
        let bytes = pkt.encode();
        let decoded = HepPacket::decode(&bytes).expect("decode");
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn header_is_well_formed() {
        let pkt = sample_pkt(false);
        let bytes = pkt.encode();
        assert_eq!(&bytes[..4], MAGIC, "magic");
        let claimed = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        assert_eq!(claimed, bytes.len(), "header length agrees with buffer");
    }

    #[test]
    fn truncated_buffer_errors() {
        let err = HepPacket::decode(&[]).expect_err("too short");
        assert!(matches!(err, DecodeError::Truncated(0)));

        let err = HepPacket::decode(b"HEP").expect_err("less than 6");
        assert!(matches!(err, DecodeError::Truncated(3)));
    }

    #[test]
    fn bad_magic_errors() {
        let bytes = [b'N', b'O', b'P', b'E', 0, 6];
        let err = HepPacket::decode(&bytes).expect_err("bad magic");
        assert!(matches!(
            err,
            DecodeError::BadMagic([b'N', b'O', b'P', b'E'])
        ));
    }

    #[test]
    fn length_mismatch_errors() {
        let pkt = sample_pkt(false);
        let mut bytes = pkt.encode();
        // Force the header to claim a length one byte off; preserve
        // buffer length so we trigger the mismatch path.
        let lie = (bytes.len() + 1) as u16;
        bytes[4..6].copy_from_slice(&lie.to_be_bytes());
        let err = HepPacket::decode(&bytes).expect_err("mismatch");
        assert!(matches!(err, DecodeError::LengthMismatch { .. }));
    }

    #[test]
    fn missing_required_chunk_errors() {
        // A header + an empty body has all magic+length but no chunks.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&6u16.to_be_bytes());
        let err = HepPacket::decode(&bytes).expect_err("missing chunks");
        assert!(matches!(err, DecodeError::MissingChunk(_)));
    }

    #[test]
    fn unknown_protocol_byte_surfaces() {
        // Build a valid v4 packet then patch the ProtocolType chunk
        // payload from 1 (SIP) to 250 (reserved/unknown).
        let mut bytes = sample_pkt(false).encode();
        let mut i = HEADER_LEN;
        while i < bytes.len() {
            let kind = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]);
            let len = u16::from_be_bytes([bytes[i + 4], bytes[i + 5]]) as usize;
            if kind == StandardChunk::ProtocolType as u16 {
                bytes[i + CHUNK_HEADER_LEN] = 250;
                break;
            }
            i += len;
        }
        let err = HepPacket::decode(&bytes).expect_err("unknown protocol");
        assert!(matches!(err, DecodeError::UnsupportedHepProtocol(250)));
    }

    #[test]
    fn payload_chunk_sits_last_on_the_wire() {
        // Useful invariant for collectors that read chunk-by-chunk
        // and want to defer payload allocation; not strictly required
        // by the spec, but documented in our encoder.
        let pkt = sample_pkt(false);
        let bytes = pkt.encode();
        let mut last_kind = 0u16;
        let mut i = HEADER_LEN;
        while i < bytes.len() {
            last_kind = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]);
            let len = u16::from_be_bytes([bytes[i + 4], bytes[i + 5]]) as usize;
            i += len;
        }
        assert_eq!(last_kind, StandardChunk::Payload as u16);
    }

    #[test]
    fn unknown_chunk_types_are_ignored_not_rejected() {
        // Forward-compat: a future spec adding a chunk type 0x0099
        // should not poison decoding of the rest of the packet.
        let pkt = sample_pkt(false);
        let mut bytes = pkt.encode();

        // Splice in a 7-byte unknown chunk (6-byte header + 1 byte
        // payload) right after the fixed header. Update total length.
        let unknown = {
            let mut v = Vec::new();
            v.extend_from_slice(&VENDOR_GENERIC.to_be_bytes());
            v.extend_from_slice(&0x0099u16.to_be_bytes()); // unknown kind
            v.extend_from_slice(&7u16.to_be_bytes()); // length 7
            v.push(0xAA);
            v
        };
        bytes.splice(HEADER_LEN..HEADER_LEN, unknown.iter().copied());
        let new_total = bytes.len() as u16;
        bytes[4..6].copy_from_slice(&new_total.to_be_bytes());

        let decoded = HepPacket::decode(&bytes).expect("ignored unknown chunk");
        assert_eq!(
            decoded, pkt,
            "decoded packet matches the pre-splice original"
        );
    }
}
