//! End-to-end test: a `UdpHepSink` ships an encoded HEP3 packet over
//! the wire to a tiny in-process UDP receiver which decodes it and
//! asserts the round-trip matches.
//!
//! Exercising the real `UdpSocket::send` path catches the bind/
//! connect/encode/wire-format integration that the unit tests in
//! `src/codec.rs` deliberately skip.

#![cfg(feature = "transport-udp")]

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use hep_rs::{HepPacket, HepProtocol, HepSink, IpProto, UdpHepSink, UdpHepSinkConfig};
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn sample_packet() -> HepPacket {
    HepPacket {
        capture_id: 2001,
        capture_password: Some("hunter2".into()),
        protocol: HepProtocol::Sip,
        transport: IpProto::Udp,
        src: "10.0.0.1:5060".parse().unwrap(),
        dst: "10.0.0.2:5060".parse().unwrap(),
        // Use a deterministic timestamp so round-trip equality is
        // straightforward; SystemTime resolution on the wire is 1µs.
        timestamp: SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000),
        correlation_id: Some("call-test-1".into()),
        payload: b"INVITE sip:bob@example.com SIP/2.0\r\nFrom: <sip:alice@example.com>\r\n\r\n"
            .to_vec(),
    }
}

#[tokio::test]
async fn udp_sink_delivers_an_encoded_packet_a_collector_can_decode() {
    // Start the "collector": a UDP socket on a kernel-chosen port.
    // We read one datagram and assert it round-trips through the
    // decoder identically to what the producer enqueued.
    let collector = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind collector");
    let collector_addr: SocketAddr = collector.local_addr().unwrap();

    let (sink, worker) = UdpHepSink::start(UdpHepSinkConfig::new(collector_addr))
        .await
        .expect("start sink");

    let pkt = sample_packet();
    sink.send(pkt.clone());

    let mut buf = vec![0u8; 2048];
    let (n, _peer) = timeout(Duration::from_secs(1), collector.recv_from(&mut buf))
        .await
        .expect("receive within 1s")
        .expect("recv ok");
    buf.truncate(n);

    let decoded = HepPacket::decode(&buf).expect("decode");
    assert_eq!(decoded, pkt);
    assert_eq!(sink.sent(), 1, "sent counter ticks on success");
    assert_eq!(sink.drops(), 0, "no drops on a happy path");

    // Drop the sink, which closes the channel and lets the worker
    // exit cleanly. Bound the wait so a hung worker fails the test
    // rather than the whole runtime.
    drop(sink);
    timeout(Duration::from_secs(1), worker)
        .await
        .expect("worker exits within 1s")
        .expect("worker join");
}

#[tokio::test]
async fn full_queue_drops_count_correctly() {
    // Stand up a collector that doesn't actually read — we just need
    // an address that's valid to connect to. We size the queue at 1
    // and immediately fire many packets; only the first occupies the
    // slot, the rest must drop.
    let collector = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let collector_addr: SocketAddr = collector.local_addr().unwrap();

    let mut cfg = UdpHepSinkConfig::new(collector_addr);
    cfg.queue_capacity = 1;
    let (sink, worker) = UdpHepSink::start(cfg).await.expect("start sink");

    // Saturate the channel synchronously so the worker can't drain
    // between sends. We fire 1000 quickly; even on a fast machine
    // the worker can't keep up because each send_to is an I/O.
    let pkt = sample_packet();
    for _ in 0..1000 {
        sink.send(pkt.clone());
    }

    // Give the worker a moment to drain anything that did fit.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sent = sink.sent();
    let drops = sink.drops();
    assert!(drops > 0, "queue full should produce drops; got {drops}");
    assert!(
        sent + drops <= 1000,
        "sent ({sent}) + drops ({drops}) should not exceed offered (1000)"
    );

    drop(sink);
    timeout(Duration::from_secs(1), worker)
        .await
        .expect("worker exits")
        .expect("join");
}
