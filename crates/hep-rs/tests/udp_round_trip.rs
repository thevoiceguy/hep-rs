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

/// Graceful `shutdown()` flushes packets still queued and lets the
/// worker exit cleanly — the property an embedder needs so a records
/// pipeline doesn't lose its final CDRs at process shutdown when the
/// producer side is held alive by immortal emitter clones (which is
/// why dropping the sink isn't a usable teardown for them).
///
/// A slow reader forces a backlog: we enqueue many packets against a
/// collector that only starts reading *after* we've signalled
/// shutdown, so the drain path — not steady-state delivery — is what
/// gets them across.
#[tokio::test]
async fn shutdown_flushes_the_queued_backlog() {
    let collector = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let collector_addr: SocketAddr = collector.local_addr().unwrap();

    // Queue big enough to hold the whole burst without dropping.
    let mut cfg = UdpHepSinkConfig::new(collector_addr);
    cfg.queue_capacity = 256;
    let (sink, worker) = UdpHepSink::start(cfg).await.expect("start sink");

    // A long-lived clone stands in for a process-wide emitter: it keeps
    // a sender alive, so the channel would NEVER close on its own.
    // Only `shutdown()` can drain the worker while this exists.
    let _immortal = sink.clone();

    const N: usize = 100;
    for _ in 0..N {
        sink.send(sample_packet());
    }
    assert_eq!(sink.drops(), 0, "queue was sized to hold the burst");

    // Signal graceful shutdown, then await the worker. The worker
    // closes its receiver and flushes the backlog before exiting.
    sink.shutdown();
    timeout(Duration::from_secs(5), worker)
        .await
        .expect("worker drains and exits within 5s")
        .expect("worker join");

    // Every queued packet was sent, despite the immortal sender clone.
    assert_eq!(
        sink.sent(),
        N as u64,
        "all queued packets flushed on shutdown"
    );

    // And the collector can actually receive them (they're on the wire,
    // not just counted). Drain what's buffered on the socket.
    let mut received = 0;
    let mut buf = vec![0u8; 4096];
    while received < N {
        match timeout(Duration::from_secs(1), collector.recv_from(&mut buf)).await {
            Ok(Ok(_)) => received += 1,
            _ => break,
        }
    }
    assert_eq!(received, N, "collector received the full flushed backlog");
}

/// After `shutdown()`, further `send`s are refused (counted as drops),
/// not silently accepted into a dead queue.
#[tokio::test]
async fn send_after_shutdown_is_dropped_not_lost_silently() {
    let collector = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let collector_addr: SocketAddr = collector.local_addr().unwrap();
    let (sink, worker) = UdpHepSink::start(UdpHepSinkConfig::new(collector_addr))
        .await
        .expect("start sink");

    sink.shutdown();
    timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker exits")
        .expect("join");

    // The receiver is closed; a post-shutdown send can't be queued.
    sink.send(sample_packet());
    assert_eq!(sink.sent(), 0);
    assert_eq!(sink.drops(), 1, "post-shutdown send is a drop, not a wedge");
}
