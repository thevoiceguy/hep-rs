//! Non-blocking UDP transport for [`HepSink`].
//!
//! Design — see CLAUDE.md §4.7 in siphon-ai for the constraint that
//! motivates this layout:
//!
//! * The producer call site (a SIP message handler, an RTP packet
//!   loop, a CDR writer) calls [`UdpHepSink::send`] which is a single
//!   `mpsc::Sender::try_send`. Constant time, no encoding, no I/O.
//! * A spawned worker drains the receiver, encodes each packet, and
//!   `send_to`s the collector. When the queue is full the producer
//!   side increments a drop counter and returns immediately.
//! * If the collector is unreachable, the worker logs once per minute
//!   and keeps going. There is no retry queue — HEP is observability,
//!   so dropping a few packets is preferable to head-of-line blocking.
//!
//! v1 ships UDP only. TCP/TLS will land as separate sinks behind
//! their own feature flags so users who don't need them don't pay
//! for them in compile time or dependency surface.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::packet::HepPacket;
use crate::HepSink;

/// Default size of the queue between producer and worker. 256 fits
/// hundreds of milliseconds of SIP signaling at the high end and a
/// few RTCP cycles' worth of QoS reports. Tune via [`UdpHepSinkConfig`].
pub const DEFAULT_QUEUE_CAPACITY: usize = 256;

/// Operational knobs for [`UdpHepSink`]. All optional — `default()`
/// is sized for a typical small/medium PBX.
#[derive(Debug, Clone)]
pub struct UdpHepSinkConfig {
    /// Where Homer/HEPlify-Server is listening.
    pub collector: SocketAddr,
    /// Bounded queue capacity between producer and worker. Producer
    /// `try_send` drops + increments [`UdpHepSink::drops`] on full.
    pub queue_capacity: usize,
    /// How often to log a single "collector unreachable" warning
    /// when sends are failing. Stops the log from drowning the
    /// daemon during a Homer outage.
    pub warn_throttle: Duration,
}

impl UdpHepSinkConfig {
    /// Build a config with the Homer endpoint set and everything else
    /// at sensible defaults.
    pub fn new(collector: SocketAddr) -> Self {
        Self {
            collector,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            warn_throttle: Duration::from_secs(60),
        }
    }
}

/// Errors from [`UdpHepSink::start`]. The producer-side `send` is
/// infallible — every drop happens silently and bumps the counter.
#[derive(Debug, Error)]
pub enum UdpHepSinkError {
    /// Failed to create or bind the local UDP socket. Wraps the
    /// underlying `std::io::Error`.
    #[error("failed to bind UDP socket: {0}")]
    Bind(#[from] std::io::Error),
}

/// A [`HepSink`] that ships HEP3 packets over UDP. Construction
/// returns both the handle (clone-safe, share liberally) and a
/// worker task that MUST be driven on a runtime — typically the
/// caller spawns it or `Arc::clone` + holds the join handle so a
/// `Drop` impl can abort it on shutdown.
pub struct UdpHepSink {
    tx: mpsc::Sender<HepPacket>,
    drops: Arc<AtomicU64>,
    sent: Arc<AtomicU64>,
}

impl UdpHepSink {
    /// Bind a local UDP socket, spawn the worker task, and return a
    /// handle. The worker runs until the [`UdpHepSink`] (and every
    /// clone of it) is dropped — the closing channel triggers a
    /// graceful exit. The returned [`JoinHandle`] lets callers await
    /// the worker on shutdown if they want a deterministic teardown.
    pub async fn start(cfg: UdpHepSinkConfig) -> Result<(Self, JoinHandle<()>), UdpHepSinkError> {
        // Bind 0:0 (UDP, family matching the collector). The
        // ephemeral port is fine — collectors don't care which
        // source port we use, and Homer matches by capture_id.
        let bind_addr: SocketAddr = match cfg.collector {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        // `connect` lets us use `send` (no per-packet sockaddr) and
        // surfaces immediate ICMP errors on the *next* send.
        socket.connect(cfg.collector).await?;

        let (tx, rx) = mpsc::channel(cfg.queue_capacity);
        let drops = Arc::new(AtomicU64::new(0));
        let sent = Arc::new(AtomicU64::new(0));

        let worker = Worker {
            socket,
            rx,
            collector: cfg.collector,
            sent: Arc::clone(&sent),
            warn_throttle: cfg.warn_throttle,
        };
        let handle = tokio::spawn(worker.run());

        Ok((Self { tx, drops, sent }, handle))
    }

    /// Number of packets the producer side has dropped due to a full
    /// queue. Monotonic — read at any time, take a difference for a
    /// rate.
    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Number of packets the worker has successfully `send_to`'d.
    /// Counts wire-level success only — a packet a downstream NAT
    /// black-holes still counts here.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

impl Clone for UdpHepSink {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            drops: Arc::clone(&self.drops),
            sent: Arc::clone(&self.sent),
        }
    }
}

impl HepSink for UdpHepSink {
    fn send(&self, packet: HepPacket) {
        if self.tx.try_send(packet).is_err() {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct Worker {
    socket: UdpSocket,
    rx: mpsc::Receiver<HepPacket>,
    collector: SocketAddr,
    sent: Arc<AtomicU64>,
    warn_throttle: Duration,
}

impl Worker {
    async fn run(mut self) {
        // Per-throttle window we use to coalesce "collector
        // unreachable" warnings. tokio::time::Instant gives us a
        // monotonic clock independent of wall time skew.
        let mut last_warn: Option<tokio::time::Instant> = None;

        while let Some(packet) = self.rx.recv().await {
            let buf = packet.encode();
            match self.socket.send(&buf).await {
                Ok(_) => {
                    self.sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    let now = tokio::time::Instant::now();
                    let should_warn = match last_warn {
                        Some(prev) => now.duration_since(prev) >= self.warn_throttle,
                        None => true,
                    };
                    if should_warn {
                        warn!(
                            collector = %self.collector,
                            error = %e,
                            "HEP UDP send failed; further failures suppressed until throttle elapses"
                        );
                        last_warn = Some(now);
                    } else {
                        debug!(
                            collector = %self.collector,
                            error = %e,
                            "HEP UDP send failed (suppressed)"
                        );
                    }
                }
            }
        }
        debug!(collector = %self.collector, "HEP UDP worker exiting (sender dropped)");
    }
}
