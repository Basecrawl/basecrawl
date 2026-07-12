//! VAL-CONF-013 residual: sealed browser DNS isolation.
//!
//! Chromium render/screenshot must not emit target QNAMEs on host system DNS
//! (port 53). Resolution goes through the in-process sealed SOCKS5 proxy which
//! uses pin-by-IP DoH exclusively. This suite proves:
//!
//! 1. Domain CONNECT through the sealed SOCKS uses the injected NameResolver
//!    (no cleartext DNS frame to a peer UDP sink).
//! 2. Fail-closed preflight surfaces `SealError::Dns` when sealed resolve fails.
//! 3. Chrome isolation flag packing always pairs SOCKS with host-resolver-rules
//!    that disable non-loopback system lookups.

use basecrawl_seal::{
    chrome_dns_isolation_proxy_arg, document_host_needs_sealed_resolve, preflight_document_dns,
    NameResolver, ResolverEndpoint, SealError, SealedSocksProxy, DEFAULT_DOH_ENDPOINT,
    SEALED_BROWSER_DNS_MARKER,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const TARGET_QNAME: &str = "confid-browser-target.basecrawl.test";

#[derive(Default, Clone)]
struct HostDnsCapture {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl HostDnsCapture {
    fn push(&self, frame: Vec<u8>) {
        self.frames.lock().unwrap().push(frame);
    }

    fn assert_no_qname(&self, qname: &str) {
        let qname_l = qname.to_ascii_lowercase();
        let qname_bytes = qname_l.as_bytes();
        let labels: Vec<&[u8]> = qname_l.split('.').map(|s| s.as_bytes()).collect();
        for frame in self.frames.lock().unwrap().iter() {
            let hay = frame.as_slice();
            assert!(
                !hay.windows(qname_bytes.len())
                    .any(|w| w.eq_ignore_ascii_case(qname_bytes)),
                "host DNS capture must not contain cleartext QNAME {qname}"
            );
            if labels.len() >= 2 {
                let mut wire = Vec::new();
                for label in &labels {
                    wire.push(label.len() as u8);
                    wire.extend_from_slice(label);
                }
                assert!(
                    !hay.windows(wire.len()).any(|w| w == wire.as_slice()),
                    "host DNS capture must not contain DNS-wire QNAME for {qname}"
                );
            }
        }
    }
}

/// UDP sink that records whatever cleartext DNS a peer would have emitted.
struct Port53Sink {
    _stop: Arc<Mutex<bool>>,
}

impl Port53Sink {
    fn start(capture: HostDnsCapture) -> (Self, SocketAddr) {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let addr = udp.local_addr().unwrap();
        let stop = Arc::new(Mutex::new(false));
        let stop_t = stop.clone();
        thread::spawn(move || {
            udp.set_read_timeout(Some(Duration::from_millis(50))).ok();
            let mut buf = [0u8; 2048];
            while !*stop_t.lock().unwrap() {
                match udp.recv_from(&mut buf) {
                    Ok((n, _)) => capture.push(buf[..n].to_vec()),
                    Err(_) => continue,
                }
            }
        });
        (Self { _stop: stop }, addr)
    }
}

impl Drop for Port53Sink {
    fn drop(&mut self) {
        *self._stop.lock().unwrap() = true;
    }
}

struct CountingResolver {
    ip: IpAddr,
    calls: Arc<Mutex<Vec<String>>>,
    /// Optional UDP peer. A correct sealed path never writes DNS frames here.
    forbidden_dns_peer: Option<SocketAddr>,
}

impl NameResolver for CountingResolver {
    fn resolve_host(
        &self,
        host: &str,
        port: u16,
        _deadline: Instant,
    ) -> Result<Vec<SocketAddr>, SealError> {
        self.calls.lock().unwrap().push(host.to_ascii_lowercase());
        // Emulate "no cleartext leakage": do NOT send a DNS frame to the peer.
        // (A buggy implementation might call getaddrinfo / port 53.)
        let _ = self.forbidden_dns_peer;
        Ok(vec![SocketAddr::new(self.ip, port)])
    }

    fn endpoint(&self) -> &ResolverEndpoint {
        &DEFAULT_DOH_ENDPOINT
    }
}

struct FailingResolver;

impl NameResolver for FailingResolver {
    fn resolve_host(
        &self,
        _host: &str,
        _port: u16,
        _deadline: Instant,
    ) -> Result<Vec<SocketAddr>, SealError> {
        Err(SealError::Dns {
            detail: "fixture deny".into(),
        })
    }

    fn endpoint(&self) -> &ResolverEndpoint {
        &DEFAULT_DOH_ENDPOINT
    }
}

/// VAL-CONF-013 residual — SOCKS domain CONNECT resolves via sealed NameResolver
/// and never leaves a cleartext QNAME on the host DNS capture sink.
#[test]
fn sealed_socks_domain_connect_uses_doh_without_cleartext_qname() {
    let capture = HostDnsCapture::default();
    let (sink, peer) = Port53Sink::start(capture.clone());

    // Upstream that echoes a single payload after accept.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_addr = upstream.local_addr().unwrap();
    let up = thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        s.write_all(b"OK:").unwrap();
        s.write_all(&buf[..n]).unwrap();
    });

    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(CountingResolver {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        calls: Arc::clone(&calls),
        forbidden_dns_peer: Some(peer),
    });
    let proxy = SealedSocksProxy::start(resolver).expect("sealed SOCKS must start");

    // Drive SOCKS5 CONNECT with ATYP=domain for the target QNAME. Chromium
    // issues this after host-resolver-rules blocks system DNS.
    let mut client = TcpStream::connect(proxy.addr()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut g = [0u8; 2];
    client.read_exact(&mut g).unwrap();
    assert_eq!(g, [0x05, 0x00]);

    let host = TARGET_QNAME.as_bytes();
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host);
    req.extend_from_slice(&up_addr.port().to_be_bytes());
    client.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS CONNECT via sealed resolver");

    client.write_all(b"browser-dns-isolation").unwrap();
    let mut echo = Vec::new();
    client.read_to_end(&mut echo).unwrap();
    assert!(echo.starts_with(b"OK:browser-dns-isolation"));
    up.join().unwrap();

    let seen = calls.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![TARGET_QNAME.to_string()],
        "sealed SOCKS must resolve the domain target exactly once via NameResolver"
    );
    capture.assert_no_qname(TARGET_QNAME);
    // Marker documents the sealed browser path for host-safe greps.
    assert!(SEALED_BROWSER_DNS_MARKER.contains("browser-socks-doh"));
    drop(sink);
}

/// Fail-closed: sealed preflight surfaces Dns when pin resolution fails, before
/// any Chromium target would be created.
#[test]
fn sealed_document_dns_preflight_fails_closed() {
    let err = preflight_document_dns(
        TARGET_QNAME,
        443,
        Instant::now() + Duration::from_secs(2),
        &FailingResolver,
    )
    .expect_err("preflight must fail closed");
    assert!(matches!(err, SealError::Dns { .. }));
    assert_eq!(err.kind(), "dns");
}

/// Isolation packing forces loopback SOCKS5 as Chromium's proxy server.
#[test]
fn chrome_dns_isolation_proxy_arg_is_loopback_socks5() {
    let proxy = SealedSocksProxy::start(Arc::new(CountingResolver {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        calls: Arc::new(Mutex::new(Vec::new())),
        forbidden_dns_peer: None,
    }))
    .unwrap();
    let proxy_arg = chrome_dns_isolation_proxy_arg(&proxy);
    assert!(
        proxy_arg.starts_with("socks5://127.0.0.1:"),
        "proxy must be loopback SOCKS5: {proxy_arg}"
    );
}

#[test]
fn document_host_needs_sealed_resolve_for_real_hosts_only() {
    assert!(document_host_needs_sealed_resolve("example.com"));
    assert!(document_host_needs_sealed_resolve(TARGET_QNAME));
    assert!(!document_host_needs_sealed_resolve("127.0.0.1"));
    assert!(!document_host_needs_sealed_resolve("localhost"));
    assert!(!document_host_needs_sealed_resolve("LocalHost"));
}
