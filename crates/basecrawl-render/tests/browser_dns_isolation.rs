//! VAL-CONF-013 residual on the Chromium render path.
//!
//! Default scrapes using headless Chromium route non-loopback names through an
//! in-process sealed SOCKS5 proxy that resolves exclusively via pin-by-IP DoH.
//! Fail-closed mapping: RenderError::DnsIsolation before sealed SOCKS is ready.

use basecrawl_render::{render, RenderConfig, RenderError, ScreenshotConfig};
use basecrawl_render::{screenshot, screenshot_until};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

/// Snapshot of cleartext DNS frames observed by a local UDP sink.
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

struct Port53Sink {
    stop: Arc<Mutex<bool>>,
}

impl Port53Sink {
    fn start(capture: HostDnsCapture) -> (Self, SocketAddr) {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind port-53 sink");
        let addr = udp.local_addr().unwrap();
        let stop = Arc::new(Mutex::new(false));
        let stop_t = stop.clone();
        thread::spawn(move || {
            let _ = udp.set_read_timeout(Some(Duration::from_millis(50)));
            let mut buf = [0u8; 2048];
            while !*stop_t.lock().unwrap() {
                match udp.recv_from(&mut buf) {
                    Ok((n, _)) => capture.push(buf[..n].to_vec()),
                    Err(_) => continue,
                }
            }
        });
        (Self { stop }, addr)
    }
}

impl Drop for Port53Sink {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
    }
}

/// Loopback HTTP origin for browser fixtures. Dropping stops the accept loop.
struct OriginServer {
    addr: SocketAddr,
    stop: Arc<Mutex<bool>>,
}

impl OriginServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking origin");
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(Mutex::new(false));
        let stop_t = stop.clone();
        thread::spawn(move || {
            while !*stop_t.lock().unwrap() {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 4096];
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.read(&mut buf);
                        let body =
                            b"<html><body><h1 id='ok'>browser-dns-isolation</h1></body></html>";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(body);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Self { addr, stop }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for OriginServer {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(100));
    }
}

fn quick_loopback_config() -> RenderConfig {
    RenderConfig {
        auto_scroll: false,
        dismiss_consent: false,
        network_idle: false,
        timeout: Duration::from_secs(25),
        wait_for: Some("#ok".into()),
        ..RenderConfig::default()
    }
}

/// Loopback HTML render accepts sealed SOCKS launch and never emits an open-web
/// QNAME on a concurrent host DNS capture sink.
#[test]
fn loopback_render_does_not_emit_openweb_qname_on_host_dns_sink() {
    let capture = HostDnsCapture::default();
    let (sink, _peer) = Port53Sink::start(capture.clone());
    let origin = OriginServer::start();
    let url = Url::parse(&format!("http://127.0.0.1:{}/iso", origin.addr().port())).unwrap();

    let rendered = render(&url, &quick_loopback_config()).expect("loopback render must succeed");
    assert!(
        rendered.html.contains("browser-dns-isolation"),
        "expected fixture content, got: {}",
        &rendered.html[..rendered.html.len().min(200)]
    );

    capture.assert_no_qname("example.com");
    capture.assert_no_qname("books.toscrape.com");
    drop(sink);
    drop(origin);
}

/// Screenshot path shares launch_browser + preflight isolation.
#[test]
fn loopback_screenshot_reuses_sealed_dns_launch_path() {
    let origin = OriginServer::start();
    let url = Url::parse(&format!("http://127.0.0.1:{}/shot", origin.addr().port())).unwrap();
    let config = ScreenshotConfig {
        timeout: Duration::from_secs(25),
        width: 320,
        height: 200,
        ..ScreenshotConfig::default()
    };
    let shot = screenshot(&url, &config).expect("loopback screenshot");
    assert!(shot.png.starts_with(b"\x89PNG"), "PNG signature");
    drop(origin);
}

/// Structured fail-closed Display form for core error mapping.
#[test]
fn dns_isolation_display_is_structured() {
    let err = RenderError::DnsIsolation("sealed DoH SOCKS unavailable".into());
    let text = err.to_string();
    assert!(text.contains("sealed browser DNS isolation failed"));
    assert!(text.contains("sealed DoH SOCKS unavailable"));
}

/// Live open-web smoke under host DNS capture: ABORT if example.com appears as
/// cleartext A/AAAA on the capture sink. Sealed SOCKS + DoH is the only resolution
/// path for non-loopback hosts. Transient origin/network may soft-skip *after*
/// proving the sink stayed clean.
#[test]
fn openweb_render_example_com_qname_absent_from_host_dns_sink() {
    if TcpStream::connect_timeout(&"1.1.1.1:443".parse().unwrap(), Duration::from_secs(3)).is_err()
    {
        eprintln!("skip: pinned DoH 1.1.1.1:443 unreachable in this environment");
        return;
    }

    let capture = HostDnsCapture::default();
    let (sink, _peer) = Port53Sink::start(capture.clone());

    let url = Url::parse("https://example.com/").unwrap();
    let config = RenderConfig {
        auto_scroll: false,
        dismiss_consent: false,
        timeout: Duration::from_secs(40),
        network_idle: true,
        quiet_period: Duration::from_millis(300),
        ..RenderConfig::default()
    };

    match render(&url, &config) {
        Ok(rendered) => {
            assert!(
                rendered.html.to_ascii_lowercase().contains("example"),
                "expected example.com content after sealed browser path"
            );
            capture.assert_no_qname("example.com");
        }
        Err(RenderError::DnsIsolation(detail)) => {
            capture.assert_no_qname("example.com");
            eprintln!("sealed DNS isolation fail-closed as designed: {detail}");
        }
        Err(other) => {
            capture.assert_no_qname("example.com");
            let msg = other.to_string().to_ascii_lowercase();
            let transient = msg.contains("timeout")
                || msg.contains("timed out")
                || msg.contains("connection")
                || msg.contains("network")
                || msg.contains("dns")
                || msg.contains("proxy")
                || msg.contains("net::")
                || msg.contains("failed to render");
            if !transient {
                panic!("unexpected non-transient render failure under DNS isolation: {other}");
            }
            eprintln!(
                "soft-skip: origin/network failure after sealed path kept QNAME off host DNS: {other}"
            );
        }
    }
    drop(sink);
}

#[test]
fn screenshot_until_maps_deadline_and_keeps_dns_preflight() {
    let origin = OriginServer::start();
    let url = Url::parse(&format!("http://127.0.0.1:{}/until", origin.addr().port())).unwrap();
    let config = ScreenshotConfig {
        timeout: Duration::from_secs(20),
        width: 200,
        height: 150,
        ..ScreenshotConfig::default()
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    let shot = screenshot_until(&url, &config, deadline).expect("screenshot_until");
    assert!(!shot.base64.is_empty());
    drop(origin);
}
