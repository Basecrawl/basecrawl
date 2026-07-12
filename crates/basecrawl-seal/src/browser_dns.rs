//! Sealed browser DNS isolation for headless Chromium.
//!
//! VAL-CONF-013 residual (default scrapes with render/screenshot): Chromium must
//! never consult the host stub resolver for scrape-target hostnames. The sealed
//! path is:
//!
//! 1. An in-process SOCKS5 CONNECT proxy on loopback that resolves domain names
//!    exclusively through [`crate::dns::NameResolver`] (production pin =
//!    [`crate::dns::PinnedResolver::doh`]) and then dials by IP only.
//! 2. Chromium launched with `--proxy-server=socks5://127.0.0.1:<port>`. SOCKS5
//!    domain (ATYP=0x03) CONNECT carries the hostname; our proxy resolves it
//!    exclusively via sealed DoH and dials by IP. With a SOCKS proxy, Chromium
//!    performs remote DNS through the proxy rather than system port 53 for
//!    navigated origins.
//!
//! Fail-closed: if the sealed proxy cannot be established, callers receive
//! [`SealError::Dns`] and render must abort before any Chromium target is
//! created.
//!
//! Note: we intentionally do **not** pass a blanket
//! `--host-resolver-rules=MAP * ~NOTFOUND` rule. That pattern is site-local and
//! historically used with a PAC to force remote DNS, but it also breaks any
//! ambient name the browser boot needs and can deadlock headless launch under
//! CDP. The sealed SOCKS domain path is the enforceable isolation surface.

use crate::dns::{is_loopback_name, resolve_for_connect, NameResolver, PinnedResolver};
use crate::error::SealError;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// Privacy path marker for telemetry / log greps (never embeds QNAMEs).
pub const SEALED_BROWSER_DNS_MARKER: &str = "basecrawl-seal/browser-socks-doh-v1";

/// Handle to a running sealed SOCKS5 proxy.
///
/// Dropping the handle signals the acceptor to stop. Existing tunnels finish
/// independently. A process-global proxy is also available via
/// [`global_sealed_socks_proxy`].
#[derive(Debug)]
pub struct SealedSocksProxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl SealedSocksProxy {
    /// Loopback socket Chromium must be pointed at (`socks5://addr`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `--proxy-server` value for headless Chromium.
    pub fn proxy_server_arg(&self) -> String {
        format!("socks5://{}", self.addr)
    }

    /// Start a sealed SOCKS5 CONNECT proxy that resolves hostnames with `resolver`.
    pub fn start(resolver: Arc<dyn NameResolver>) -> Result<Self, SealError> {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|e| SealError::Dns {
                detail: format!("sealed SOCKS bind failed: {e}"),
            })?;
        listener.set_nonblocking(true).map_err(|e| SealError::Dns {
            detail: format!("sealed SOCKS set_nonblocking failed: {e}"),
        })?;
        let addr = listener.local_addr().map_err(|e| SealError::Dns {
            detail: format!("sealed SOCKS local_addr failed: {e}"),
        })?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);
        thread::Builder::new()
            .name("basecrawl-sealed-socks".into())
            .spawn(move || accept_loop(listener, resolver, stop_t))
            .map_err(|e| SealError::Dns {
                detail: format!("sealed SOCKS acceptor spawn failed: {e}"),
            })?;
        // Brief readiness: the acceptor is non-blocking; binding already proves listen.
        Ok(Self { addr, stop })
    }

    /// Start pinned to the production DoH resolver.
    pub fn start_doh() -> Result<Self, SealError> {
        Self::start(Arc::new(PinnedResolver::doh()))
    }
}

impl Drop for SealedSocksProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Process-global sealed SOCKS proxy used by default Chromium launches.
///
/// Fail-closed: the first start error is retained so later render attempts do
/// not silently reintroduce system DNS.
pub fn global_sealed_socks_proxy() -> Result<&'static SealedSocksProxy, SealError> {
    static PROXY: OnceLock<Result<SealedSocksProxy, String>> = OnceLock::new();
    match PROXY.get_or_init(|| SealedSocksProxy::start_doh().map_err(|e| e.to_string())) {
        Ok(proxy) => Ok(proxy),
        Err(detail) => Err(SealError::Dns {
            detail: format!("sealed browser SOCKS unavailable: {detail}"),
        }),
    }
}

/// Chrome `--proxy-server` value that forces origin dials through sealed SOCKS/DoH.
pub fn chrome_dns_isolation_proxy_arg(proxy: &SealedSocksProxy) -> String {
    proxy.proxy_server_arg()
}

/// Resolve the document host through the sealed pin **before** Chromium target creation.
///
/// IP literals and `localhost` short-circuit (no DoH). Any other hostname must
/// succeed on the pin or the render path fails closed with [`SealError::Dns`].
pub fn preflight_document_dns(
    host: &str,
    port: u16,
    deadline: Instant,
    resolver: &dyn NameResolver,
) -> Result<SocketAddr, SealError> {
    resolve_for_connect(host, port, resolver, deadline)
}

fn accept_loop(listener: TcpListener, resolver: Arc<dyn NameResolver>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let resolver = Arc::clone(&resolver);
                let _ = thread::Builder::new()
                    .name("basecrawl-sealed-socks-conn".into())
                    .spawn(move || {
                        let _ = handle_client(stream, resolver.as_ref());
                    });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

fn handle_client(mut client: TcpStream, resolver: &dyn NameResolver) -> Result<(), ()> {
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ())?;
    client
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ())?;

    // Greeting: VER, NMETHODS, METHODS...
    let mut header = [0u8; 2];
    client.read_exact(&mut header).map_err(|_| ())?;
    if header[0] != 0x05 {
        return Err(());
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        client.read_exact(&mut methods).map_err(|_| ())?;
    }
    // no-auth only
    client.write_all(&[0x05, 0x00]).map_err(|_| ())?;
    client.flush().map_err(|_| ())?;

    // Request: VER CMD RSV ATYP ...
    let mut req_hdr = [0u8; 4];
    client.read_exact(&mut req_hdr).map_err(|_| ())?;
    if req_hdr[0] != 0x05 || req_hdr[1] != 0x01 {
        // Only CONNECT
        let _ = write_socks_reply(&mut client, 0x07, SocketAddr::from(([0, 0, 0, 0], 0)));
        return Err(());
    }
    let target = match req_hdr[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).map_err(|_| ())?;
            let mut port_b = [0u8; 2];
            client.read_exact(&mut port_b).map_err(|_| ())?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port_b))
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).map_err(|_| ())?;
            let mut host = vec![0u8; len[0] as usize];
            client.read_exact(&mut host).map_err(|_| ())?;
            let mut port_b = [0u8; 2];
            client.read_exact(&mut port_b).map_err(|_| ())?;
            let port = u16::from_be_bytes(port_b);
            let host = String::from_utf8(host).map_err(|_| ())?;
            let deadline = Instant::now() + Duration::from_secs(15);
            match resolve_for_connect(&host, port, resolver, deadline) {
                Ok(addr) => addr,
                Err(_) => {
                    let _ =
                        write_socks_reply(&mut client, 0x04, SocketAddr::from(([0, 0, 0, 0], 0)));
                    return Err(());
                }
            }
        }
        0x04 => {
            let mut ip = [0u8; 16];
            client.read_exact(&mut ip).map_err(|_| ())?;
            let mut port_b = [0u8; 2];
            client.read_exact(&mut port_b).map_err(|_| ())?;
            SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes(port_b),
            )
        }
        _ => {
            let _ = write_socks_reply(&mut client, 0x08, SocketAddr::from(([0, 0, 0, 0], 0)));
            return Err(());
        }
    };

    let upstream = match TcpStream::connect_timeout(&target, Duration::from_secs(15)) {
        Ok(stream) => stream,
        Err(_) => {
            let _ = write_socks_reply(&mut client, 0x05, SocketAddr::from(([0, 0, 0, 0], 0)));
            return Err(());
        }
    };
    upstream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();
    upstream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .ok();

    let bind = upstream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    write_socks_reply(&mut client, 0x00, bind).map_err(|_| ())?;

    // Bidirectional pipe.
    let mut client_read = client.try_clone().map_err(|_| ())?;
    let mut upstream_read = upstream.try_clone().map_err(|_| ())?;
    let mut client_write = client;
    let mut upstream_write = upstream;

    let c2u = thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match client_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if upstream_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = upstream_write.shutdown(Shutdown::Both);
        let _ = client_read.shutdown(Shutdown::Both);
    });
    let u2c = thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match upstream_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client_write.shutdown(Shutdown::Both);
        let _ = upstream_read.shutdown(Shutdown::Both);
    });
    let _ = c2u.join();
    let _ = u2c.join();
    Ok(())
}

fn write_socks_reply(stream: &mut TcpStream, rep: u8, bind: SocketAddr) -> std::io::Result<()> {
    match bind {
        SocketAddr::V4(v4) => {
            let mut out = [0u8; 10];
            out[0] = 0x05;
            out[1] = rep;
            out[2] = 0x00;
            out[3] = 0x01;
            out[4..8].copy_from_slice(&v4.ip().octets());
            out[8..10].copy_from_slice(&v4.port().to_be_bytes());
            stream.write_all(&out)?;
        }
        SocketAddr::V6(v6) => {
            let mut out = [0u8; 22];
            out[0] = 0x05;
            out[1] = rep;
            out[2] = 0x00;
            out[3] = 0x04;
            out[4..20].copy_from_slice(&v6.ip().octets());
            out[20..22].copy_from_slice(&v6.port().to_be_bytes());
            stream.write_all(&out)?;
        }
    }
    stream.flush()
}

/// Whether a document URL host is safe to hand to Chromium without a sealed resolve.
pub fn document_host_needs_sealed_resolve(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    !is_loopback_name(host)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::dns::{ResolverEndpoint, DEFAULT_DOH_ENDPOINT};
    use std::net::Ipv4Addr;

    struct FixedResolver {
        ip: IpAddr,
    }

    impl NameResolver for FixedResolver {
        fn resolve_host(
            &self,
            host: &str,
            port: u16,
            _deadline: Instant,
        ) -> Result<Vec<SocketAddr>, SealError> {
            assert!(
                !host.eq_ignore_ascii_case("localhost"),
                "localhost must not hit the name resolver"
            );
            Ok(vec![SocketAddr::new(self.ip, port)])
        }

        fn endpoint(&self) -> &ResolverEndpoint {
            &DEFAULT_DOH_ENDPOINT
        }
    }

    #[test]
    fn proxy_server_arg_is_loopback_socks5() {
        let proxy = SealedSocksProxy::start(Arc::new(FixedResolver {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }))
        .unwrap();
        let arg = chrome_dns_isolation_proxy_arg(&proxy);
        assert!(arg.starts_with("socks5://127.0.0.1:"));
    }

    #[test]
    fn preflight_short_circuits_ip_literal() {
        let resolver = FixedResolver {
            ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        };
        let addr = preflight_document_dns(
            "203.0.113.10",
            443,
            Instant::now() + Duration::from_secs(1),
            &resolver,
        )
        .unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
    }

    #[test]
    fn socks_connects_domain_via_sealed_resolver() {
        // Upstream echo server on loopback.
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let up_thread = thread::spawn(move || {
            let (mut s, _) = upstream.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap();
            s.write_all(&buf[..n]).unwrap();
        });

        let proxy = SealedSocksProxy::start(Arc::new(FixedResolver {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }))
        .expect("start socks");

        let mut client = TcpStream::connect(proxy.addr()).unwrap();
        // greeting
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        // CONNECT confid-target.basecrawl.test:up_port (domain ATYP)
        let host = b"confid-target.basecrawl.test";
        let mut req = Vec::new();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
        req.extend_from_slice(host);
        req.extend_from_slice(&up_addr.port().to_be_bytes());
        client.write_all(&req).unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[0], 0x05);
        assert_eq!(
            reply[1], 0x00,
            "SOCKS connect must succeed via sealed resolver"
        );

        client.write_all(b"ping-via-socks").unwrap();
        let mut echo = [0u8; 64];
        let n = client.read(&mut echo).unwrap();
        assert_eq!(&echo[..n], b"ping-via-socks");
        up_thread.join().unwrap();
    }
}
