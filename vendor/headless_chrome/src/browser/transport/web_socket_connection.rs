use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::Result;
use log::{debug, info, trace, warn};
use tungstenite::http::Response;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use url::Url;

use crate::browser::{BrowserOperationTimeout, BrowserSetupTimeout};
use crate::types::{Message, parse_raw_message};

type TungsteniteWebsocketConnection =
    tungstenite::protocol::WebSocket<MaybeTlsStream<DeadlineStream>>;

const READ_TIMEOUT_DURATION: Duration = Duration::from_millis(100);
const HANDSHAKE_TIMEOUT_DURATION: Duration = Duration::from_secs(30);

#[cfg(feature = "rustls-tls-webpki-roots")]
static RUSTLS_INIT: std::sync::Once = std::sync::Once::new();

#[cfg(feature = "rustls-tls-webpki-roots")]
fn init_rustls_provider() {
    RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(feature = "rustls-tls-webpki-roots")]
fn add_root_certificates(
    roots: &mut rustls::RootCertStore,
    root_cert: Option<&[u8]>,
) -> Result<()> {
    use std::io::Cursor;

    let Some(cert_bytes) = root_cert else {
        return Ok(());
    };

    if cert_bytes.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let mut reader = Cursor::new(cert_bytes);

        for cert in rustls_pemfile::certs(&mut reader) {
            roots.add(cert?)?;
        }
    } else {
        roots.add(rustls::pki_types::CertificateDer::from(cert_bytes.to_vec()))?;
    }

    Ok(())
}

fn remaining_until(deadline: Instant, setup_phase: &AtomicBool) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            if setup_phase.load(Ordering::SeqCst) {
                BrowserSetupTimeout.into()
            } else {
                BrowserOperationTimeout.into()
            }
        })
}

/// The part of the transport currently using the socket.
///
/// The WebSocket handshake needs the full remainder for every I/O operation. Once the transport is
/// established, reads retain the driver's short polling cap while writes and flushes remain bounded
/// by the caller's absolute deadline.
#[derive(Clone, Copy)]
enum StreamPhase {
    Handshake,
    Dispatch,
}

/// A TCP stream whose timeout is re-derived immediately before every I/O operation.
///
/// `tungstenite` performs the TLS and HTTP-upgrade handshakes through its generic `Read`/`Write`
/// stream. Wrapping that stream, rather than setting one timeout before entering tungstenite, makes
/// a peer that trickles incomplete handshake bytes consume the caller-owned absolute deadline.
struct DeadlineStream {
    inner: TcpStream,
    deadline: Option<Instant>,
    setup_phase: Arc<AtomicBool>,
    phase: StreamPhase,
}

impl DeadlineStream {
    fn new(
        inner: TcpStream,
        deadline: Option<Instant>,
        setup_phase: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            deadline,
            setup_phase,
            phase: StreamPhase::Handshake,
        }
    }

    fn begin_dispatch(&mut self) {
        self.phase = StreamPhase::Dispatch;
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .map(|deadline| {
                remaining_until(deadline, &self.setup_phase).map_err(|error| {
                    io::Error::new(io::ErrorKind::TimedOut, error.to_string())
                })
            })
            .transpose()
            .map(|remaining| remaining.unwrap_or(HANDSHAKE_TIMEOUT_DURATION))
    }

    fn read_timeout(&self) -> io::Result<Duration> {
        let remaining = self.remaining()?;
        Ok(match self.phase {
            StreamPhase::Handshake => remaining,
            StreamPhase::Dispatch => remaining.min(READ_TIMEOUT_DURATION),
        })
    }

    fn set_read_timeout(&self) -> io::Result<()> {
        self.inner.set_read_timeout(Some(self.read_timeout()?))
    }

    fn set_write_timeout(&self) -> io::Result<()> {
        self.inner.set_write_timeout(Some(self.remaining()?))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.set_read_timeout()?;
        self.inner.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.set_write_timeout()?;
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.set_write_timeout()?;
        self.inner.flush()
    }
}

fn connect_tcp(
    ws_url: &Url,
    deadline: Option<Instant>,
    setup_phase: &AtomicBool,
) -> Result<TcpStream> {
    let host = ws_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing websocket host: {ws_url}"))?;
    let port = ws_url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("missing websocket port: {ws_url}"))?;
    let addresses = (host, port).to_socket_addrs()?;
    let mut last_error = None;
    for address in addresses {
        let timeout = deadline
            .map(|deadline| remaining_until(deadline, setup_phase))
            .transpose()?
            .unwrap_or(HANDSHAKE_TIMEOUT_DURATION);
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no addresses found for websocket host {host}")))
}

pub struct WebSocketConnection {
    connection: Arc<Mutex<TungsteniteWebsocketConnection>>,
    thread: std::thread::JoinHandle<()>,
    process_id: Option<u32>,
}

impl std::fmt::Debug for WebSocketConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "WebSocketConnection {{}}")
    }
}

impl WebSocketConnection {
    pub fn new(
        ws_url: &Url,
        process_id: Option<u32>,
        messages_tx: mpsc::Sender<Message>,
        root_cert: Option<Vec<u8>>,
        deadline: Option<Instant>,
        setup_phase: Arc<AtomicBool>,
    ) -> Result<Self> {
        let (connection, _) =
            Self::websocket_connection_with_root_cert(
                ws_url,
                root_cert.as_deref(),
                deadline,
                Arc::clone(&setup_phase),
            )?;

        let connection = Arc::new(Mutex::new(connection));

        let thread = {
            let sender = connection.clone();

            std::thread::spawn(move || {
                trace!("Starting msg dispatching loop");
                Self::dispatch_incoming_messages(sender, messages_tx, process_id);
                trace!("Quit loop msg dispatching loop");
            })
        };

        Ok(Self {
            connection,
            thread,
            process_id,
        })
    }

    pub fn shutdown(&self) {
        trace!(
            "Shutting down WebSocket connection for Chrome {:?}",
            self.process_id
        );

        if let Ok(mut connection) = self.connection.lock() {
            if let Err(err) = connection.close(None) {
                debug!(
                    "Couldn't shut down WS connection for Chrome {:?}: {}",
                    self.process_id, err
                );
            }

            connection.flush().ok();
        }

        self.thread.thread().unpark();
    }

    fn dispatch_incoming_messages(
        receiver: Arc<Mutex<TungsteniteWebsocketConnection>>,
        messages_tx: mpsc::Sender<Message>,
        process_id: Option<u32>,
    ) {
        loop {
            let message = match receiver.lock() {
                Ok(mut receiver) => receiver.read(),
                Err(err) => {
                    debug!("WS mutex poisoned for Chrome #{process_id:?}: {err}");
                    break;
                }
            };

            match message {
                Err(err) => match err {
                    tungstenite::Error::Io(err) => {
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) {
                            std::thread::park_timeout(READ_TIMEOUT_DURATION);
                        } else {
                            debug!("WS IO Error for Chrome #{process_id:?}: {err}");
                            break;
                        }
                    }
                    tungstenite::Error::ConnectionClosed
                    | tungstenite::Error::AlreadyClosed
                    | tungstenite::Error::Protocol(
                        tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                    ) => break,
                    error => {
                        debug!("Unhandled WebSocket error for Chrome #{process_id:?}: {error:?}");
                        break;
                    }
                },
                Ok(message) => {
                    if let tungstenite::protocol::Message::Text(message_string) = message {
                        if let Ok(message) = parse_raw_message(&message_string) {
                            if messages_tx.send(message).is_err() {
                                break;
                            }
                        } else {
                            trace!(
                                "Incoming message isn't recognised as event or method response: {message_string}",
                            );
                        }
                    } else if let tungstenite::protocol::Message::Close(close_frame) = message {
                        match close_frame {
                            Some(tungstenite::protocol::CloseFrame { code, reason }) => {
                                debug!(
                                    "Received close frame from Chrome #{process_id:?}: {code:?} {reason:?}",
                                );

                                if code != tungstenite::protocol::frame::coding::CloseCode::Normal {
                                    debug!("Abnormal close code {code:?}, shutting down");
                                }
                            }
                            None => {
                                debug!("Received close frame from Chrome #{process_id:?}: None");
                            }
                        }

                        break;
                    } else {
                        debug!("Ignoring unexpected WebSocket message: {message:?}");
                    }
                }
            }
        }

        info!("Sending shutdown message to message handling loop");

        if messages_tx.send(Message::ConnectionShutdown).is_err() {
            warn!("Couldn't send message to transport loop telling it to shut down");
        }
    }

    fn websocket_connection_with_root_cert(
        ws_url: &Url,
        root_cert: Option<&[u8]>,
        deadline: Option<Instant>,
        setup_phase: Arc<AtomicBool>,
    ) -> Result<(
        tungstenite::WebSocket<MaybeTlsStream<DeadlineStream>>,
        Response<Option<Vec<u8>>>,
    )> {
        let config = Some(
            WebSocketConfig::default()
                .accept_unmasked_frames(true)
                .max_message_size(None)
                .max_frame_size(None),
        );

        if root_cert.is_none() {
            let tcp = DeadlineStream::new(
                connect_tcp(ws_url, deadline, &setup_phase)?,
                deadline,
                Arc::clone(&setup_phase),
            );
            let mut client = tungstenite::client::client_with_config(
                ws_url.as_str(),
                MaybeTlsStream::Plain(tcp),
                config,
            )
            .map_err(|error| {
                deadline
                    .map(|deadline| remaining_until(deadline, &setup_phase))
                    .transpose()
                    .err()
                    .unwrap_or_else(|| error.into())
            })?;

            match client.0.get_mut() {
                MaybeTlsStream::Plain(stream) => stream.begin_dispatch(),

                #[allow(unreachable_patterns)]
                _ => {
                    return Err(anyhow::anyhow!("unsupported plain websocket stream type"));
                }
            }

            debug!("Successfully connected to WebSocket: {ws_url}");

            return Ok(client);
        }

        #[cfg(feature = "rustls-tls-webpki-roots")]
        {
            use tungstenite::client::IntoClientRequest;

            init_rustls_provider();

            let tcp = DeadlineStream::new(
                connect_tcp(ws_url, deadline, &setup_phase)?,
                deadline,
                Arc::clone(&setup_phase),
            );

            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            add_root_certificates(&mut roots, root_cert)?;

            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();

            let connector = tungstenite::Connector::Rustls(Arc::new(tls_config));
            let request = ws_url.as_str().into_client_request()?;

            let mut client =
                tungstenite::client_tls_with_config(request, tcp, config, Some(connector)).map_err(
                    |error| {
                        deadline
                            .map(|deadline| remaining_until(deadline, &setup_phase))
                            .transpose()
                            .err()
                            .unwrap_or_else(|| error.into())
                    },
                )?;

            match client.0.get_mut() {
                MaybeTlsStream::Plain(stream) => stream.begin_dispatch(),

                #[cfg(any(
                    feature = "rustls-tls-native-roots",
                    feature = "rustls-tls-webpki-roots"
                ))]
                MaybeTlsStream::Rustls(stream) => stream.sock.begin_dispatch(),

                #[cfg(feature = "native-tls")]
                MaybeTlsStream::NativeTls(stream) => stream.get_mut().begin_dispatch(),

                #[allow(unreachable_patterns)]
                _ => {
                    return Err(anyhow::anyhow!("unsupported websocket stream type"));
                }
            }

            debug!("Successfully connected to WebSocket with custom root cert: {ws_url}");

            Ok(client)
        }

        #[cfg(not(feature = "rustls-tls-webpki-roots"))]
        {
            Err(anyhow::anyhow!(
                "root_cert was provided, but feature rustls-tls-webpki-roots is not enabled"
            ))
        }
    }

    pub fn send_message(&self, message_text: &str) -> Result<()> {
        let message = tungstenite::protocol::Message::text(message_text);

        let mut sender = self
            .connection
            .lock()
            .map_err(|err| anyhow::anyhow!("WS mutex poisoned: {err}"))?;

        sender.send(message)?;
        self.thread.thread().unpark();

        Ok(())
    }
}

impl Drop for WebSocketConnection {
    fn drop(&mut self) {
        info!("dropping websocket connection");
    }
}
