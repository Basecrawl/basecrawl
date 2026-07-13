//! In-enclave key-release client + AEAD sealed-task decrypt (VAL-CONF-011, VAL-CONF-027).
//!
//! Fixtures are built in-process with the same libsodium sealed-box wire format used by
//! `relay.seal.tasks.seal_task` and `relay.keyrelease.server.seal_task_key_to_session`
//! (aad || 0x00 || payload inside a sealed box to the enclave/session X25519 pubkey).
//! Pure-Rust fixture generation keeps this suite hermetic in GHA (no monorepo Python
//! relay checkout / venv) and independent of CI env such as `BASECRAWL_HTTPBIN_BASE`.

use basecrawl_seal::{
    build_aad, decrypt_requires_released_key, decrypt_sealed_task, decrypt_with_foreign_key,
    decrypt_without_released_key, key_release_report_data, parse_release_response,
    to_report_data_field, EnclaveIdentity, KeyReleaseClient, KeyReleaseTransport, QuoteBundle,
    QuoteProvider, ReleasedTaskKey, SealError, SealedTaskEnvelope, KEY_RELEASE_TAG,
    RA_TLS_PEER_HEADER, TASK_SEAL_SUITE,
};
use crypto_box::aead::OsRng;
use crypto_box::PublicKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const PLAINTEXT_URL: &str = "https://example.com/private/path?token=known-url-marker";
const HEADER_MARKER: &str = "known-header-marker";
const BODY_MARKER: &str = "known-body-marker";
const TASK_KEY_SENTINEL: &str = "SENTINEL-KEY-RELEASE-RAW-BYTES!!";

/// Seal a scrape task to the enclave public key (relay.seal.tasks.seal_task wire).
fn fixture_sealed_task(identity: &EnclaveIdentity) -> (SealedTaskEnvelope, Value) {
    let task = json!({
        "task_id": "task-val-conf-011",
        "url": PLAINTEXT_URL,
        "method": "POST",
        "headers": {"X-Secret": HEADER_MARKER, "Cookie": format!("cookie-{HEADER_MARKER}")},
        "body": BODY_MARKER,
        "formats": ["markdown"],
        "required_zone": "any",
        "nonce": "nonce-val-conf-011",
        "deadline": "2099-01-01T00:00:00+00:00",
        "difficulty": "easy",
        "is_canary": false,
    });
    let task_id = task["task_id"].as_str().unwrap();
    let nonce = task["nonce"].as_str().unwrap();
    let aad = build_aad(task_id, nonce, identity.key_id()).expect("fixture aad");
    let body = serde_json::to_vec(&task).expect("task json");
    let mut authenticated = Vec::with_capacity(aad.len() + 1 + body.len());
    authenticated.extend_from_slice(&aad);
    authenticated.push(0);
    authenticated.extend_from_slice(&body);

    let public = PublicKey::from(*identity.public_key_bytes());
    let ciphertext = public
        .seal(&mut OsRng, &authenticated)
        .expect("fixture sealed-task seal");

    let envelope = SealedTaskEnvelope {
        version: 1,
        suite: TASK_SEAL_SUITE.to_string(),
        recipient_key_id: identity.key_id().to_string(),
        enc: None,
        ciphertext: encode_b64url_for_test(&ciphertext),
    };
    assert_eq!(envelope.suite, TASK_SEAL_SUITE);
    assert_eq!(envelope.recipient_key_id, identity.key_id());
    // Host-visible envelope has no plaintext markers (VAL-CONF-001 style check).
    let host_bytes = serde_json::to_vec(&envelope).unwrap();
    assert!(
        !host_bytes
            .windows(PLAINTEXT_URL.len())
            .any(|w| w == PLAINTEXT_URL.as_bytes()),
        "sealed envelope must not contain the task URL"
    );
    assert!(!String::from_utf8_lossy(&host_bytes).contains(HEADER_MARKER));
    assert!(!String::from_utf8_lossy(&host_bytes).contains(BODY_MARKER));
    (envelope, task)
}

/// Seal a raw task key to the enclave session public key (key-release `/release` wire).
fn fixture_session_sealed_key(identity: &EnclaveIdentity) -> (String, Vec<u8>) {
    let task_key = TASK_KEY_SENTINEL.as_bytes().to_vec();
    assert_eq!(task_key.len(), 32);
    let public = PublicKey::from(*identity.public_key_bytes());
    let sealed = public
        .seal(&mut OsRng, &task_key)
        .expect("fixture session seal");
    let key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sealed);
    (key_b64, task_key)
}

// ---------------------------------------------------------------------------
// Mock transport for the key-release client (no real network; hermetic mocks).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockTransport {
    inner: Arc<Mutex<MockState>>,
}

struct MockState {
    nonce: String,
    release_responses: HashMap<String, Value>,
    default_release: Value,
    calls: Vec<String>,
}

impl MockTransport {
    fn new(nonce: &str, default_release: Value) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockState {
                nonce: nonce.to_string(),
                release_responses: HashMap::new(),
                default_release,
                calls: Vec::new(),
            })),
        }
    }

    fn with_deny(reason: &str) -> Self {
        Self::new("nonce-mock", json!({"released": false, "reason": reason}))
    }
}

impl KeyReleaseTransport for MockTransport {
    fn request_json(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<(u16, Value), SealError> {
        let mut state = self.inner.lock().unwrap();
        state.calls.push(format!("{method} {path}"));
        if path == "/nonce" {
            return Ok((200, json!({"nonce": state.nonce})));
        }
        if path == "/release" {
            // Require the peer header (RA-TLS binding).
            let peer = headers
                .iter()
                .find(|(k, _)| *k == RA_TLS_PEER_HEADER)
                .map(|(_, v)| v.as_str());
            if peer.is_none() {
                return Ok((200, json!({"released": false, "reason": "ra_tls_required"})));
            }
            if let Some(body) = body {
                if let Some(nonce) = body.get("nonce").and_then(|v| v.as_str()) {
                    if let Some(resp) = state.release_responses.get(nonce) {
                        return Ok((200, resp.clone()));
                    }
                }
            }
            return Ok((200, state.default_release.clone()));
        }
        Err(SealError::KeyReleaseProtocol {
            detail: format!("unexpected path {path}"),
        })
    }
}

struct StaticQuote {
    quote_hex: String,
}

impl QuoteProvider for StaticQuote {
    fn get_quote(&self, _report_data_hex: &str) -> Result<QuoteBundle, SealError> {
        Ok(QuoteBundle {
            quote_hex: self.quote_hex.clone(),
            event_log: Some(json!([])),
            vm_config: None,
        })
    }
}

// ---------------------------------------------------------------------------
// VAL-CONF-011: without the key, sealed task stays opaque
// ---------------------------------------------------------------------------

#[test]
fn val_conf_011_host_without_key_cannot_decrypt_sealed_task() {
    let identity = EnclaveIdentity::generate();
    let (envelope, task) = fixture_sealed_task(&identity);

    // Happy control: genuine enclave identity decrypts.
    let recovered = decrypt_sealed_task(&envelope, &identity).expect("enclave opens sealed task");
    assert_eq!(recovered.task, task);
    assert_eq!(recovered.task["url"], PLAINTEXT_URL);
    assert_eq!(recovered.task["body"], BODY_MARKER);
    assert_eq!(recovered.task["headers"]["X-Secret"], HEADER_MARKER);

    // VAL-CONF-011: host / no-key path.
    let err = decrypt_without_released_key(&envelope).expect_err("host has no key");
    assert_eq!(err, SealError::KeyNotReleased);
    assert!(err.is_auth_failure());
    assert_eq!(err.kind(), "key_not_released");
    // Error Display/kind must not contain any task plaintext markers.
    let rendered = format!("{err}");
    assert!(!rendered.contains(PLAINTEXT_URL));
    assert!(!rendered.contains(HEADER_MARKER));
    assert!(!rendered.contains(BODY_MARKER));
}

#[test]
fn val_conf_011_foreign_enclave_identity_cannot_decrypt() {
    let genuine = EnclaveIdentity::generate();
    let forked = EnclaveIdentity::generate();
    let (envelope, _) = fixture_sealed_task(&genuine);

    let err = decrypt_with_foreign_key(&envelope, &forked).expect_err("forked image denied");
    assert!(
        matches!(
            err,
            SealError::AuthenticationFailed | SealError::InvalidEnvelope { .. }
        ),
        "expected auth failure, got {err:?}"
    );
    let rendered = format!("{err}");
    assert!(!rendered.contains("known-url-marker"));
    assert!(!rendered.contains(BODY_MARKER));
}

#[test]
fn val_conf_011_key_release_deny_paths_yield_no_usable_key() {
    // Model every production deny reason the measurement gate emits. On each
    // deny the client returns KeyReleaseDenied *and* decrypt_requires_released_key
    // refuses to proceed, so the sealed task stays opaque.
    let deny_reasons = [
        "measurement_not_allowlisted",
        "unknown_nonce",
        "stale_nonce",
        "consumed_nonce",
        "ra_tls_peer_mismatch",
        "ra_tls_required",
        "tcb_unacceptable",
        "report_data_mismatch",
        "invalid_quote",
        "event_log_required",
    ];

    for reason in deny_reasons {
        let identity = EnclaveIdentity::generate();
        let transport = MockTransport::with_deny(reason);
        let client = KeyReleaseClient::new(
            transport,
            StaticQuote {
                quote_hex: "00".repeat(64),
            },
            identity,
        );
        let err = client.obtain_task_key().expect_err("deny path");
        match err {
            SealError::KeyReleaseDenied { reason: r } => assert_eq!(r, reason),
            other => panic!("expected KeyReleaseDenied({reason}), got {other:?}"),
        }
        // No key held → decrypt gate fails closed.
        assert!(matches!(
            decrypt_requires_released_key(None),
            Err(SealError::KeyNotReleased)
        ));
    }
}

#[test]
fn val_conf_011_session_sealed_key_from_other_session_is_useless() {
    let session_a = EnclaveIdentity::generate();
    let session_b = EnclaveIdentity::generate();
    let (key_b64, _raw) = fixture_session_sealed_key(&session_a);

    // Success body as the key-release server would emit for session A.
    let response = json!({"released": true, "key": key_b64});

    // Session A opens successfully (control).
    let key = parse_release_response(&response, &session_a).expect("session A opens");
    assert_eq!(key.as_bytes(), TASK_KEY_SENTINEL.as_bytes());

    // Session B cannot open a response sealed to A (VAL-CONF-030 complement /
    // host-captured response is useless).
    let err = parse_release_response(&response, &session_b).expect_err("session B denied");
    assert_eq!(err, SealError::AuthenticationFailed);
}

// ---------------------------------------------------------------------------
// VAL-CONF-027: tampered / truncated ciphertext fails AEAD with zero partial PT
// ---------------------------------------------------------------------------

#[test]
fn val_conf_027_bitflip_fails_authenticated_decryption_no_partial_plaintext() {
    let identity = EnclaveIdentity::generate();
    let (mut envelope, _) = fixture_sealed_task(&identity);

    // Decode, flip one ciphertext byte, re-encode (base64url, no pad).
    let mut raw = decode_b64url_for_test(&envelope.ciphertext);
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    envelope.ciphertext = encode_b64url_for_test(&raw);

    let err = decrypt_sealed_task(&envelope, &identity).expect_err("bitflip must fail AEAD");
    assert_eq!(
        err,
        SealError::AuthenticationFailed,
        "tamper must fail closed at the AEAD boundary, not later"
    );
    // Nothing about the URL, headers, or body may leak through the error path.
    let rendered = format!("{err:?}{err}");
    assert!(!rendered.contains("known-url-marker"));
    assert!(!rendered.contains(HEADER_MARKER));
    assert!(!rendered.contains(BODY_MARKER));
    assert!(!rendered.contains("example.com"));
}

#[test]
fn val_conf_027_truncate_fails_authenticated_decryption_no_partial_plaintext() {
    let identity = EnclaveIdentity::generate();
    let (mut envelope, _) = fixture_sealed_task(&identity);

    let mut raw = decode_b64url_for_test(&envelope.ciphertext);
    raw.pop(); // truncate one byte of the sealed box
    envelope.ciphertext = encode_b64url_for_test(&raw);

    let err = decrypt_sealed_task(&envelope, &identity).expect_err("truncate must fail AEAD");
    assert!(
        matches!(
            err,
            SealError::AuthenticationFailed | SealError::InvalidEnvelope { .. }
        ),
        "unexpected err {err:?}"
    );
    let rendered = format!("{err:?}");
    assert!(!rendered.contains("known-url-marker"));
    assert!(!rendered.contains(BODY_MARKER));
}

#[test]
fn val_conf_027_empty_and_short_ciphertext_rejected() {
    let identity = EnclaveIdentity::generate();
    let (mut envelope, _) = fixture_sealed_task(&identity);

    envelope.ciphertext.clear();
    let err = decrypt_sealed_task(&envelope, &identity).expect_err("empty");
    assert!(matches!(
        err,
        SealError::InvalidEnvelope { .. } | SealError::AuthenticationFailed
    ));

    // 32-byte-only (just an ephemeral, no MAC/body) is truncated.
    envelope.ciphertext = encode_b64url_for_test(&[0u8; 40]);
    let err = decrypt_sealed_task(&envelope, &identity).expect_err("short");
    assert!(
        matches!(
            err,
            SealError::AuthenticationFailed | SealError::InvalidEnvelope { .. }
        ),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Happy path: genuine identity + session-released key + AEAD decrypt
// ---------------------------------------------------------------------------

#[test]
fn happy_path_release_response_opens_and_task_decrypts() {
    let identity = EnclaveIdentity::generate();
    let (envelope, task) = fixture_sealed_task(&identity);
    let (key_b64, raw_key) = fixture_session_sealed_key(&identity);

    // Client parses a success response, unsealing the session-bound key.
    let response = json!({"released": true, "key": key_b64});
    let released = parse_release_response(&response, &identity).expect("open key");
    assert_eq!(released.as_bytes(), raw_key.as_slice());
    assert_eq!(released.as_bytes(), TASK_KEY_SENTINEL.as_bytes());
    // Debug print of the key type never dumps key bytes.
    let dbg = format!("{released:?}");
    assert!(!dbg.contains(TASK_KEY_SENTINEL));
    assert!(!dbg.contains(&hex_encode_local(released.as_bytes())));

    decrypt_requires_released_key(Some(&released)).expect("key present");

    // Released key presence gates the scrape; the sealed task itself is still
    // opened by the enclave identity (SealedBox to enclave pubkey). Both are
    // enclave-held only.
    let recovered = decrypt_sealed_task(&envelope, &identity).expect("decrypt");
    assert_eq!(recovered.task, task);
    assert_eq!(recovered.task_id, "task-val-conf-011");
    assert_eq!(recovered.nonce, "nonce-val-conf-011");
}

#[test]
fn happy_path_client_round_trip_against_mock_allow_service() {
    let identity = EnclaveIdentity::generate();
    let (key_b64, raw_key) = fixture_session_sealed_key(&identity);
    let success = json!({"released": true, "key": key_b64});

    let transport = MockTransport::new("nonce-happy", success);
    // Report_data binding concords with the tag used by the relay.
    let binding = key_release_report_data("nonce-happy", identity.public_key_bytes());
    let field = to_report_data_field(&binding);
    assert_eq!(field.len(), 128); // 64 bytes hex
    assert!(field.ends_with(&"00".repeat(32)));
    assert_eq!(KEY_RELEASE_TAG, b"basecrawl-keyrelease-v1");

    let client = KeyReleaseClient::new(
        transport.clone(),
        StaticQuote {
            quote_hex: "aa".repeat(32),
        },
        identity,
    );
    let key = client.obtain_task_key().expect("happy release");
    assert_eq!(key.as_bytes(), raw_key.as_slice());

    let calls = transport.inner.lock().unwrap().calls.clone();
    assert!(calls.iter().any(|c| c.contains("/nonce")));
    assert!(calls.iter().any(|c| c.contains("/release")));
}

#[test]
fn deny_response_with_spurious_key_field_is_rejected() {
    let identity = EnclaveIdentity::generate();
    let response = json!({
        "released": false,
        "reason": "measurement_not_allowlisted",
        "key": "YQ==",
    });
    let err = parse_release_response(&response, &identity).expect_err("spurious key");
    assert!(matches!(err, SealError::KeyReleaseProtocol { .. }));
}

#[test]
fn released_task_key_is_zeroizing_and_never_displays_bytes() {
    let key = ReleasedTaskKey::from_bytes(TASK_KEY_SENTINEL.as_bytes().to_vec()).unwrap();
    let rendered = format!("{key:?}");
    assert!(!rendered.contains("SENTINEL"));
    assert!(rendered.contains("len"));
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn decode_b64url_for_test(value: &str) -> Vec<u8> {
    let mut padded = value.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE,
        padded.as_bytes(),
    )
    .expect("b64url")
}

fn encode_b64url_for_test(raw: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw)
}

fn hex_encode_local(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
