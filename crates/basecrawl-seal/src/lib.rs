//! `basecrawl-seal` — enclave-side confidentiality primitives.
//!
//! Owns:
//! * the enclave X25519 identity used for sealed-box task receipt and the
//!   RA-TLS peer binding presented to the key-release server;
//! * the key-release CLIENT that obtains a session-sealed task key from the
//!   validator-operated measurement gate (architecture §7);
//! * authenticated (AEAD sealed-box) decryption of sealed scrape tasks in
//!   enclave memory — zero partial plaintext on tamper/truncate;
//! * **in-enclave DoH/DoT resolution** against a pin-by-IP recursive resolver
//!   so the host stub resolver / port 53 never sees a cleartext QNAME for the
//!   scrape target (VAL-CONF-013), complementing the in-process rustls TLS 1.3
//!   terminator that already keeps HTTP application data off the host wire
//!   (VAL-CONF-014);
//! * **sealed browser DNS isolation** — an in-process SOCKS5 CONNECT proxy
//!   that resolves domain names only through the DoH pin and is required by
//!   headless Chromium via `--proxy-server=socks5://…`, failing closed if the
//!   proxy cannot be established (VAL-CONF-013 residual for render/screenshot);
//! * **result sealing to the validator committee threshold public key** —
//!   the ScrapeProof result body is sealed to the committee, never to the
//!   miner, so the host-visible sealed-result payload stays opaque ciphertext
//!   (VAL-CONF-015, VAL-CONF-017);
//! * **host-visible log / metric redaction** — every host-facing log line,
//!   structured error on stderr, metric label, stack trace, and panic payload
//!   is reduced to host-safe kinds + digests so path/query, headers/cookies/
//!   tokens/body, and result plaintext never escape (VAL-CONF-018/019/020/031).
//!
//! Assertions satisfied by this crate for M3:
//! * **VAL-CONF-011** — without a released / enclave-held key the sealed task
//!   stays opaque; host and forked-image decrypts fail closed.
//! * **VAL-CONF-013** — DNS for scrape targets is resolved only over DoH/DoT to
//!   a pin-by-IP endpoint; no cleartext A/AAAA for the target on the host.
//! * **VAL-CONF-014** — application traffic is TLS 1.3 application-data only
//!   (enforced jointly with `basecrawl-core`'s rustls terminator).
//! * **VAL-CONF-015** — sealed result is addressed to the committee threshold
//!   public key; miner/host-held keys recover no result plaintext.
//! * **VAL-CONF-017** — host-visible sealed result is opaque ciphertext; result
//!   content markers never appear in the host-relayed envelope.
//! * **VAL-CONF-018** — host-visible logs / metric labels never carry a target
//!   URL path or query string; only redacted task IDs / hashes appear.
//! * **VAL-CONF-019** — request header / cookie / auth token / body markers
//!   never appear in host-visible logs or metric labels.
//! * **VAL-CONF-020** — result canary strings never leak into host-visible
//!   logs or metrics (results stay sealed, logs are redacted).
//! * **VAL-CONF-027** — bit-flip or truncation of the sealed-task ciphertext
//!   fails authenticated decryption; no partial plaintext is emitted or acted on.
//! * **VAL-CONF-031** — error / exception / panic paths are redacted to the
//!   same host-safe standard as the happy path.

#![forbid(unsafe_code)]

pub mod antibot_feedback;
pub mod browser_dns;
pub mod dns;
pub mod error;
pub mod identity;
pub mod keyrelease;
pub mod redact;
pub mod result;
pub mod task;

pub use antibot_feedback::{
    classify_coarse_from_status_and_markers, decrypt_antibot_feedback_as_miner_host,
    maybe_seal_failure_feedback, miner_visible_contains_marker, seal_antibot_feedback,
    unseal_antibot_feedback_with_committee_secret, AntibotFeedbackPlaintext, CoarseFailureHint,
    SealedAntibotFeedback, ANTIBOT_FEEDBACK_DOMAIN, ANTIBOT_FEEDBACK_KIND,
    ANTIBOT_FEEDBACK_RECIPIENT, ANTIBOT_FEEDBACK_SUITE,
};
pub use browser_dns::{
    chrome_dns_isolation_proxy_arg, document_host_needs_sealed_resolve, global_sealed_socks_proxy,
    preflight_document_dns, SealedSocksProxy, SEALED_BROWSER_DNS_MARKER,
};
pub use dns::{
    build_query, is_loopback_name, parse_answers, resolve_for_connect, NameResolver,
    PinnedResolver, ResolveResult, ResolverEndpoint, ResolverMode, DEFAULT_DOH_ENDPOINT,
    DEFAULT_DOT_ENDPOINT, DOH_PATH_MARKER, QTYPE_A, QTYPE_AAAA,
};
pub use error::SealError;
pub use identity::{
    hex_decode_32, key_id_for, task_seal_report_data_for, EnclaveIdentity, TASK_SEAL_DOMAIN,
};
pub use keyrelease::{
    decrypt_requires_released_key, key_release_report_data, parse_release_response,
    to_report_data_field, HttpKeyReleaseTransport, KeyReleaseClient, KeyReleaseTransport,
    QuoteBundle, QuoteProvider, ReleasedTaskKey, DEFAULT_KEY_RELEASE_TIMEOUT, KEY_RELEASE_TAG,
    RA_TLS_PEER_HEADER, REPORT_DATA_LEN,
};
pub use redact::{
    host_safe_digest, host_safe_panic_message, install_host_safe_panic_hook, redact_json_value,
    redact_markers, task_id_ref, url_path_query_ref, url_ref, HostSafeLabels,
    HOST_SAFE_DIGEST_PREFIX, REDACTED_TOKEN,
};
pub use result::{
    build_result_aad, decrypt_result_as_miner_host, decrypt_result_with_foreign_key,
    host_visible_contains_marker, seal_formats_to_committee, seal_result_to_committee,
    unseal_result_with_committee_secret, CommitteeThresholdPublicKey, ResultSealPlaintext,
    SealedResultEnvelope, RESULT_RECIPIENT_ROLE, RESULT_SEAL_DOMAIN, RESULT_SEAL_KIND,
    RESULT_SEAL_SUITE,
};
pub use task::{
    build_aad, decrypt_sealed_task, decrypt_with_foreign_key, decrypt_without_released_key,
    recipient_key_id, DecryptedTask, SealedTaskEnvelope, TASK_SEAL_SUITE,
};
