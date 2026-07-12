//! Per-scrape, non-attestation egress metadata.
//!
//! These fields are intentionally outside the deterministic result surface: they describe the
//! network route and fetch time of one observation rather than the crawled content. Landmark RTT
//! collection belongs to the later geo feature, so this module emits its stable empty-object shape
//! at M1. The `fingerprint_seed` is the auditable seed that parameterized the non-security
//! fingerprint dimensions (VAL-ANTIBOT-036) and is committed into `report_data`.

use crate::error::Error;
use basecrawl_proof::Egress;
use std::collections::BTreeMap;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Assemble egress metadata captured at the successful-fetch boundary.
///
/// `egress_ip` is the source address selected by the operating system for the actual outbound
/// route. `fingerprint_seed` is the already-normalized (64-hex) seed that drove the per-miner /
/// per-task fingerprint profile; it is logged here so the emitted variation is auditable and
/// bound into the attested `report_data` digest. Landmark RTT population is deferred to geo.
pub fn build(
    egress_ip: IpAddr,
    fetched_at: OffsetDateTime,
    fingerprint_seed: &str,
) -> Result<Egress, Error> {
    let timestamp = fetched_at
        .format(&Rfc3339)
        .map_err(|error| Error::EgressMetadata(error.to_string()))?;

    Ok(Egress {
        egress_ip: Some(egress_ip.to_string()),
        landmark_rtts: BTreeMap::new(),
        timestamp: Some(timestamp),
        fingerprint_seed: Some(fingerprint_seed.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn build_emits_complete_m1_egress_shape() {
        let seed = "11".repeat(32);
        let egress = build(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            OffsetDateTime::now_utc(),
            &seed,
        )
        .expect("egress metadata");

        let timestamp = egress.timestamp.expect("timestamp");
        let parsed =
            OffsetDateTime::parse(&timestamp, &Rfc3339).expect("timestamp must be RFC 3339");
        assert!(parsed.offset().is_utc());
        assert_eq!(egress.egress_ip.as_deref(), Some("127.0.0.1"));
        assert!(egress.landmark_rtts.is_empty());
        assert_eq!(egress.fingerprint_seed.as_deref(), Some(seed.as_str()));
    }

    #[test]
    fn fingerprint_seed_is_logged_verbatim() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let fetched_at = OffsetDateTime::UNIX_EPOCH;
        let seed = basecrawl_fp::normalize_seed("miner-task-seed");

        let first = build(ip, fetched_at, &seed).expect("first egress metadata");
        let second = build(ip, fetched_at, &seed).expect("second egress metadata");

        assert_eq!(first.fingerprint_seed, second.fingerprint_seed);
        assert_eq!(first.fingerprint_seed.as_deref(), Some(seed.as_str()));
    }

    #[test]
    fn different_seeds_remain_distinct_in_egress() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let fetched_at = OffsetDateTime::UNIX_EPOCH;
        let a = build(ip, fetched_at, &basecrawl_fp::normalize_seed("a")).unwrap();
        let b = build(ip, fetched_at, &basecrawl_fp::normalize_seed("b")).unwrap();
        assert_ne!(a.fingerprint_seed, b.fingerprint_seed);
    }
}
