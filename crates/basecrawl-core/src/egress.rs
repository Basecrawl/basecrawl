//! Per-scrape, non-attestation egress metadata.
//!
//! These fields are intentionally outside the deterministic result surface: they describe the
//! network route and fetch time of one observation rather than the crawled content. Landmark RTT
//! collection belongs to the later geo feature, so this module emits its stable empty-object shape
//! at M1.

use crate::error::Error;
use basecrawl_proof::Egress;
use std::collections::BTreeMap;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const FINGERPRINT_SEED_BYTES: usize = 32;

/// Assemble egress metadata captured at the successful-fetch boundary.
///
/// `egress_ip` is the source address selected by the operating system for the actual outbound
/// route. The public-IP corroboration and landmark RTT population are deferred to geo validation,
/// but the M1 wire shape is complete now.
pub fn build(egress_ip: IpAddr, fetched_at: OffsetDateTime) -> Result<Egress, Error> {
    let timestamp = fetched_at
        .format(&Rfc3339)
        .map_err(|error| Error::EgressMetadata(error.to_string()))?;

    let mut seed = [0u8; FINGERPRINT_SEED_BYTES];
    getrandom::fill(&mut seed).map_err(|error| Error::EgressMetadata(error.to_string()))?;

    Ok(Egress {
        egress_ip: Some(egress_ip.to_string()),
        landmark_rtts: BTreeMap::new(),
        timestamp: Some(timestamp),
        fingerprint_seed: Some(hex(&seed)),
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn build_emits_complete_m1_egress_shape() {
        let egress = build(IpAddr::V4(Ipv4Addr::LOCALHOST), OffsetDateTime::now_utc())
            .expect("egress metadata");

        let timestamp = egress.timestamp.expect("timestamp");
        let parsed =
            OffsetDateTime::parse(&timestamp, &Rfc3339).expect("timestamp must be RFC 3339");
        assert!(parsed.offset().is_utc());
        assert_eq!(egress.egress_ip.as_deref(), Some("127.0.0.1"));
        assert!(egress.landmark_rtts.is_empty());
        assert_eq!(
            egress.fingerprint_seed.as_deref().map(str::len),
            Some(FINGERPRINT_SEED_BYTES * 2)
        );
    }
}
