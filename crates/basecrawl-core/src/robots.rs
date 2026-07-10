//! `robots.txt` policy evaluation and XML sitemap discovery.
//!
//! The crawler reads the origin's robots policy before the requested resource. It records an
//! allow/deny decision for the `basecrawl` user agent and can enforce that decision before any
//! page fetch. Sitemap discovery is deliberately best-effort: unavailable or malformed sitemap
//! documents never turn an otherwise permitted page into a failed scrape.

use crate::charset;
use crate::fetch::{self, FetchConfig};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use url::Url;

/// The robots user-agent token used by the crawler policy evaluator.
pub const USER_AGENT: &str = "basecrawl";

/// Bounded number of sitemap documents fetched from a single page's policy and default location.
const MAX_SITEMAPS: usize = 32;
/// Bounded number of sitemap URL seeds surfaced in one scrape result.
const MAX_SITEMAP_URLS: usize = 10_000;

/// Configured handling for an origin's `robots.txt` policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RobotsPolicy {
    /// Block a path matched by a `Disallow` rule before fetching it.
    #[default]
    Enforce,
    /// Fetch regardless, but surface the policy's decision in metadata.
    Observe,
    /// Do not fetch or evaluate `robots.txt`.
    Ignore,
}

impl RobotsPolicy {
    /// Stable CLI/metadata spelling for the policy.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Observe => "observe",
            Self::Ignore => "ignore",
        }
    }
}

impl fmt::Display for RobotsPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RobotsPolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "enforce" => Ok(Self::Enforce),
            "observe" => Ok(Self::Observe),
            "ignore" => Ok(Self::Ignore),
            _ => Err("must be one of: enforce, observe, ignore".to_string()),
        }
    }
}

/// A decision made for the requested path from the origin's robots policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobotsDecision {
    /// Configured mode that determined whether a deny rule is enforced.
    pub policy: RobotsPolicy,
    /// Whether a robots response was received, including an unavailable HTTP status.
    pub fetched: bool,
    /// HTTP status of the robots response when one was received.
    pub status_code: Option<u16>,
    /// Canonical robots URL consulted by the crawler.
    pub robots_url: String,
    /// `allowed`, `denied`, `unmatched`, `unavailable`, or `ignored`.
    pub disposition: &'static str,
    /// Most-specific applicable allow/disallow rule, if a rule matched.
    pub matched_rule: Option<MatchedRule>,
    /// Absolute sitemap URLs declared by robots, excluding malformed/non-HTTP(S) entries.
    pub sitemap_urls: Vec<Url>,
}

impl RobotsDecision {
    /// Whether policy enforcement must stop the target page fetch.
    pub fn denies_fetch(&self) -> bool {
        self.policy == RobotsPolicy::Enforce && self.disposition == "denied"
    }

    /// Structured policy field used in emitted metadata and deny errors.
    pub fn to_value(&self) -> Value {
        let matched_rule = self.matched_rule.as_ref().map_or(Value::Null, |rule| {
            json!({
                "directive": rule.directive,
                "path": rule.path,
            })
        });
        json!({
            "policy": self.policy.as_str(),
            "fetched": self.fetched,
            "statusCode": self.status_code,
            "robotsUrl": self.robots_url,
            "disposition": self.disposition,
            "matched_rule": matched_rule,
        })
    }
}

/// A policy decision made before transmitting a top-level document request.
#[derive(Debug, Clone)]
pub struct DocumentHop {
    target_url: String,
    decision: RobotsDecision,
}

impl DocumentHop {
    fn to_value(&self) -> Value {
        let mut value = self.decision.to_value();
        if let Value::Object(object) = &mut value {
            object.insert(
                "targetUrl".to_string(),
                Value::String(self.target_url.clone()),
            );
        }
        value
    }
}

/// Shared robots consultation for all direct and browser top-level document hops in one scrape.
///
/// Auxiliary policy documents such as `robots.txt` and sitemaps continue to use the unguarded
/// fetch path. This keeps policy consultation non-recursive and distinct from document traversal.
#[derive(Debug, Clone)]
pub struct DocumentPolicy {
    config: FetchConfig,
    policy: RobotsPolicy,
    deadline: Instant,
    hops: Arc<Mutex<Vec<DocumentHop>>>,
}

impl DocumentPolicy {
    /// Create a recorder that applies one policy configuration to every document hop.
    pub fn new(config: FetchConfig, policy: RobotsPolicy, deadline: Instant) -> Self {
        Self {
            config,
            policy,
            deadline,
            hops: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Consult and record policy before the caller transmits a top-level document request.
    pub fn check(&self, target: &Url) -> Result<(), crate::Error> {
        let decision = consult(target, &self.config, self.policy, self.deadline)?;
        let denied = decision.denies_fetch();
        self.hops
            .lock()
            .expect("document robots policy mutex must not be poisoned")
            .push(DocumentHop {
                target_url: target.to_string(),
                decision: decision.clone(),
            });
        if denied {
            let mut value = decision.to_value();
            if let Value::Object(object) = &mut value {
                object.insert("targetUrl".to_string(), Value::String(target.to_string()));
            }
            return Err(crate::Error::RobotsDenied(value));
        }
        Ok(())
    }

    /// Return the first document hop's decision for compatibility with the existing metadata
    /// field. A policy check is always performed for the initial document before this is called.
    pub fn initial_decision(&self) -> RobotsDecision {
        self.hops
            .lock()
            .expect("document robots policy mutex must not be poisoned")
            .first()
            .expect("initial document robots policy must be checked")
            .decision
            .clone()
    }

    /// Serialize every recorded top-level document disposition in traversal order.
    pub fn hops_value(&self) -> Value {
        Value::Array(
            self.hops
                .lock()
                .expect("document robots policy mutex must not be poisoned")
                .iter()
                .map(DocumentHop::to_value)
                .collect(),
        )
    }
}

/// The most-specific robots rule that matched a target path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    pub directive: &'static str,
    pub path: String,
}

#[derive(Debug, Default)]
struct Group {
    agents: Vec<String>,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
struct Rule {
    allow: bool,
    path: String,
}

#[derive(Debug, Default)]
struct ParsedRobots {
    groups: Vec<Group>,
    sitemap_urls: Vec<String>,
}

/// Fetch and evaluate an origin's `/robots.txt` for a requested URL.
///
/// Failure to retrieve, parse, or receive a successful robots document is observable as
/// `unavailable`, but remains permissive. This follows the normal crawler convention that a
/// transient policy fetch failure is not a deny rule.
pub fn consult(
    url: &Url,
    config: &FetchConfig,
    policy: RobotsPolicy,
    deadline: Instant,
) -> Result<RobotsDecision, crate::Error> {
    let robots_url = robots_url(url);
    if policy == RobotsPolicy::Ignore {
        return Ok(RobotsDecision {
            policy,
            fetched: false,
            status_code: None,
            robots_url: robots_url.to_string(),
            disposition: "ignored",
            matched_rule: None,
            sitemap_urls: Vec::new(),
        });
    }

    let fetched = match fetch::fetch_until(&robots_url, config, deadline) {
        Ok(fetched) => fetched,
        Err(crate::Error::Timeout(message)) => return Err(crate::Error::Timeout(message)),
        Err(_) => return Ok(unavailable_decision(policy, robots_url, false, None)),
    };
    if !(200..300).contains(&fetched.status_code) {
        return Ok(unavailable_decision(
            policy,
            robots_url,
            true,
            Some(fetched.status_code),
        ));
    }

    let source = charset::decode_body(&fetched.body, fetched.content_type.as_deref(), false);
    let parsed = parse(&source);
    let sitemap_urls = parsed
        .sitemap_urls
        .iter()
        .filter_map(|candidate| robots_url.join(candidate).ok())
        .filter(is_http)
        .collect();
    let matched_rule = matching_rule(url.path(), &parsed.groups);
    let disposition =
        matched_rule.as_ref().map_or(
            "unmatched",
            |rule| if rule.allow { "allowed" } else { "denied" },
        );

    Ok(RobotsDecision {
        policy,
        fetched: true,
        status_code: Some(fetched.status_code),
        robots_url: robots_url.to_string(),
        disposition,
        matched_rule: matched_rule.map(|rule| MatchedRule {
            directive: if rule.allow { "allow" } else { "disallow" },
            path: rule.path,
        }),
        sitemap_urls,
    })
}

fn unavailable_decision(
    policy: RobotsPolicy,
    robots_url: Url,
    fetched: bool,
    status_code: Option<u16>,
) -> RobotsDecision {
    RobotsDecision {
        policy,
        fetched,
        status_code,
        robots_url: robots_url.to_string(),
        disposition: "unavailable",
        matched_rule: None,
        sitemap_urls: Vec::new(),
    }
}

/// Discover sitemap URL seeds from the default `/sitemap.xml` and any robots-declared locations.
///
/// Sitemap indexes are followed recursively within a bounded queue. All fetch and parse failures
/// are ignored so discovery cannot make an otherwise allowed target request fail.
pub fn discover_sitemap_urls(
    target: &Url,
    config: &FetchConfig,
    robots_sitemaps: &[Url],
    deadline: Instant,
) -> Result<Vec<String>, crate::Error> {
    let mut queue = Vec::with_capacity(1 + robots_sitemaps.len());
    queue.push(default_sitemap_url(target));
    queue.extend(robots_sitemaps.iter().cloned());

    let mut seen_sitemaps = HashSet::new();
    let mut seen_seeds = HashSet::new();
    let mut seeds = Vec::new();

    while let Some(sitemap_url) = queue.pop() {
        if seen_sitemaps.len() >= MAX_SITEMAPS || !is_http(&sitemap_url) {
            break;
        }
        if !seen_sitemaps.insert(sitemap_url.to_string()) {
            continue;
        }

        let fetched = match fetch::fetch_until(&sitemap_url, config, deadline) {
            Ok(fetched) => fetched,
            Err(crate::Error::Timeout(message)) => return Err(crate::Error::Timeout(message)),
            Err(_) => continue,
        };
        if !(200..300).contains(&fetched.status_code) {
            continue;
        }
        let source = charset::decode_body(&fetched.body, fetched.content_type.as_deref(), false);
        let parsed = parse_sitemap(&source, &sitemap_url);

        for url in parsed.url_seeds {
            if seeds.len() >= MAX_SITEMAP_URLS {
                return Ok(seeds);
            }
            if seen_seeds.insert(url.clone()) {
                seeds.push(url);
            }
        }
        queue.extend(parsed.nested_sitemaps);
    }

    Ok(seeds)
}

fn robots_url(target: &Url) -> Url {
    let mut robots = target.clone();
    robots.set_path("/robots.txt");
    robots.set_query(None);
    robots.set_fragment(None);
    robots
}

fn default_sitemap_url(target: &Url) -> Url {
    let mut sitemap = target.clone();
    sitemap.set_path("/sitemap.xml");
    sitemap.set_query(None);
    sitemap.set_fragment(None);
    sitemap
}

fn is_http(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

fn parse(source: &str) -> ParsedRobots {
    let mut parsed = ParsedRobots::default();
    let mut current: Option<Group> = None;

    for raw_line in source.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();

        match name.as_str() {
            "sitemap" if !value.is_empty() => parsed.sitemap_urls.push(value.to_string()),
            "user-agent" => {
                if current
                    .as_ref()
                    .is_some_and(|group| !group.rules.is_empty())
                {
                    parsed
                        .groups
                        .push(current.take().expect("current group exists"));
                }
                let group = current.get_or_insert_with(Group::default);
                group.agents.push(value.to_ascii_lowercase());
            }
            "allow" | "disallow" => {
                if value.is_empty() {
                    continue;
                }
                if let Some(group) = current.as_mut() {
                    if !group.agents.is_empty() {
                        group.rules.push(Rule {
                            allow: name == "allow",
                            path: value.to_string(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(group) = current {
        parsed.groups.push(group);
    }
    parsed
}

fn matching_rule(path: &str, groups: &[Group]) -> Option<Rule> {
    let best_agent_match = groups.iter().filter_map(group_agent_match).max()?;

    let mut selected: Option<(usize, Rule)> = None;
    for group in groups
        .iter()
        .filter(|group| group_agent_match(group) == Some(best_agent_match))
    {
        for rule in &group.rules {
            if !rule_matches(path, &rule.path) {
                continue;
            }
            let specificity = rule.path.bytes().filter(|byte| *byte != b'*').count();
            let replace = selected.as_ref().is_none_or(|(current, selected_rule)| {
                specificity > *current
                    || (specificity == *current && rule.allow && !selected_rule.allow)
            });
            if replace {
                selected = Some((specificity, rule.clone()));
            }
        }
    }
    selected.map(|(_, rule)| rule)
}

fn group_agent_match(group: &Group) -> Option<usize> {
    group
        .agents
        .iter()
        .filter_map(|agent| {
            if agent == "*" {
                Some(0)
            } else if USER_AGENT.contains(agent) {
                Some(agent.len())
            } else {
                None
            }
        })
        .max()
}

fn rule_matches(path: &str, rule: &str) -> bool {
    let (pattern, anchored) = rule
        .strip_suffix('$')
        .map_or((rule, false), |pattern| (pattern, true));
    wildcard_matches_prefix(pattern.as_bytes(), path.as_bytes(), anchored)
}

/// Match a robots pattern with `*` wildcards against the start of a path, or the entire path when
/// a trailing `$` anchor was present. The byte-level form is appropriate because `url::Url` exposes
/// the percent-encoded request path sent to the origin.
fn wildcard_matches_prefix(pattern: &[u8], value: &[u8], anchored: bool) -> bool {
    let (mut pattern_index, mut value_index) = (0usize, 0usize);
    let mut wildcard = None;
    let mut wildcard_value_index = 0usize;

    while value_index < value.len() {
        if pattern_index == pattern.len() {
            return !anchored;
        }
        if pattern[pattern_index] == b'*' {
            wildcard = Some(pattern_index);
            pattern_index += 1;
            wildcard_value_index = value_index;
        } else if pattern[pattern_index] == value[value_index] {
            pattern_index += 1;
            value_index += 1;
        } else if let Some(star_index) = wildcard {
            pattern_index = star_index + 1;
            wildcard_value_index += 1;
            value_index = wildcard_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len() || !anchored
}

#[derive(Debug, Default)]
struct SitemapDocument {
    url_seeds: Vec<String>,
    nested_sitemaps: Vec<Url>,
}

fn parse_sitemap(source: &str, base: &Url) -> SitemapDocument {
    let mut reader = Reader::from_str(source);
    reader.config_mut().trim_text(true);
    let mut result = SitemapDocument::default();
    let mut parent = None;
    let mut in_loc = false;
    let mut location = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => match local_name(event.name().as_ref()) {
                b"url" => parent = Some(b"url".as_slice()),
                b"sitemap" => parent = Some(b"sitemap".as_slice()),
                b"loc" if parent.is_some() => {
                    in_loc = true;
                    location.clear();
                }
                _ => {}
            },
            Ok(Event::Text(text)) if in_loc => {
                if let Ok(decoded) = text.decode() {
                    location.push_str(&decoded);
                }
            }
            Ok(Event::CData(text)) if in_loc => {
                if let Ok(decoded) = text.decode() {
                    location.push_str(&decoded);
                }
            }
            Ok(Event::End(event)) => match local_name(event.name().as_ref()) {
                b"loc" if in_loc => {
                    let location = location.trim();
                    if let Ok(url) = base.join(location) {
                        if is_http(&url) {
                            match parent {
                                Some(b"url") => result.url_seeds.push(url.to_string()),
                                Some(b"sitemap") => result.nested_sitemaps.push(url),
                                _ => {}
                            }
                        }
                    }
                    in_loc = false;
                }
                b"url" | b"sitemap" => parent = None,
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    result
}

fn local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ParsedRobots {
        parse(
            "User-agent: *\nDisallow: /private\nAllow: /private/ok\n\
             User-agent: basecrawl\nDisallow: /exclusive\nAllow: /exclusive/open$\n\
             Sitemap: /sitemap.xml\n",
        )
    }

    #[test]
    fn applies_the_most_specific_user_agent_and_rule() {
        let rules = fixture().groups;
        let denied = matching_rule("/exclusive/closed", &rules).expect("matching deny rule");
        assert!(!denied.allow);
        assert_eq!(denied.path, "/exclusive");

        let allowed = matching_rule("/exclusive/open", &rules).expect("matching allow rule");
        assert!(allowed.allow);
        assert_eq!(allowed.path, "/exclusive/open$");

        assert!(
            matching_rule("/private", &rules).is_none(),
            "the specific basecrawl group must supersede wildcard rules"
        );
    }

    #[test]
    fn longest_match_wins_and_allow_breaks_ties() {
        let parsed = parse(
            "User-agent: *\nDisallow: /blocked\nAllow: /blocked/open\nDisallow: /same\nAllow: /same\n",
        );
        assert!(
            matching_rule("/blocked/open/page", &parsed.groups)
                .expect("longer allow rule")
                .allow
        );
        assert!(
            matching_rule("/same", &parsed.groups)
                .expect("allow wins equal-length tie")
                .allow
        );
    }

    #[test]
    fn wildcards_and_end_anchors_match_as_robots_patterns() {
        assert!(rule_matches("/files/one.pdf", "/files/*.pdf$"));
        assert!(!rule_matches("/files/one.pdf/extra", "/files/*.pdf$"));
        assert!(rule_matches("/files/one.pdf/extra", "/files/*.pdf"));
        assert!(rule_matches("/anywhere", "/*"));
    }

    #[test]
    fn sitemap_parser_extracts_urlsets_and_indexes() {
        let base = Url::parse("https://example.test/dir/sitemap.xml").unwrap();
        let urls = parse_sitemap(
            "<urlset><url><loc>/a</loc></url><url><loc>https://other.test/b</loc></url></urlset>",
            &base,
        );
        assert_eq!(
            urls.url_seeds,
            vec![
                "https://example.test/a".to_string(),
                "https://other.test/b".to_string()
            ]
        );

        let index = parse_sitemap(
            "<sitemapindex><sitemap><loc>nested.xml</loc></sitemap></sitemapindex>",
            &base,
        );
        assert_eq!(
            index.nested_sitemaps,
            vec![Url::parse("https://example.test/dir/nested.xml").unwrap()]
        );
    }
}
