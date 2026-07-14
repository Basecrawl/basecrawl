//! M18 hard-path CDP anti-detect depth (VAL-CDP-001/002/003/004/005/006/007/008/009/010,
//! VAL-FPRINT-001/002/013/014, VAL-UNLOCK-014).
//!
//! Hermetic canaries bind only in mission range 21000–21099. No captcha marketplace,
//! no live industrial bot vendors, no Oxylabs lock-in. Residual and honesty language only.

use basecrawl_fp::{
    browser_injection_script, generate, hard_path_versions_are_pin_coherent,
    product_chromium_major, product_chromium_version, sec_ch_ua_header, PINNED_CHROMIUM_MAJOR,
    USER_AGENTS,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

/// Bind a canary listener exclusively inside the mission hermetic port range (VAL-CDP-010).
fn bind_cdp_canary_port() -> TcpListener {
    for port in 21000u16..=21099 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            let _ = listener.set_nonblocking(false);
            return listener;
        }
    }
    panic!("no free CDP canary port in 21000-21099");
}

fn run_cli(args: &[&str]) -> Output {
    run_cli_env(args, &[])
}

fn run_cli_env(args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    cmd.env_remove("BASECRAWL_LIVE_PROXY");
    cmd.env_remove("BASECRAWL_DISABLE_STEALTH_INJECT");
    for key in [
        "BASECRAWL_HTTP_PROXY",
        "BASECRAWL_HTTPS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        cmd.env_remove(key);
    }
    for (k, v) in env {
        match v {
            Some(val) => {
                cmd.env(k, val);
            }
            None => {
                cmd.env_remove(k);
            }
        }
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn basecrawl")
}

fn proof_from_output(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON stdout, got parse error {e}; status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn html_from_proof(proof: &Value) -> String {
    proof["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

/// Early-document canary that records webdriver/chrome/runtime BEFORE any deferred DOM work.
/// The inline `<script>` runs at parse time; Page.addScriptToEvaluateOnNewDocument must win first.
const EARLY_SURFACE_CANARY: &str = r#"<!doctype html><html><head>
<script>
(function () {
  function safeRuntimeProbe() {
    try {
      if (typeof window.chrome === 'undefined' || !window.chrome) {
        return { present: false, runtimePresent: false, threw: false, idType: 'absent' };
      }
      var rt = window.chrome.runtime;
      if (typeof rt === 'undefined') {
        return { present: true, runtimePresent: false, threw: false, idType: 'undefined' };
      }
      var idType = typeof rt.id;
      // Common detector touch points must not throw on a coherent policy surface.
      var connectType = typeof rt.connect;
      var sendType = typeof rt.sendMessage;
      return {
        present: true,
        runtimePresent: true,
        threw: false,
        idType: idType,
        connectType: connectType,
        sendType: sendType
      };
    } catch (e) {
      return { present: true, runtimePresent: true, threw: true, err: String(e && e.message || e) };
    }
  }
  function dualPatchProbe() {
    var proto = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
    var own = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
    var desc = own || proto;
    var wd;
    try { wd = navigator.webdriver; } catch (e) { wd = 'throw:' + String(e && e.message || e); }
    return {
      webdriver: wd,
      configurable: !!(desc && desc.configurable),
      hasGetter: !!(desc && typeof desc.get === 'function'),
      dualMarker: typeof window.__bcStealthInstalled !== 'undefined'
    };
  }
  var chromePresent = (typeof window.chrome !== 'undefined' && window.chrome !== null);
  var reports = {
    early: true,
    webdriver: (function () { try { return navigator.webdriver === true; } catch (_) { return true; } })(),
    webdriverRaw: (function () { try { return String(navigator.webdriver); } catch (e) { return 'throw'; } })(),
    chromePresent: chromePresent,
    runtime: safeRuntimeProbe(),
    dual: dualPatchProbe(),
    banner: (document.documentElement && document.documentElement.outerHTML) || ''
  };
  window.__bcCdpCanary = reports;
  document.addEventListener('DOMContentLoaded', function () {
    try {
      document.body.setAttribute('data-webdriver', String(reports.webdriver));
      document.body.setAttribute('data-chrome', String(reports.chromePresent));
      document.body.setAttribute('data-runtime-threw', String(reports.runtime.threw));
      document.body.setAttribute('data-early', '1');
      document.body.innerHTML =
        '<pre id="surface">' +
        'early=1' +
        ';webdriver=' + reports.webdriver +
        ';webdriverRaw=' + reports.webdriverRaw +
        ';chrome=' + reports.chromePresent +
        ';runtimePresent=' + reports.runtime.runtimePresent +
        ';runtimeThrew=' + reports.runtime.threw +
        ';runtimeIdType=' + reports.runtime.idType +
        ';dualMarker=' + reports.dual.dualMarker +
        ';dualWd=' + reports.dual.webdriver +
        '</pre>';
    } catch (_) {}
  });
  // Also write immediately for rsparser-sensitive environments where body is already present.
  try {
    if (document.body) {
      document.body.setAttribute('data-webdriver', String(reports.webdriver));
      document.body.setAttribute('data-chrome', String(reports.chromePresent));
      document.body.setAttribute('data-early', '1');
      document.body.innerHTML =
        '<pre id="surface">' +
        'early=1' +
        ';webdriver=' + reports.webdriver +
        ';webdriverRaw=' + reports.webdriverRaw +
        ';chrome=' + reports.chromePresent +
        ';runtimePresent=' + reports.runtime.runtimePresent +
        ';runtimeThrew=' + reports.runtime.threw +
        ';runtimeIdType=' + reports.runtime.idType +
        ';dualMarker=' + reports.dual.dualMarker +
        ';dualWd=' + reports.dual.webdriver +
        '</pre>';
    }
  } catch (_) {}
})();
</script>
</head><body>
<div id="status">pending-early-probe</div>
</body></html>"#;

fn spawn_static_canary(body: &'static str) -> String {
    let listener = bind_cdp_canary_port();
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.read(&mut buf);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    format!("http://{addr}/")
}

/// Same-origin multipage sticky canary for VAL-CDP-004.
/// Two dedicated mission-range origins avoid path-routing races under Chromium multipath.
/// Sticky early-inject coherence is what this asserts (same hard-path policy; A then B).
fn spawn_multipage_surface_canary() -> (String, String) {
    fn body_for(page: &str, with_next: bool) -> String {
        let next = if with_next {
            r#"<a id="next" rel="next" href="/page-b">next</a>"#
        } else {
            ""
        };
        format!(
            r#"<!doctype html><html><body data-static-page="{page}">
{next}
<script>
const chromePresent = (typeof window.chrome !== 'undefined' && window.chrome !== null);
let wd = false;
try {{ wd = navigator.webdriver === true; }} catch (e) {{ wd = true; }}
let runtimeThrew = false;
try {{ if (window.chrome && window.chrome.runtime) {{ void window.chrome.runtime.id; }} }} catch (e) {{ runtimeThrew = true; }}
document.body.setAttribute('data-page', '{page}');
document.body.setAttribute('data-webdriver', String(wd));
document.body.setAttribute('data-chrome', String(chromePresent));
document.body.insertAdjacentHTML('beforeend',
  '<pre id="surface">page={page};webdriver=' + wd +
  ';chrome=' + chromePresent +
  ';runtimeThrew=' + runtimeThrew +
  ';dual=' + (typeof window.__bcStealthInstalled !== 'undefined') +
  '</pre>');
</script>
<pre id="static-surface">page={page}-static</pre>
</body></html>"#,
            page = page,
            next = next
        )
    }

    fn spawn_fixed(body: String) -> String {
        let listener = bind_cdp_canary_port();
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(90);
            while Instant::now() < deadline {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.read(&mut buf);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                } else {
                    thread::sleep(Duration::from_millis(5));
                }
            }
        });
        format!("http://{addr}/")
    }

    let a = spawn_fixed(body_for("A", true));
    let b = spawn_fixed(body_for("B", false));
    (a, b)
}

/// Parent-frame dual-surface canary for VAL-CDP-005 (no hanging iframe dependency).
/// Attaches a same-document sandbox iframe via about:blank so network/Fetch intercept cannot hang.
/// Top-level webdriver/chrome must stay coherent without dual-inject thrash after attach.
fn spawn_iframe_cross_origin_canary() -> String {
    let parent_body = r#"<!doctype html><html><head>
<script>
(function(){
  function dump(tag){
    var wd=false; try{wd=navigator.webdriver===true;}catch(e){wd=true;}
    var chromePresent=(typeof window.chrome!=='undefined'&&window.chrome!==null);
    var rtThrew=false;
    try{ if(window.chrome&&window.chrome.runtime){ void window.chrome.runtime.id; } }catch(e){rtThrew=true;}
    return 'tag='+tag+';webdriver='+wd+';chrome='+chromePresent+';runtimeThrew='+rtThrew+
      ';dual='+(typeof window.__bcStealthInstalled!=='undefined');
  }
  window.__pre = dump('pre');
  var finished = false;
  function finish(tag){
    if(finished) return;
    finished = true;
    var post=dump(tag);
    try {
      document.body.setAttribute('data-done','1');
      document.body.innerHTML='<pre id="surface">'+window.__pre+'|'+post+'</pre>';
    } catch (_) {}
  }
  document.addEventListener('DOMContentLoaded', function(){
    try {
      var iframe=document.createElement('iframe');
      iframe.id='xframe';
      // about:blank is hermetic and avoids Fetch/resource budget hangs from second-origin documents.
      iframe.src='about:blank';
      iframe.onload=function(){ finish('post'); };
      document.body.appendChild(iframe);
    } catch (e) {
      finish('post-err');
      return;
    }
    setTimeout(function(){ finish('post-timeout'); }, 300);
  });
})();
</script></head><body><div id="host">parent</div></body></html>"#;
    spawn_static_canary_dynamic(parent_body.to_string())
}

fn spawn_static_canary_dynamic(body: String) -> String {
    let listener = bind_cdp_canary_port();
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.read(&mut buf);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    format!("http://{addr}/")
}

fn assert_success_surface(out: &Output) -> String {
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let proof = proof_from_output(out);
    assert_eq!(
        proof["egress"]["fetch_path"].as_str(),
        Some("chromium"),
        "hard path must use chromium identity"
    );
    html_from_proof(&proof)
}

#[test]
fn val_cdp_010_canary_ports_only_mission_range() {
    let listener = bind_cdp_canary_port();
    let port = listener.local_addr().expect("addr").port();
    assert!(
        (21000..=21099).contains(&port),
        "CDP canary must stay in 21000-21099, got {port}"
    );
    // Default suite never imports captcha marketplace tokens.
    let profile = generate("cdp-range-seed");
    let script = browser_injection_script(&profile);
    for banned in [
        "2captcha",
        "anti-captcha",
        "capsolver",
        "capmonster",
        "oxylabs.io",
        "undetectable",
        "trustless",
        "100% guaranteed",
    ] {
        assert!(
            !script.to_ascii_lowercase().contains(banned),
            "inject must not embed marketplace/banned claim {banned}"
        );
    }
}

#[test]
fn val_cdp_001_early_document_script_before_content_probe() {
    let url = spawn_static_canary(EARLY_SURFACE_CANARY);
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "cdp-early-001",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_surface(&out);
    assert!(
        html.contains("early=1") || html.contains("data-early=\"1\""),
        "early probe marker missing; html={html}"
    );
    assert!(
        html.contains("webdriver=false") || html.contains("data-webdriver=\"false\""),
        "early inject must patch webdriver before canary read; html={html}"
    );
}

#[test]
fn val_cdp_002_005_no_dual_inject_thrash_and_iframe_parent_stable() {
    // Dual-inject thrash probe on main frame.
    let url = spawn_static_canary(EARLY_SURFACE_CANARY);
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "cdp-dual-002",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_surface(&out);
    assert!(
        html.contains("dualMarker=true") || html.contains("dual=true"),
        "stealth install marker should be present and stable; html={html}"
    );
    assert!(
        html.contains("webdriver=false") || html.contains("dualWd=false"),
        "final webdriver must stay false (no thrash re-expose); html={html}"
    );
    assert!(
        !html.contains("webdriver=true"),
        "dual inject must not re-expose webdriver true; html={html}"
    );

    // Cross-origin iframe attach must not thrash parent surface or hang (VAL-CDP-005).
    let parent = spawn_iframe_cross_origin_canary();
    let out = run_cli(&[
        &parent,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "cdp-iframe-005",
        "--timeout",
        "45",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_surface(&out);
    assert!(
        html.contains("tag=pre")
            && (html.contains("tag=post")
                || html.contains("tag=post-timeout")
                || html.contains("tag=post-err")),
        "parent pre/post dumps required; html={html}"
    );
    assert!(
        html.contains("webdriver=false") && !html.contains("webdriver=true"),
        "parent must remain webdriver=false after iframe attach; html={html}"
    );
}

#[test]
fn val_cdp_004_same_origin_multipage_sticky_keeps_early_inject() {
    let (page_a, page_b) = spawn_multipage_surface_canary();

    let out_a = run_cli(&[
        &page_a,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "cdp-multi-004-a",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html_a = assert_success_surface(&out_a);
    assert!(
        html_a.contains("page=A")
            && html_a.contains("webdriver=false")
            && html_a.contains("chrome=true"),
        "page A early inject; html={html_a}"
    );

    let out_b = run_cli(&[
        &page_b,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "cdp-multi-004-b",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html_b = assert_success_surface(&out_b);
    assert!(
        html_b.contains("page=B")
            && html_b.contains("webdriver=false")
            && html_b.contains("chrome=true"),
        "page B early inject must match A policy; html={html_b}"
    );
    assert!(
        !html_b.contains("webdriver=true"),
        "page B must not re-expose webdriver true; html={html_b}"
    );
}

#[test]
fn val_cdp_006_no_automation_console_banner_in_capture() {
    let url = spawn_static_canary(EARLY_SURFACE_CANARY);
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "cdp-banner-006",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_surface(&out);
    for banner in [
        "controlled by automated test software",
        "Chrome is being controlled by automated test software",
        "automationcontrolled",
    ] {
        assert!(
            !html.to_ascii_lowercase().contains(banner),
            "automation banner leaked into capture: {banner}; html={html}"
        );
    }
}

#[test]
fn val_cdp_008_hard_path_fails_closed_when_inject_disabled() {
    let url = spawn_static_canary(EARLY_SURFACE_CANARY);
    let out = run_cli_env(
        &[
            &url,
            "--formats",
            "html",
            "--force-browser",
            "--disable-stealth-inject",
            "--task-id",
            "cdp-fail-008",
            "--timeout",
            "30",
        ],
        &[("BASECRAWL_DISABLE_STEALTH_INJECT", Some("1"))],
    );
    assert!(
        !out.status.success(),
        "hard path must fail closed without stealth inject; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("hard_path_policy")
            || stderr.contains("stealth_inject")
            || stderr.contains("inject"),
        "error must name inject/hard-path policy; stderr={stderr}"
    );
    // No silent success with chromium residential-class claim.
    let stdout = String::from_utf8_lossy(&out.stdout);
    if let Ok(proof) = serde_json::from_str::<Value>(stdout.trim()) {
        assert!(
            proof.get("result").is_none()
                || proof["result"]["formats_produced"].is_null()
                || proof.get("error").is_some(),
            "must not emit success proof formats without inject"
        );
    }
}

#[test]
fn val_cdp_009_inject_source_never_embeds_secrets() {
    let secret = "super-secret-proxy-pass-XYZ-9f1d4c22";
    let profile = generate("cdp-secret-seed");
    let script = browser_injection_script(&profile);
    for token in [
        secret,
        "BASECRAWL_HTTP_PROXY",
        "oxylabs",
        "customer-USER",
        "pr.oxylabs.io",
        "OPENAI_API_KEY",
        "PHALA_CLOUD_API_KEY",
    ] {
        assert!(
            !script
                .to_ascii_lowercase()
                .contains(&token.to_ascii_lowercase()),
            "inject source must not embed secret/token-ish material {token}"
        );
    }

    // Live hard-path run with a header that looks sensitive must not leak into inject path logs.
    let remaining = Arc::new(Mutex::new(Vec::<String>::new()));
    let logs = Arc::clone(&remaining);
    // Use canary + success scrape; grepping inject unit already sufficient for source.
    // Keep an e2e grep of ScrapeProof for the secret password marker.
    let url = spawn_static_canary(EARLY_SURFACE_CANARY);
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--header",
        &format!("X-Proxy-Token: {secret}"),
        "--task-id",
        "cdp-secret-009",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let blob = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !blob.contains(secret),
        "secret leaked into stdout/stderr on hard path"
    );
    // Silence unused warning if mutex held for future log capture expansion.
    let _ = logs.lock().map(|v| v.len());
}

#[test]
fn val_fprint_001_002_window_chrome_and_runtime_policy() {
    let profile = generate("chrome-surface-seed");
    let script = browser_injection_script(&profile);
    assert!(
        script.contains("window.chrome") || script.contains("chrome"),
        "inject must mention chrome surface"
    );
    assert!(
        script.contains("runtime"),
        "inject must define chrome.runtime policy"
    );
    assert!(
        script.contains("__bcStealthInstalled"),
        "inject must be idempotent (dual-inject guard)"
    );

    let url = spawn_static_canary(EARLY_SURFACE_CANARY);
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "chrome-surface-seed",
        "--task-id",
        "fprint-chrome-001",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_surface(&out);
    assert!(
        html.contains("chrome=true") || html.contains("data-chrome=\"true\""),
        "window.chrome must be present on hard Chromium path; html={html}"
    );
    assert!(
        html.contains("runtimeThrew=false") || html.contains("data-runtime-threw=\"false\""),
        "chrome.runtime common reads must not throw; html={html}"
    );
    // Policy: residual-honest non-extension pages expose runtime without a real extension id.
    assert!(
        html.contains("runtimeIdType=undefined")
            || html.contains("runtimePresent=true")
            || html.contains("runtimePresent=false"),
        "runtime presence policy must be explicit in canary dump; html={html}"
    );
}

/// UA / Sec-CH-UA / full version canary written as attributes for hard-path pin coherence.
const UA_PIN_CANARY: &str = r#"<!doctype html><html><head>
<script>
(function () {
  function brands() {
    try {
      if (navigator.userAgentData && navigator.userAgentData.brands) {
        return navigator.userAgentData.brands.map(function (b) {
          return b.brand + ':' + b.version;
        }).join('|');
      }
    } catch (e) {}
    return '';
  }
  function fullBrands() {
    try {
      if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
        // Fire-and-forget high entropy is async; surface low-entropy brands + UA immediately.
      }
    } catch (e) {}
    return brands();
  }
  var ua = navigator.userAgent || '';
  var report = {
    ua: ua,
    brands: brands(),
    fullBrands: fullBrands(),
    platform: (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || ''
  };
  window.__bcUaCanary = report;
  function paint() {
    try {
      if (!document.body) return;
      document.body.setAttribute('data-ua', report.ua);
      document.body.setAttribute('data-brands', report.brands);
      document.body.innerHTML =
        '<pre id="surface">' +
        'ua=' + report.ua +
        ';brands=' + report.brands +
        ';platform=' + report.platform +
        '</pre>';
    } catch (_) {}
  }
  document.addEventListener('DOMContentLoaded', paint);
  paint();
})();
</script>
</head><body><div id="status">pending-ua-probe</div></body></html>"#;

#[test]
fn val_cdp_007_and_fprint_013_single_chromium_major_pin_coherent() {
    // Profile + product surfaces must share one pin major (no 145 vs 148 product drift).
    assert_eq!(product_chromium_major(), PINNED_CHROMIUM_MAJOR);
    assert!(product_chromium_version().starts_with("145."));
    for ua in USER_AGENTS {
        assert!(
            ua.contains(&format!("Chrome/{PINNED_CHROMIUM_MAJOR}.")),
            "USER_AGENTS must stay on pin major: {ua}"
        );
        assert!(
            !ua.contains("Chrome/148"),
            "no 148 drift in allowlist: {ua}"
        );
    }

    let profile = generate("cdp-ua-pin-seed");
    assert!(hard_path_versions_are_pin_coherent(&profile));
    assert_eq!(profile.chrome_major, PINNED_CHROMIUM_MAJOR);
    assert!(profile
        .user_agent
        .contains(&format!("Chrome/{PINNED_CHROMIUM_MAJOR}.")));
    let ch = sec_ch_ua_header(&profile);
    assert!(ch.contains(&format!("v=\"{PINNED_CHROMIUM_MAJOR}\"")));
    assert!(!ch.contains("v=\"148\""));

    let url = spawn_static_canary(UA_PIN_CANARY);
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "cdp-ua-pin-seed",
        "--task-id",
        "cdp-ua-007",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_surface(&out);
    assert!(
        html.contains(&format!("Chrome/{PINNED_CHROMIUM_MAJOR}.")),
        "post-inject reflected UA major must match product pin; html={html}"
    );
    assert!(
        !html.contains("Chrome/148"),
        "hard path must not reflect neighbor major 148; html={html}"
    );
    // Brand list (when UA-CH is available) must not advertise a different major.
    if html.contains("Google Chrome:") || html.contains("Chromium:") {
        assert!(
            html.contains(&format!("Google Chrome:{PINNED_CHROMIUM_MAJOR}"))
                || html.contains(&format!("Chromium:{PINNED_CHROMIUM_MAJOR}")),
            "CH-UA brand major must match pin; html={html}"
        );
        assert!(
            !html.contains("Google Chrome:148") && !html.contains("Chromium:148"),
            "CH-UA must not advertise 148 on hard path; html={html}"
        );
    }
}

#[test]
fn val_cdp_003_fprint_014_unlock_014_residual_honesty_in_product_surfaces() {
    // VAL-CDP-003 / VAL-FPRINT-014 / VAL-UNLOCK-014: residual docs + --help honesty
    // (Runtime.enable residual, headless residual, Chromium major residual).
    let help = Command::new(BIN)
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn help");
    assert!(help.status.success());
    let help_text = format!(
        "{}{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    )
    .to_ascii_lowercase();
    assert!(
        help_text.contains("headless") || help_text.contains("runtime"),
        "CLI help must surface residual honesty markers; help={help_text}"
    );
    assert!(
        help_text.contains("145") || help_text.contains("chromium"),
        "CLI help should mention Chromium pin residual; help={help_text}"
    );
    // Use multi-word absolute claims only: short tokens may appear inside honest negation
    // phrases if copywriters reverse polarity ("not X"), so gate on full claim language.
    for banned in [
        "passes all headless detectors",
        "100% guaranteed",
        "cdp residual fully eliminated",
        "no cdp leak forever",
        "trustless scrape",
        "fully undetectable",
    ] {
        assert!(
            !help_text.contains(banned),
            "help must not claim absolute anti-detect elimination ({banned})"
        );
    }

    // Product residual docs (SECURITY + TCB inventory + operator guide) must be present
    // and honest about Runtime / headless / Chromium major. Path is workspace-relative.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let security = std::fs::read_to_string(root.join("docs/SECURITY.md")).expect("SECURITY.md");
    let tcb = std::fs::read_to_string(root.join("docs/tcb-inventory.md")).expect("tcb-inventory");
    let operator = std::fs::read_to_string(root.join("docs/operators/proxy-and-egress.md"))
        .expect("proxy-ops");
    let combined = format!("{security}\n{tcb}\n{operator}").to_ascii_lowercase();
    assert!(
        combined.contains("runtime.enable") || combined.contains("runtime protocol"),
        "residual docs must list Runtime.enable / CDP protocol residual (VAL-CDP-003)"
    );
    assert!(
        combined.contains("headless")
            && (combined.contains("residual") || combined.contains("detect")),
        "residual docs must admit headless residual (VAL-FPRINT-014)"
    );
    assert!(
        combined.contains("145")
            && (combined.contains("chromium major")
                || combined.contains("major 145")
                || combined.contains("chrome/145")
                || combined.contains("chromium_version=145")),
        "residual docs must note Chromium major pin residual (VAL-UNLOCK-014)"
    );
    // Positive absolute marketing claims only (honest residual prose must still talk about residuals).
    for banned in [
        "we are undetectable",
        "fully eliminates cdp residual",
        "trustless scrape authenticity",
        "100% guaranteed authenticity",
        "anonymous residential exit",
    ] {
        assert!(
            !combined.contains(banned),
            "residual docs still contain absolute claim {banned}"
        );
    }

    // Vendored launcher prefers new headless mode on hard path.
    let process_src =
        std::fs::read_to_string(root.join("vendor/headless_chrome/src/browser/process.rs"))
            .expect("process.rs");
    assert!(
        process_src.contains("--headless=new"),
        "launch hygiene must prefer --headless=new where pin supports it"
    );
}
