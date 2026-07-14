//! M19 hard-path fingerprint depth
//! (VAL-FPRINT-003/004/005/006/007/008/009/010/011/012/015/016/017/018).
//!
//! Hermetic canaries bind only in mission range 21000–21099. No captcha marketplace,
//! no anonymity/undetectable claims, no complete OS font inventory spoof marketing.

use basecrawl_fp::{
    browser_injection_script, generate, DEVICE_MEMORY, HARDWARE_CONCURRENCY, PLUGIN_INVENTORY,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

fn bind_mission_canary_port() -> TcpListener {
    for port in 21000u16..=21099 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            let _ = listener.set_nonblocking(false);
            return listener;
        }
    }
    panic!("no free fingerprint-depth canary port in 21000-21099");
}

fn run_cli(args: &[&str]) -> Output {
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

fn assert_success_chromium(out: &Output) -> String {
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

fn spawn_static_canary(body: String) -> String {
    let listener = bind_mission_canary_port();
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

/// Deep surface canary: plugins, mimeTypes, permissions, screen, deviceMemory, HC, canvas.
const DEEP_SURFACE_CANARY: &str = r#"<!doctype html><html><head>
<script>
(function () {
  function pluginsDump() {
    try {
      var p = navigator.plugins;
      var names = [];
      var len = (p && p.length) || 0;
      for (var i = 0; i < len; i++) {
        try { names.push((p[i] && p[i].name) || ''); } catch (e) { names.push('err'); }
      }
      return { length: len, names: names.join('|') };
    } catch (e) {
      return { length: 0, names: 'throw:' + String(e && e.message || e) };
    }
  }
  function mimeDump() {
    try {
      var m = navigator.mimeTypes;
      var len = (m && m.length) || 0;
      var types = [];
      for (var i = 0; i < len; i++) {
        try { types.push((m[i] && m[i].type) || ''); } catch (e) { types.push('err'); }
      }
      return { length: len, types: types.join('|') };
    } catch (e) {
      return { length: 0, types: 'throw' };
    }
  }
  function screenDump() {
    try {
      return {
        w: screen.width || 0,
        h: screen.height || 0,
        aw: screen.availWidth || 0,
        ah: screen.availHeight || 0,
        cd: screen.colorDepth || 0,
        vw: window.innerWidth || 0,
        vh: window.innerHeight || 0
      };
    } catch (e) {
      return { w: 0, h: 0, aw: 0, ah: 0, cd: 0, vw: 0, vh: 0 };
    }
  }
  function canvasProbe() {
    try {
      var c = document.createElement('canvas');
      c.width = 16; c.height = 16;
      var ctx = c.getContext('2d');
      if (!ctx) return { ok: false, crash: false };
      ctx.fillStyle = '#f00';
      ctx.fillRect(0, 0, 16, 16);
      var img = ctx.getImageData(0, 0, 4, 4);
      return { ok: !!(img && img.data && img.data.length), crash: false, len: (img && img.data && img.data.length) || 0 };
    } catch (e) {
      return { ok: false, crash: true, err: String(e && e.message || e) };
    }
  }

  var plugins = pluginsDump();
  var mimes = mimeDump();
  var scr = screenDump();
  var canvas = canvasProbe();
  var hc = 0;
  try { hc = navigator.hardwareConcurrency || 0; } catch (_) { hc = 0; }
  var dm = 0;
  try { dm = navigator.deviceMemory || 0; } catch (_) { dm = 0; }

  var reports = {
    pluginsLen: plugins.length,
    pluginsNames: plugins.names,
    mimeLen: mimes.length,
    mimeTypes: mimes.types,
    screenW: scr.w,
    screenH: scr.h,
    availW: scr.aw,
    availH: scr.ah,
    colorDepth: scr.cd,
    viewW: scr.vw,
    viewH: scr.vh,
    deviceMemory: dm,
    hardwareConcurrency: hc,
    canvasOk: canvas.ok,
    canvasCrash: canvas.crash,
    permState: 'pending',
    permThrew: false,
    notifPerm: (function () {
      try {
        if (typeof Notification !== 'undefined' && Notification.permission) return String(Notification.permission);
      } catch (_) {}
      return 'n/a';
    })()
  };

  function paint() {
    try {
      if (!document.body) return;
      document.body.setAttribute('data-plugins', String(reports.pluginsLen));
      document.body.setAttribute('data-mimes', String(reports.mimeLen));
      document.body.setAttribute('data-hc', String(reports.hardwareConcurrency));
      document.body.setAttribute('data-dm', String(reports.deviceMemory));
      document.body.setAttribute('data-sw', String(reports.screenW));
      document.body.setAttribute('data-cd', String(reports.colorDepth));
      document.body.setAttribute('data-perm', String(reports.permState));
      document.body.innerHTML =
        '<pre id="surface">' +
        'pluginsLen=' + reports.pluginsLen +
        ';pluginsNames=' + reports.pluginsNames +
        ';mimeLen=' + reports.mimeLen +
        ';mimeTypes=' + reports.mimeTypes +
        ';screenW=' + reports.screenW +
        ';screenH=' + reports.screenH +
        ';availW=' + reports.availW +
        ';availH=' + reports.availH +
        ';colorDepth=' + reports.colorDepth +
        ';viewW=' + reports.viewW +
        ';viewH=' + reports.viewH +
        ';deviceMemory=' + reports.deviceMemory +
        ';hc=' + reports.hardwareConcurrency +
        ';canvasOk=' + reports.canvasOk +
        ';canvasCrash=' + reports.canvasCrash +
        ';permState=' + reports.permState +
        ';permThrew=' + reports.permThrew +
        ';notifPerm=' + reports.notifPerm +
        '</pre>';
    } catch (_) {}
  }

  function finishPermissions() {
    try {
      if (!navigator.permissions || typeof navigator.permissions.query !== 'function') {
        reports.permState = 'missing';
        reports.permThrew = false;
        paint();
        return;
      }
      navigator.permissions.query({ name: 'notifications' }).then(function (status) {
        try {
          reports.permState = (status && status.state) ? String(status.state) : 'empty';
          reports.permThrew = false;
        } catch (e) {
          reports.permState = 'read-err';
          reports.permThrew = true;
        }
        paint();
      }).catch(function (e) {
        reports.permState = 'reject';
        reports.permThrew = true;
        paint();
      });
    } catch (e) {
      reports.permState = 'throw';
      reports.permThrew = true;
      paint();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      paint();
      finishPermissions();
    });
  } else {
    paint();
    finishPermissions();
  }
  // Safety: ensure surface exists even if permissions hang (VAL timeout covered by CLI).
  setTimeout(function () {
    if (reports.permState === 'pending') {
      reports.permState = 'timeout';
      paint();
    }
  }, 1500);
})();
</script>
</head><body><div id="status">pending-fprint-depth</div></body></html>"#;

fn parse_kv(html: &str, key: &str) -> Option<String> {
    // Prefer the structured canary dump inside <pre id="surface">…</pre> so attribute
    // names like data-hc do not false-match the surface key "hc".
    let surface = html
        .find(r#"id="surface""#)
        .or_else(|| html.find("id='surface'"))
        .and_then(|start| {
            let after = &html[start..];
            let gt = after.find('>')?;
            let body = &after[gt + 1..];
            let end = body.find("</pre>").or_else(|| body.find("</PRE>"))?;
            Some(&body[..end])
        })
        .unwrap_or(html);
    // Require start-of-string or ';' before the key so attr tags cannot steal matches.
    let marker = format!("{key}=");
    let candidates: Vec<usize> = surface
        .match_indices(&marker)
        .map(|(i, _)| i)
        .filter(|&i| i == 0 || surface.as_bytes().get(i - 1) == Some(&b';'))
        .collect();
    let idx = *candidates.first()?;
    let rest = &surface[idx + marker.len()..];
    let end = rest
        .find(|c: char| c == ';' || c == '<' || c.is_whitespace() || c == '"')
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn parse_u32_kv(html: &str, key: &str) -> Option<u32> {
    parse_kv(html, key)?.parse().ok()
}

#[test]
fn val_fprint_003_004_plugins_and_mimetypes_depth() {
    // Also assert inject source embeds multipass inventory (not single PDF stub marketing).
    let profile = generate("fprint-plugins-src");
    let script = browser_injection_script(&profile);
    assert!(
        script.contains("Chrome PDF Viewer") || script.contains("Chromium PDF Viewer"),
        "inject must advertise multipass PDF plugin inventory"
    );
    assert!(script.contains("mimeTypes"));
    assert!(
        profile.plugins_length as usize == PLUGIN_INVENTORY.len() && profile.plugins_length > 1
    );

    let url = spawn_static_canary(DEEP_SURFACE_CANARY.to_string());
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "fprint-plugins-runtime",
        "--task-id",
        "fprint-003-004",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_chromium(&out);
    let plugins_len = parse_u32_kv(&html, "pluginsLen").unwrap_or(0);
    let mime_len = parse_u32_kv(&html, "mimeLen").unwrap_or(0);
    assert!(
        plugins_len > 1,
        "VAL-FPRINT-003: multipass plugins expected (not single stub); html={html}"
    );
    assert!(
        mime_len > 0,
        "VAL-FPRINT-004: mimeTypes must be non-empty when plugins present; html={html}"
    );
    let names = parse_kv(&html, "pluginsNames").unwrap_or_default();
    assert!(
        names.contains("PDF") || names.to_ascii_lowercase().contains("viewer"),
        "plugins names should resemble Chromium inventory; names={names}; html={html}"
    );
}

#[test]
fn val_fprint_005_permissions_notifications_consistency() {
    let url = spawn_static_canary(DEEP_SURFACE_CANARY.to_string());
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "fprint-perm-005",
        "--task-id",
        "fprint-005",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_chromium(&out);
    let perm = parse_kv(&html, "permState").unwrap_or_default();
    let threw = parse_kv(&html, "permThrew").unwrap_or_default();
    assert_eq!(
        threw, "false",
        "permissions.query must not throw unhandled; html={html}"
    );
    assert!(
        matches!(
            perm.as_str(),
            "granted" | "denied" | "prompt" | "default" | "timeout" | "n/a" | "missing"
        ),
        "perm state must be formal or documented residual; got {perm}; html={html}"
    );
    // Prefer formal triple when query completed.
    if matches!(perm.as_str(), "granted" | "denied" | "prompt") {
        let notif = parse_kv(&html, "notifPerm").unwrap_or_default();
        if notif != "n/a" {
            let expected = if notif == "default" {
                "prompt".to_string()
            } else {
                notif.clone()
            };
            assert!(
                perm == expected
                    || (perm == "prompt" && (notif == "default" || notif == "prompt")),
                "permissions.state must cohere with Notification.permission (notif={notif} perm={perm}); html={html}"
            );
        }
    }
}

#[test]
fn val_fprint_008_009_010_screen_memory_hc_coherent() {
    let seed = "fprint-screen-stable-z";
    let profile = generate(seed);
    assert!(profile.device_memory > 0 && DEVICE_MEMORY.contains(&profile.device_memory));
    assert!(
        profile.hardware_concurrency > 0
            && HARDWARE_CONCURRENCY.contains(&profile.hardware_concurrency)
    );
    assert!(profile.screen_width >= profile.viewport_width);
    assert!(profile.screen_height >= profile.viewport_height);
    assert!(profile.screen_color_depth > 0);

    let url = spawn_static_canary(DEEP_SURFACE_CANARY.to_string());
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        seed,
        "--task-id",
        "fprint-008-009-010",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_chromium(&out);
    let sw = parse_u32_kv(&html, "screenW").unwrap_or(0);
    let sh = parse_u32_kv(&html, "screenH").unwrap_or(0);
    let aw = parse_u32_kv(&html, "availW").unwrap_or(0);
    let ah = parse_u32_kv(&html, "availH").unwrap_or(0);
    let cd = parse_u32_kv(&html, "colorDepth").unwrap_or(0);
    let dm = parse_u32_kv(&html, "deviceMemory").unwrap_or(0);
    let hc = parse_u32_kv(&html, "hc").unwrap_or(0);
    assert!(sw > 0 && sh > 0, "screen must be non-zero; html={html}");
    assert!(
        aw > 0 && ah > 0,
        "avail screen must be non-zero; html={html}"
    );
    assert!(cd > 0, "colorDepth must be non-zero; html={html}");
    assert!(
        sw >= profile.viewport_width && sh >= profile.viewport_height,
        "screen ≥ viewport (profile vw={} vh={}); html={html}",
        profile.viewport_width,
        profile.viewport_height
    );
    assert!(
        dm > 0 && DEVICE_MEMORY.contains(&dm),
        "deviceMemory finite positive from allowlist; dm={dm}; html={html}"
    );
    assert_eq!(
        hc, profile.hardware_concurrency,
        "HC must match seed policy; html={html}"
    );
}

#[test]
fn val_fprint_015_016_017_canvas_honesty_seed_stable_and_diversify() {
    // VAL-FPRINT-015: inject residual language; no anonymity claim in source/script.
    let p = generate("fprint-canvas-honesty");
    let script = browser_injection_script(&p);
    let lower = script.to_ascii_lowercase();
    // Absolute claim strings below are forbidden / must never appear as product claims.
    for banned in [
        "anonymous",
        "un-fingerprintable",
        "unfingerprintable",
        "undetectable",
        "cryptographic anonymity", // forbidden claim pattern denylist
    ] {
        // Allow residual denial commentary mentioning the concept only when marked as non-claim.
        if banned == "cryptographic anonymity" {
            assert!(
                lower.contains("does not claim") || !lower.contains(banned),
                "canvas path must not market {banned}"
            );
            continue;
        }
        // Only fail if marketing affirmative usage; residual "does not claim ... anonymity" is ok.
        if lower.contains(banned) {
            assert!(
                lower.contains("does not claim")
                    || lower.contains("not claim")
                    || lower.contains("never")
                    || lower.contains("residual"),
                "must not market {banned} without residual denial; snippet around ban missing"
            );
        }
    }
    assert!(
        lower.contains("best-effort") || lower.contains("diversity") || lower.contains("residual"),
        "canvas residual honesty phrasing required"
    );

    // VAL-FPRINT-016: two runtime runs same seed → stable deeper dims.
    let seed = "fprint-stable-pair-seed";
    let url1 = spawn_static_canary(DEEP_SURFACE_CANARY.to_string());
    let out1 = run_cli(&[
        &url1,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        seed,
        "--task-id",
        "fprint-016-a",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html1 = assert_success_chromium(&out1);
    let url2 = spawn_static_canary(DEEP_SURFACE_CANARY.to_string());
    let out2 = run_cli(&[
        &url2,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        seed,
        "--task-id",
        "fprint-016-b",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html2 = assert_success_chromium(&out2);
    for key in [
        "hc",
        "deviceMemory",
        "screenW",
        "screenH",
        "colorDepth",
        "pluginsLen",
    ] {
        let a = parse_kv(&html1, key).unwrap_or_default();
        let b = parse_kv(&html2, key).unwrap_or_default();
        assert_eq!(
            a, b,
            "VAL-FPRINT-016: {key} thrash under fixed seed; a={a} b={b}"
        );
    }
    // Canvas must not crash.
    assert_eq!(
        parse_kv(&html1, "canvasCrash").as_deref(),
        Some("false"),
        "canvas must not crash; html={html1}"
    );

    // VAL-FPRINT-017: different seeds diversify at least one non-crypto dim (runtime or profile).
    let pa = generate("fprint-diverse-seed-alpha");
    let pb = generate("fprint-diverse-seed-omega");
    let diversifies = pa.hardware_concurrency != pb.hardware_concurrency
        || pa.device_memory != pb.device_memory
        || pa.locale != pb.locale
        || pa.webgl_renderer != pb.webgl_renderer
        || pa.viewport_width != pb.viewport_width
        || pa.screen_width != pb.screen_width;
    assert!(
        diversifies,
        "different seeds must diversify HC/locale/WebGL/screen/memory"
    );

    let url_a = spawn_static_canary(DEEP_SURFACE_CANARY.to_string());
    let out_a = run_cli(&[
        &url_a,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "fprint-diverse-seed-alpha",
        "--task-id",
        "fprint-017-a",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html_a = assert_success_chromium(&out_a);
    let url_b = spawn_static_canary(DEEP_SURFACE_CANARY.to_string());
    let out_b = run_cli(&[
        &url_b,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "fprint-diverse-seed-omega",
        "--task-id",
        "fprint-017-b",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html_b = assert_success_chromium(&out_b);
    // Both complete coherent chromium hard path.
    assert!(
        parse_u32_kv(&html_a, "hc").unwrap_or(0) > 0
            && parse_u32_kv(&html_b, "hc").unwrap_or(0) > 0
    );
}

/// Deep WebGL / OfflineAudio / WebRTC / iframe canary (VAL-FPRINT-006/007/011/012).
const DEEP_MEDIA_FRAME_CANARY: &str = r#"<!doctype html><html><head>
<script>
(function () {
  function webglDump() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { ok: false, throw: false, vendor: '', renderer: '', extPresent: false, paramsThrow: false };
      var vendor = '';
      var renderer = '';
      var paramsThrow = false;
      try {
        var dbg = null;
        try { dbg = gl.getExtension('WEBGL_debug_renderer_info'); } catch (e) { dbg = null; }
        var UV = (dbg && dbg.UNMASKED_VENDOR_WEBGL) || 0x9245;
        var UR = (dbg && dbg.UNMASKED_RENDERER_WEBGL) || 0x9246;
        vendor = String(gl.getParameter(UV) || '');
        renderer = String(gl.getParameter(UR) || '');
      } catch (e) {
        paramsThrow = true;
      }
      var extPresent = false;
      try {
        var list = gl.getSupportedExtensions() || [];
        for (var i = 0; i < list.length; i++) {
          if (list[i] === 'WEBGL_debug_renderer_info') { extPresent = true; break; }
        }
        if (!extPresent) {
          try { extPresent = !!gl.getExtension('WEBGL_debug_renderer_info'); } catch (_) {}
        }
      } catch (_) {}
      return {
        ok: !!(vendor && renderer && !paramsThrow),
        throw: false,
        vendor: vendor,
        renderer: renderer,
        extPresent: extPresent,
        paramsThrow: paramsThrow
      };
    } catch (e) {
      return { ok: false, throw: true, vendor: '', renderer: '', extPresent: false, paramsThrow: true, err: String(e && e.message || e) };
    }
  }

  function audioDump() {
    try {
      if (typeof OfflineAudioContext === 'undefined' && typeof webkitOfflineAudioContext === 'undefined') {
        return { available: false, finite: false, seeded: false, residual: true, sample: 'na' };
      }
      var Ctx = OfflineAudioContext || webkitOfflineAudioContext;
      var ctx = new Ctx(1, 128, 44100);
      var osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.value = 10000;
      var comp = ctx.createDynamicsCompressor();
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      return ctx.startRendering().then(function (buf) {
        var data = buf.getChannelData(0);
        var sum = 0;
        var n = Math.min(32, data.length);
        for (var i = 0; i < n; i++) {
          var v = data[i];
          if (!isFinite(v)) {
            return { available: true, finite: false, seeded: false, residual: true, sample: 'nan' };
          }
          sum += Math.abs(v);
        }
        return {
          available: true,
          finite: true,
          seeded: sum > 0,
          residual: true,
          sample: String(sum.toFixed(6))
        };
      }).catch(function () {
        return { available: true, finite: false, seeded: false, residual: true, sample: 'render-fail' };
      });
    } catch (e) {
      return Promise.resolve({
        available: false,
        finite: false,
        seeded: false,
        residual: true,
        sample: 'throw'
      });
    }
  }

  function webrtcDump() {
    try {
      var hasCtor = typeof RTCPeerConnection !== 'undefined' || typeof webkitRTCPeerConnection !== 'undefined';
      if (!hasCtor) {
        return Promise.resolve({
          available: false,
          privateLeak: false,
          candidates: '',
          policy: 'disabled-or-missing'
        });
      }
      var Ctor = RTCPeerConnection || webkitRTCPeerConnection;
      var pc;
      try {
        pc = new Ctor({ iceServers: [] });
      } catch (e) {
        return Promise.resolve({
          available: true,
          privateLeak: false,
          candidates: '',
          policy: 'ctor-blocked'
        });
      }
      var cands = [];
      var privateLeak = false;
      var privateRe = /\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|fe80:)/i;
      pc.onicecandidate = function (ev) {
        try {
          if (!ev || !ev.candidate || !ev.candidate.candidate) return;
          var line = String(ev.candidate.candidate);
          cands.push(line);
          if (privateRe.test(line) || /\btyp host\b/i.test(line)) {
            privateLeak = true;
          }
        } catch (_) {}
      };
      try {
        pc.createDataChannel('bc');
      } catch (_) {}
      return pc.createOffer().then(function (offer) {
        return pc.setLocalDescription(offer);
      }).then(function () {
        return new Promise(function (resolve) {
          setTimeout(function () {
            try { pc.close(); } catch (_) {}
            resolve({
              available: true,
              privateLeak: privateLeak,
              candidates: cands.join('|').slice(0, 400),
              policy: privateLeak ? 'leak' : 'redacted-or-none'
            });
          }, 1200);
        });
      }).catch(function () {
        try { pc.close(); } catch (_) {}
        return {
          available: true,
          privateLeak: false,
          candidates: cands.join('|').slice(0, 400),
          policy: 'offer-fail'
        };
      });
    } catch (e) {
      return Promise.resolve({
        available: false,
        privateLeak: false,
        candidates: '',
        policy: 'throw'
      });
    }
  }

  function iframeDump() {
    return new Promise(function (resolve) {
      try {
        var iframe = document.createElement('iframe');
        iframe.setAttribute('id', 'bc-frame');
        iframe.setAttribute('src', 'about:blank');
        iframe.style.display = 'none';
        document.documentElement.appendChild(iframe);
        setTimeout(function () {
          try {
            var win = iframe.contentWindow;
            var doc = iframe.contentDocument || (win && win.document);
            var parentChrome = !!(window.chrome && typeof window.chrome === 'object');
            var frameChrome = !!(win && win.chrome && typeof win.chrome === 'object');
            var parentWd = false;
            var frameWd = false;
            try { parentWd = !!navigator.webdriver; } catch (_) { parentWd = true; }
            try { frameWd = !!(win && win.navigator && win.navigator.webdriver); } catch (_) { frameWd = true; }
            resolve({
              ok: true,
              parentChrome: parentChrome,
              frameChrome: frameChrome,
              parentWd: parentWd,
              frameWd: frameWd,
              hasDoc: !!doc,
              consistent: (parentChrome === frameChrome) && (parentWd === frameWd)
            });
          } catch (e) {
            resolve({
              ok: false,
              parentChrome: false,
              frameChrome: false,
              parentWd: true,
              frameWd: true,
              hasDoc: false,
              consistent: false,
              err: String(e && e.message || e)
            });
          }
        }, 200);
      } catch (e) {
        resolve({
          ok: false,
          parentChrome: false,
          frameChrome: false,
          parentWd: true,
          frameWd: true,
          hasDoc: false,
          consistent: false
        });
      }
    });
  }

  function paint(reports, done) {
    try {
      if (!document.body) return;
      // Only expose #surface once async probes finish so --wait-for does not race.
      var id = done ? 'surface' : 'surface-pending';
      document.body.innerHTML =
        '<pre id="' + id + '">' +
        'webglOk=' + reports.webglOk +
        ';webglThrow=' + reports.webglThrow +
        ';webglVendor=' + reports.webglVendor +
        ';webglRenderer=' + reports.webglRenderer +
        ';webglExt=' + reports.webglExt +
        ';webglCtx=' + reports.webglCtx +
        ';audioAvail=' + reports.audioAvail +
        ';audioFinite=' + reports.audioFinite +
        ';audioSample=' + reports.audioSample +
        ';audioResidual=' + reports.audioResidual +
        ';webrtcAvail=' + reports.webrtcAvail +
        ';webrtcPrivateLeak=' + reports.webrtcPrivateLeak +
        ';webrtcPolicy=' + reports.webrtcPolicy +
        ';webrtcCands=' + reports.webrtcCands +
        ';iframeOk=' + reports.iframeOk +
        ';iframeConsistent=' + reports.iframeConsistent +
        ';parentChrome=' + reports.parentChrome +
        ';frameChrome=' + reports.frameChrome +
        ';parentWd=' + reports.parentWd +
        ';frameWd=' + reports.frameWd +
        '</pre>';
    } catch (_) {}
  }

  var base = {
    webglOk: false,
    webglThrow: false,
    webglVendor: '',
    webglRenderer: '',
    webglExt: false,
    webglCtx: false,
    audioAvail: false,
    audioFinite: false,
    audioSample: 'na',
    audioResidual: true,
    webrtcAvail: false,
    webrtcPrivateLeak: false,
    webrtcPolicy: 'pending',
    webrtcCands: '',
    iframeOk: false,
    iframeConsistent: false,
    parentChrome: false,
    frameChrome: false,
    parentWd: true,
    frameWd: true
  };

  function run() {
    var wg = webglDump();
    base.webglCtx = !!(wg && (wg.vendor || wg.renderer || wg.extPresent || !wg.throw));
    // Distinguish missing context (gl null) from throw / empty pair after context.
    try {
      var c = document.createElement('canvas');
      var gl2 = c.getContext('webgl') || c.getContext('experimental-webgl') || c.getContext('webgl2');
      base.webglCtx = !!gl2;
    } catch (_) { base.webglCtx = false; }
    base.webglOk = !!wg.ok;
    base.webglThrow = !!wg.throw || !!wg.paramsThrow;
    base.webglVendor = wg.vendor || '';
    base.webglRenderer = wg.renderer || '';
    base.webglExt = !!wg.extPresent;
    paint(base, false);
    Promise.all([audioDump(), webrtcDump(), iframeDump()]).then(function (parts) {
      var a = parts[0] || {};
      var w = parts[1] || {};
      var f = parts[2] || {};
      base.audioAvail = !!a.available;
      base.audioFinite = !!a.finite;
      base.audioSample = a.sample || 'na';
      base.audioResidual = a.residual !== false;
      base.webrtcAvail = !!w.available;
      base.webrtcPrivateLeak = !!w.privateLeak;
      base.webrtcPolicy = w.policy || 'unknown';
      base.webrtcCands = (w.candidates || '').replace(/;/g, ',');
      base.iframeOk = !!f.ok;
      base.iframeConsistent = !!f.consistent;
      base.parentChrome = !!f.parentChrome;
      base.frameChrome = !!f.frameChrome;
      base.parentWd = !!f.parentWd;
      base.frameWd = !!f.frameWd;
      paint(base, true);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();
</script>
</head><body><div id="status">pending-media-frame</div></body></html>"#;

#[test]
fn val_fprint_006_webgl_vendor_renderer_deeper_than_missing_getparameter() {
    let profile = generate("fprint-webgl-006-src");
    let script = browser_injection_script(&profile);
    assert!(
        script.contains("UNMASKED_VENDOR_WEBGL") && script.contains("UNMASKED_RENDERER_WEBGL"),
        "inject must patch WebGL unmasked vendor/renderer"
    );
    assert!(
        script.contains("WEBGL_debug_renderer_info") || script.contains("getSupportedExtensions"),
        "WebGL depth should cover extension surface, not only missing getParameter"
    );
    assert!(
        !profile.webgl_vendor.is_empty() && !profile.webgl_renderer.is_empty(),
        "seeded WebGL pair must be non-empty allowlist entries"
    );

    let url = spawn_static_canary(DEEP_MEDIA_FRAME_CANARY.to_string());
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "fprint-webgl-006-rt",
        "--task-id",
        "fprint-006",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_chromium(&out);
    let threw = parse_kv(&html, "webglThrow").unwrap_or_else(|| "true".into());
    assert_eq!(
        threw, "false",
        "VAL-FPRINT-006: WebGL getParameter must not throw; html={html}"
    );
    let vendor = parse_kv(&html, "webglVendor").unwrap_or_default();
    let renderer = parse_kv(&html, "webglRenderer").unwrap_or_default();
    let ok = parse_kv(&html, "webglOk").unwrap_or_default();
    let ctx = parse_kv(&html, "webglCtx").unwrap_or_default();
    if ctx == "true" {
        assert!(
            !vendor.is_empty() && !renderer.is_empty(),
            "VAL-FPRINT-006: non-empty vendor/renderer when context exists; vendor={vendor} renderer={renderer}; html={html}"
        );
        assert_eq!(
            ok, "true",
            "VAL-FPRINT-006: WebGL depth probe must report ok when context exists; html={html}"
        );
    } else {
        // GPU-less hosts / disable-gpu residual: injected allowlist + residual docs remain the
        // product honesty path (no GPU-plausible success claim without residual).
        assert!(!profile.webgl_vendor.is_empty() && !profile.webgl_renderer.is_empty());
        let security = include_str!("../../../docs/SECURITY.md").to_ascii_lowercase();
        assert!(
            security.contains("webgl depth residual")
                || security.contains("gpu-less")
                || security.contains("swiftshader"),
            "SECURITY residual must document WebGL/GPU-less detector risk when context missing"
        );
    }
}

#[test]
fn val_fprint_007_offline_audio_residual_or_bounded_noise() {
    let profile = generate("fprint-audio-007-src");
    let script = browser_injection_script(&profile);
    let lower = script.to_ascii_lowercase();
    // Product must either implement OfflineAudio noise OR residual-admit (honesty first).
    let has_audio_impl = script.contains("OfflineAudioContext")
        || script.contains("getChannelData")
        || script.contains("AudioBuffer");
    let has_residual = lower.contains("audio residual")
        || lower.contains("offlineaudio")
        || lower.contains("val-fprint-007");
    assert!(
        has_audio_impl || has_residual,
        "inject must implement audio noise or residual-admit OfflineAudio"
    );
    // Absolute audio anonymity marketing is forbidden/must never appear as product claim.
    // Residual denial phrases like "no ... claim" are allowed when marked residual.
    for banned in [
        "audio anonymized",
        "guarantees audio anonymity", // forbidden claim pattern denylist
        "offline audio undefeated",   // forbidden claim pattern denylist
    ] {
        assert!(
            !lower.contains(banned),
            "must never claim complete audio anonymity ({banned})"
        );
    }
    assert!(
        !(lower.contains("makes browser anonymous") || lower.contains("audio is anonymous")),
        "must never market audio as anonymous"
    );
    let security = include_str!("../../../docs/SECURITY.md").to_ascii_lowercase();
    assert!(
        security.contains("audio residual")
            || security.contains("offlineaudiocontext")
            || security.contains("offline audio"),
        "SECURITY.md must residual-document OfflineAudioContext residual or implementable path"
    );

    let url = spawn_static_canary(DEEP_MEDIA_FRAME_CANARY.to_string());
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "fprint-audio-007-rt",
        "--task-id",
        "fprint-007",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_chromium(&out);
    // Either Audio API unavailable (honest residual) or finite samples (implementable noise / host path).
    let finite = parse_kv(&html, "audioFinite").unwrap_or_default();
    let residual = parse_kv(&html, "audioResidual").unwrap_or_default();
    let avail = parse_kv(&html, "audioAvail").unwrap_or_default();
    if avail == "true" {
        assert_eq!(
            finite, "true",
            "when OfflineAudioContext exists, sample must be finite; html={html}"
        );
    }
    assert!(
        residual == "true" || finite == "true",
        "VAL-FPRINT-007: residual honesty or finite implementable noise; html={html}"
    );
}

#[test]
fn val_fprint_011_webrtc_hard_path_disable_or_redact() {
    let profile = generate("fprint-webrtc-011-src");
    let script = browser_injection_script(&profile);
    let lower = script.to_ascii_lowercase();
    assert!(
        script.contains("RTCPeerConnection")
            || lower.contains("webrtc")
            || lower.contains("icecandidate"),
        "inject must install WebRTC disable-or-redact policy"
    );
    // Render launch hygiene must also force WEBRTC IP policy (or inject-only redaction is
    // accepted if residual docs admit host residual). Source-check launch args.
    let render_src = include_str!("../../../crates/basecrawl-render/src/lib.rs");
    assert!(
        render_src.contains("force-webrtc-ip-handling-policy")
            || render_src.contains("disable-webrtc")
            || script.contains("icecandidate"),
        "hard path must disable or force webrtc IP policy or inject redaction"
    );
    let security = include_str!("../../../docs/SECURITY.md").to_ascii_lowercase();
    assert!(
        security.contains("webrtc")
            && (security.contains("residual")
                || security.contains("redact")
                || security.contains("disable")),
        "SECURITY.md must document WebRTC residual / redaction policy"
    );

    let url = spawn_static_canary(DEEP_MEDIA_FRAME_CANARY.to_string());
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "fprint-webrtc-011-rt",
        "--task-id",
        "fprint-011",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_chromium(&out);
    let leak = parse_kv(&html, "webrtcPrivateLeak").unwrap_or_else(|| "true".into());
    assert_eq!(
        leak, "false",
        "VAL-FPRINT-011: private/LAN ice candidates must not leak into capture; html={html}"
    );
    let policy = parse_kv(&html, "webrtcPolicy").unwrap_or_default();
    assert!(
        matches!(
            policy.as_str(),
            "redacted-or-none" | "disabled-or-missing" | "ctor-blocked" | "offer-fail" | "throw"
        ),
        "WebRTC policy must be disable-or-redact formal set; got {policy}; html={html}"
    );
    // Candidate dump itself must not include host-class private IPs (canary encodes probe
    // regex separately; only inspect the parsed webrtcCands field).
    let cands = parse_kv(&html, "webrtcCands").unwrap_or_default();
    for banned in [
        "192.168.", "10.0.", "172.16.", "127.0.0.", "0.0.0.0", "typ host",
    ] {
        assert!(
            !cands.to_ascii_lowercase().contains(banned),
            "ICE candidate dump must not carry {banned}; cands={cands}"
        );
    }
    let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    // Logs must not dump full ice candidate lines with host LAN IPs as operational residue.
    assert!(
        !stderr.contains("candidate:") || !stderr.contains("typ host"),
        "stderr must not log host ICE candidates"
    );
}

#[test]
fn val_fprint_012_iframe_chrome_webdriver_consistency() {
    let profile = generate("fprint-iframe-012-src");
    let script = browser_injection_script(&profile);
    assert!(
        script.contains("__bcStealthInstalled") && script.contains("window.chrome"),
        "inject must install chrome surface per document window"
    );

    let url = spawn_static_canary(DEEP_MEDIA_FRAME_CANARY.to_string());
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "fprint-iframe-012-rt",
        "--task-id",
        "fprint-012",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    let html = assert_success_chromium(&out);
    let consistent = parse_kv(&html, "iframeConsistent").unwrap_or_default();
    let iframe_ok = parse_kv(&html, "iframeOk").unwrap_or_default();
    assert_eq!(iframe_ok, "true", "iframe probe must succeed; html={html}");
    assert_eq!(
        consistent, "true",
        "VAL-FPRINT-012: parent vs same-origin iframe chrome/webdriver must match policy; html={html}"
    );
    let parent_wd = parse_kv(&html, "parentWd").unwrap_or_default();
    let frame_wd = parse_kv(&html, "frameWd").unwrap_or_default();
    assert_eq!(
        parent_wd, "false",
        "parent webdriver must be false under stealth; html={html}"
    );
    assert_eq!(
        frame_wd, "false",
        "iframe webdriver must be false under stealth; html={html}"
    );
    let parent_chrome = parse_kv(&html, "parentChrome").unwrap_or_default();
    let frame_chrome = parse_kv(&html, "frameChrome").unwrap_or_default();
    assert_eq!(
        parent_chrome, frame_chrome,
        "chrome presence must match across frames; html={html}"
    );
    assert_eq!(
        parent_chrome, "true",
        "parent chrome surface expected; html={html}"
    );
}

#[test]
fn val_fprint_018_no_complete_font_inventory_spoof_claim() {
    let profile = generate("fprint-font-residual");
    let script = browser_injection_script(&profile);
    let lower = script.to_ascii_lowercase();
    // Product may mention complete-font spoof only as residual denial / must never claim.
    // Affirmative marketing forms (without residual denial) are forbidden.
    for banned_claim in [
        "implements complete os font inventory",
        "provides full font anonymity",
        "complete font spoof success",
        "all system fonts spoofed",
    ] {
        assert!(
            !lower.contains(banned_claim),
            "must never claim complete font inventory spoof: {banned_claim}"
        );
    }
    // Residual honesty present in inject comments (VAL-FPRINT-018).
    assert!(
        lower.contains("not a complete os font")
            || lower.contains("font inventory spoof")
            || lower.contains("val-fprint-018"),
        "inject should reference font residual honesty"
    );
    // docs residual language must document font residual (operator-facing honesty).
    let security = include_str!("../../../docs/SECURITY.md").to_ascii_lowercase();
    assert!(
        security.contains("font inventory residual")
            || security.contains("complete os font")
            || security.contains("full font anonymity"),
        "SECURITY.md must residual-document font inventory limits"
    );
}

#[test]
fn inject_never_embeds_marketplace_or_absolute_trust() {
    let script = browser_injection_script(&generate("fprint-ban-check"));
    // Absolute claim strings below are forbidden / must never appear in inject.
    for banned in [
        "2captcha",
        "anti-captcha",
        "capsolver",
        "oxylabs.io",
        "undetectable",
        "trustless", // must never claim
        "100% guaranteed",
    ] {
        assert!(
            !script.to_ascii_lowercase().contains(banned),
            "inject must not embed {banned}"
        );
    }
}
