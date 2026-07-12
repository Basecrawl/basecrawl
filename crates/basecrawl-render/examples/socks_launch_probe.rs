//! Manual probe for sealed SOCKS Chromium launch (not part of the focused suite).
use std::ffi::OsStr;
use std::time::{Duration, Instant};

fn main() {
    let proxy = basecrawl_seal::SealedSocksProxy::start_doh().expect("socks");
    let proxy_server = proxy.proxy_server_arg();
    println!("proxy={proxy_server}");
    let chrome = std::path::PathBuf::from("/usr/bin/google-chrome-stable");
    let args = [
        OsStr::new("--disable-dev-shm-usage"),
        OsStr::new("--disable-gpu"),
        OsStr::new("--proxy-bypass-list=127.0.0.1;localhost;::1"),
    ];
    let mut builder = headless_chrome::LaunchOptions::default_builder();
    builder
        .path(Some(chrome))
        .headless(true)
        .sandbox(false)
        .window_size(Some((800, 600)))
        .proxy_server(Some(proxy_server.as_str()))
        .args(args.to_vec())
        .idle_browser_timeout(Duration::from_secs(12));
    let options = builder.build().unwrap();
    let t0 = Instant::now();
    let browser = headless_chrome::Browser::new(options).expect("browser");
    let _tab = browser.new_tab().expect("tab");
    println!("browser+tab ok in {:?}", t0.elapsed());
}
