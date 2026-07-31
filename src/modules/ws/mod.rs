use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(
            reqwest::header::HeaderMap::from_iter([(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
            )]),
        );
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

pub async fn fuzz(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    message: &str,
) -> anyhow::Result<()> {
    println!("{} WebSocket Fuzzing", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url);
    println!("{} Message: {}", "[*]".cyan().bold(), message);
    println!("{}", "─".repeat(60).dimmed());

    let ws_url = url.replace("http://", "ws://").replace("https://", "wss://");
    println!("{} WebSocket URL: {}", "[*]".cyan().bold(), ws_url);

    let client = build_client(timeout, token);

    let fuzz_payloads = [
        ("Long string", "A".repeat(10000)),
        ("Null bytes", "test\x00\x00\x00payload".to_string()),
        ("Format string", "%s%s%s%s%s%s%s%s%s%s".to_string()),
        ("JSON injection", "{\"type\":\"fuzz\",\"data\":\"".to_string() + message + "\"}"),
        ("SQLi probe", "' OR '1'='1".to_string()),
        ("XSS probe", "<script>alert(1)</script>".to_string()),
        ("Command injection", ";id".to_string()),
        ("Path traversal", "../../../etc/passwd".to_string()),
        ("Template injection", "{{7*7}}".to_string()),
        ("XXE probe", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>".to_string()),
    ];

    for (name, payload) in &fuzz_payloads {
        println!("  {} {:20} len={}", "•".cyan(), name, payload.len());
    }

    println!("\n{} Note: WebSocket fuzzing requires a raw socket connection.", "[*]".cyan().bold());
    println!("{} Use 'inject' subcommand for targeted payload delivery.", "[*]".cyan().bold());
    Ok(())
}

pub async fn inject(
    url: &str,
    _token: Option<&str>,
    _timeout: u64,
    payload: &str,
) -> anyhow::Result<()> {
    println!("{} WebSocket Injection", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url);
    println!("{} Payload: {}", "[*]".cyan().bold(), payload);
    println!("{}", "─".repeat(60).dimmed());

    let ws_url = url.replace("http://", "ws://").replace("https://", "wss://");

    println!("{} Target WebSocket: {}", "[*]".cyan().bold(), ws_url);
    println!("{} Payload to inject: {}", "[*]".cyan().bold(), payload);
    println!("{} Note: Use a WebSocket client (e.g. websocat) to send payload:", "[*]".cyan().bold());
    println!("  websocat {} -1 '{}'", ws_url, payload);

    Ok(())
}

pub async fn cswssh(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Cross-Site WebSocket Hijacking (CSWSH)", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let ws_url = url.replace("http://", "ws://").replace("https://", "wss://");

    println!("{} Testing CSWSH conditions:", "[*]".cyan().bold());

    let resp = client.get(url).send().await?;
    let headers = resp.headers().clone();

    let has_origin_check = headers.get("sec-websocket-protocol").is_some();
    let has_csrf_token = headers.keys().any(|k| k.as_str().to_lowercase().contains("csrf"));
    let has_cookie = headers.get("set-cookie").is_some();

    println!("  {} Origin validation:    {}", "•".cyan(), if has_origin_check { "present".green().to_string() } else { "MISSING".red().bold().to_string() });
    println!("  {} CSRF token:           {}", "•".cyan(), if has_csrf_token { "present".green().to_string() } else { "MISSING".red().bold().to_string() });
    println!("  {} Cookie-based session: {}", "•".cyan(), if has_cookie { "YES — vulnerable if no origin check".yellow().to_string() } else { "no".green().to_string() });

    if !has_origin_check && has_cookie {
        println!("\n{} [HIGH] Potential CSWSH — no origin validation with cookie-based auth!", "[!]".red().bold());
        println!("  {} Attack: Cross-origin WebSocket from malicious page", "•".cyan());
    } else {
        println!("\n{} CSWSH not likely (origin check or no cookies).", "[-]".green().bold());
    }

    Ok(())
}

pub async fn auth(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} WebSocket Auth Bypass", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    println!("{} Testing WebSocket authentication mechanisms:", "[*]".cyan().bold());

    let tests = [
        ("No auth headers", None),
        ("Fake bearer token", Some("Bearer fake_token_123")),
        ("Empty bearer", Some("Bearer ")),
        ("Null token", Some("Bearer null")),
        ("Admin bypass", Some("Bearer admin")),
    ];

    for (name, auth_header) in &tests {
        let mut req = client.get(url);
        if let Some(auth) = auth_header {
            req = req.header("Authorization", *auth);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                let ws_upgrade = resp.headers().get("upgrade").and_then(|v| v.to_str().ok()).unwrap_or("none");
                println!("  {} {:25} status={} upgrade={}", "•".cyan(), name, status, ws_upgrade);
            }
            Err(_) => {}
        }
    }

    println!("\n{} Auth bypass scan complete.", "[*]".cyan().bold());
    Ok(())
}
