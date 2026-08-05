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

pub async fn idor(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    start_id: u64,
    count: u64,
) -> anyhow::Result<()> {
    println!("{} IDOR / BOLA Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Start ID: {}", "[*]".cyan().bold(), start_id);
    println!("{} Count:    {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let mut found = Vec::new();
    let mut responses: Vec<(u64, usize, String, String)> = Vec::new();

    for i in 0..count {
        let test_id = start_id + i;
        let test_url = url.replace("{id}", &test_id.to_string());
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();
                let body = resp.text().await.unwrap_or_default();
                let body_len = body.len();
                let is_html = content_type.contains("text/html")
                    || body.trim_start().starts_with("<!doctype")
                    || body.trim_start().starts_with("<html");

                if status.as_u16() == 200 && body_len > 50 && !is_html {
                    println!(
                        "  {} ID={} status={} len={} [ACCESSIBLE]",
                        "*".cyan(),
                        test_id,
                        status,
                        body_len
                    );
                    responses.push((test_id, body_len, body.clone(), content_type));
                } else if status.as_u16() == 200 && is_html {
                    println!(
                        "  {} ID={} status={} len={} [HTML — likely SPA catch-all]",
                        "*".dimmed(),
                        test_id,
                        status,
                        body_len
                    );
                    responses.push((test_id, body_len, body.clone(), content_type));
                } else if status.as_u16() == 403 {
                    println!("  {} ID={} status=403 (forbidden)", "*".dimmed(), test_id);
                } else if status.as_u16() == 404 {
                    println!("  {} ID={} status=404 (not found)", "*".dimmed(), test_id);
                } else if status.as_u16() == 401 {
                    println!(
                        "  {} ID={} status=401 (unauthorized)",
                        "*".dimmed(),
                        test_id
                    );
                } else {
                    println!("  {} ID={} status={}", "*".cyan(), test_id, status);
                }
            }
            Err(_) => {
                println!("  {} ID={} error", "*".red(), test_id);
            }
        }
    }

    // Filter out identical responses (SPA catch-all pattern)
    if !responses.is_empty() {
        let first_body = &responses[0].2;
        let all_identical = responses.iter().all(|(_, _, body, _)| body == first_body);
        if all_identical && responses.len() > 1 {
            println!(
                "\n{} All {} responses are identical ({} bytes) — likely SPA catch-all, not IDOR.",
                "[-]".yellow().bold(),
                responses.len(),
                first_body.len()
            );
        } else {
            for (id, len, body, ct) in &responses {
                if !ct.contains("text/html") && len > &50 {
                    found.push((*id, *len));
                }
            }
        }
    }

    if found.is_empty() {
        println!(
            "\n{} No IDOR detected — all resources properly protected.",
            "[-]".yellow().bold()
        );
    } else {
        println!(
            "\n{} [HIGH] {} resource(s) accessible via IDOR:",
            "[!]".red().bold(),
            found.len()
        );
        for (id, len) in &found {
            println!("  {} ID={} ({} bytes)", "*".red(), id, len);
        }
    }
    Ok(())
}

pub async fn bfla(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} BFLA (Broken Function Level Authorization) Test",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

    for method in &methods {
        let req = match *method {
            "GET" => client.get(url),
            "POST" => client
                .post(url)
                .header("Content-Type", "application/json")
                .body("{}"),
            "PUT" => client
                .put(url)
                .header("Content-Type", "application/json")
                .body("{}"),
            "PATCH" => client
                .patch(url)
                .header("Content-Type", "application/json")
                .body("{}"),
            "DELETE" => client.delete(url),
            "HEAD" => client.head(url),
            "OPTIONS" => client.request(reqwest::Method::OPTIONS, url),
            _ => continue,
        };

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                let allow_header = resp
                    .headers()
                    .get("allow")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let body = resp.text().await.unwrap_or_default();
                let body_len = body.len();
                let allowed = status.as_u16() < 400;
                let status_str = if allowed {
                    "ALLOWED".red().bold().to_string()
                } else {
                    format!("{}", status.as_u16())
                };
                println!(
                    "  {} {:8} status={} len={} {}",
                    "*".cyan(),
                    method,
                    status,
                    body_len,
                    status_str
                );

                if allowed && (*method == "DELETE" || *method == "PUT" || *method == "PATCH") {
                    println!(
                        "    {} [HIGH] Privileged method {} accessible without proper auth!",
                        ">".red().bold(),
                        method
                    );
                }

                if *method == "OPTIONS"
                    && let Some(allow) = allow_header
                {
                    println!("    {} Allow: {}", ">".cyan(), allow);
                }
            }
            Err(_) => {
                println!("  {} {:8} error", "*".cyan(), method);
            }
        }
    }

    println!("\n{} BFLA test complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn privilege(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    low_token: &str,
) -> anyhow::Result<()> {
    println!("{} Privilege Escalation Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client_no_auth = build_client(timeout, None);
    let client_low = build_client(timeout, Some(low_token));
    let client_high = build_client(timeout, token);

    let tests = [
        ("No auth", &client_no_auth),
        ("Low-priv token", &client_low),
        ("High-priv token", &client_high),
    ];

    let mut baseline_len = 0usize;
    let mut baseline_status = 0u16;

    for (name, cli) in &tests {
        match cli.get(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let body_len = body.len();

                if name == &"High-priv token" {
                    baseline_len = body_len;
                    baseline_status = status;
                    println!(
                        "  {} {:20} status={} len={} (baseline)",
                        "*".cyan(),
                        name,
                        status,
                        body_len
                    );
                } else {
                    let matches_baseline = status == baseline_status && body_len == baseline_len;
                    let status_str = if status == 200 && !matches_baseline {
                        "ACCESS GRANTED".red().bold().to_string()
                    } else if status == 200 && matches_baseline {
                        "same as baseline".yellow().to_string()
                    } else {
                        format!("blocked ({})", status)
                    };
                    println!(
                        "  {} {:20} status={} len={} {}",
                        "*".cyan(),
                        name,
                        status,
                        body_len,
                        status_str
                    );

                    if status == 200 && body_len > 50 && !matches_baseline {
                        println!(
                            "    {} [HIGH] Low-priv/no-auth access returns different data!",
                            ">".red().bold()
                        );
                    }
                }
            }
            Err(_) => {
                println!("  {} {:20} error", "*".cyan(), name);
            }
        }
    }

    println!(
        "\n{} Privilege escalation test complete.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn path(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    wordlist: Option<&str>,
) -> anyhow::Result<()> {
    println!("{} Forced Browsing / Path Traversal", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let paths: Vec<String> = if let Some(wl) = wordlist {
        std::fs::read_to_string(wl)?
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![
            "/admin",
            "/admin/",
            "/admin/login",
            "/admin/dashboard",
            "/admin/users",
            "/administrator",
            "/panel",
            "/dashboard",
            "/console",
            "/debug",
            "/internal",
            "/private",
            "/secret",
            "/hidden",
            "/backup",
            "/api/admin",
            "/api/internal",
            "/api/users",
            "/api/config",
            "/api/debug",
            "/config",
            "/configuration",
            "/settings",
            "/env",
            "/environment",
            "/.env",
            "/.git/config",
            "/.git/HEAD",
            "/backup.sql",
            "/dump.sql",
            "/phpinfo.php",
            "/info.php",
            "/test",
            "/dev",
            "/staging",
            "/wp-admin",
            "/wp-login.php",
            "/cms",
            "/manage",
            "/management",
            "/system",
            "/control",
            "/monitor",
            "/status",
            "/health",
            "/v1/admin",
            "/v2/admin",
            "/graphql",
            "/graphiql",
            "/playground",
            "/swagger",
            "/swagger-ui",
            "/api-docs",
            "/openapi",
            "/redoc",
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
            "/server-status",
            "/server-info",
            "/metrics",
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/metrics",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };

    let mut found = Vec::new();

    for path in &paths {
        let test_url = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&test_url).send().await {
            let status = resp.status();
            let body_len = resp.text().await.unwrap_or_default().len();

            if status.as_u16() == 200 && body_len > 0 {
                println!(
                    "  {} {:40} status={} len={} [FOUND]",
                    "*".green(),
                    path,
                    status,
                    body_len
                );
                found.push((path.clone(), status.as_u16(), body_len));
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                println!(
                    "  {} {:40} status={} [PROTECTED]",
                    "*".yellow(),
                    path,
                    status
                );
                found.push((path.clone(), status.as_u16(), body_len));
            } else if status.as_u16() == 301 || status.as_u16() == 302 {
                println!("  {} {:40} status={} [REDIRECT]", "*".cyan(), path, status);
            }
        }
    }

    if found.is_empty() {
        println!("\n{} No interesting paths found.", "[-]".yellow().bold());
    } else {
        println!(
            "\n{} {} interesting path(s) found:",
            "[*]".cyan().bold(),
            found.len()
        );
        for (path, status, len) in &found {
            let tag = if *status == 200 {
                "ACCESSIBLE".green().to_string()
            } else {
                "PROTECTED".yellow().to_string()
            };
            println!(
                "  {} {:40} status={} len={} {}",
                "*".cyan(),
                path,
                status,
                len,
                tag
            );
        }
    }
    Ok(())
}
