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

const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS Access Key", "AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", "wJalrXUt[0-9A-Za-z/+]{36}"),
    ("Google API Key", "AIza[0-9A-Za-z\\-_]{35}"),
    ("GitHub Token", "gh[ps]_[0-9A-Za-z]{36}"),
    ("GitHub Token (old)", "ghp_[0-9A-Za-z]{36}"),
    ("Slack Token", "xox[baprs]-[0-9A-Za-z-]{10,48}"),
    ("Stripe Key", "sk_live_[0-9A-Za-z]{24,99}"),
    ("Stripe Key (test)", "sk_test_[0-9A-Za-z]{24,99}"),
    (
        "Generic API Key",
        "api[_-]?key[\"']?\\s*[:=]\\s*[\"']?[0-9A-Za-z\\-_]{20,}",
    ),
    ("Bearer Token", "Bearer\\s+[0-9A-Za-z\\-._~+/]+=*"),
    (
        "JWT Token",
        "eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+",
    ),
    (
        "Private Key",
        "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ),
    ("MongoDB URI", "mongodb(\\+srv)?://[^\\s]+"),
    ("PostgreSQL URI", "postgres(ql)?://[^\\s]+"),
    ("MySQL URI", "mysql://[^\\s]+"),
    ("Redis URI", "redis://[^\\s]+"),
    (
        "Generic Secret",
        "secret[\"']?\\s*[:=]\\s*[\"']?[0-9A-Za-z\\-_]{16,}",
    ),
    ("Password", "password[\"']?\\s*[:=]\\s*[\"']?[^\"'\\s]{8,}"),
    (
        "Client Secret",
        "client[_-]secret[\"']?\\s*[:=]\\s*[\"']?[0-9A-Za-z\\-_]{20,}",
    ),
    ("OAuth Token", "ya29\\.[0-9A-Za-z\\-_]+"),
    ("Twilio Key", "SK[0-9a-fA-F]{32}"),
    ("Square Key", "sq0atp-[0-9A-Za-z\\-_]{22}"),
    ("Mailgun Key", "key-[0-9a-zA-Z]{32}"),
];

pub async fn js(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} JavaScript Secret Hunter", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!(
        "{} {} secret patterns",
        "[*]".cyan().bold(),
        SECRET_PATTERNS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    // Find JS file references
    let js_urls: Vec<&str> = body
        .matches("src=\"")
        .map(|m| {
            let start = m.as_ptr() as usize - body.as_ptr() as usize + 5;
            let end = body[start..].find('"').map(|e| start + e).unwrap_or(start);
            &body[start..end]
        })
        .filter(|s| s.ends_with(".js"))
        .collect();

    println!(
        "{} Found {} JS file(s) in page",
        "[*]".cyan().bold(),
        js_urls.len()
    );

    let mut all_secrets = Vec::new();
    // Scan main page
    scan_text(&body, "main page", &mut all_secrets);
    // Scan each JS file
    for js_url in &js_urls {
        let full_url = if js_url.starts_with("http") {
            js_url.to_string()
        } else if js_url.starts_with("/") {
            format!("{}{}", url.trim_end_matches('/'), js_url)
        } else {
            format!("{}/{}", url.trim_end_matches('/'), js_url)
        };
        if let Ok(r) = client.get(&full_url).send().await {
            let js_body = r.text().await.unwrap_or_default();
            scan_text(&js_body, js_url, &mut all_secrets);
        }
    }

    if all_secrets.is_empty() {
        println!("\n{} No secrets found in JS.", "[-]".green().bold());
    } else {
        println!(
            "\n{} {} secret(s) found:",
            "[!]".red().bold(),
            all_secrets.len()
        );
        for (name, value, source) in &all_secrets {
            println!(
                "  {} {:20} in {} — {}...",
                "*".red(),
                name,
                source,
                value.chars().take(60).collect::<String>()
            );
        }
    }
    Ok(())
}

pub async fn repo(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Repository Secret Scanner", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }
    let resp = req.send().await?;
    let body = resp.text().await?;

    let mut all_secrets = Vec::new();
    scan_text(&body, "repo", &mut all_secrets);

    // Also check common secret file paths
    let secret_files = [
        ".env",
        "config.json",
        "config.yml",
        "settings.py",
        "application.properties",
        "secrets.yaml",
        "credentials.json",
    ];
    for file in &secret_files {
        let file_url = format!("{}/{}", url.trim_end_matches('/'), file);
        let mut req = client.get(&file_url);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        if let Ok(r) = req.send().await
            && r.status().as_u16() == 200
        {
            let content = r.text().await.unwrap_or_default();
            scan_text(&content, file, &mut all_secrets);
        }
    }

    if all_secrets.is_empty() {
        println!("\n{} No secrets found in repository.", "[-]".green().bold());
    } else {
        println!(
            "\n{} {} secret(s) found:",
            "[!]".red().bold(),
            all_secrets.len()
        );
        for (name, value, source) in &all_secrets {
            println!(
                "  {} {:20} in {} — {}...",
                "*".red(),
                name,
                source,
                value.chars().take(60).collect::<String>()
            );
        }
    }
    Ok(())
}

pub async fn response(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} API Response Secret Hunter", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }
    let resp = req.send().await?;
    let headers_str = format!("{:?}", resp.headers());
    let body = resp.text().await?;

    let mut all_secrets = Vec::new();
    scan_text(&body, "API response", &mut all_secrets);

    // Also check response headers
    scan_text(&headers_str, "headers", &mut all_secrets);

    if all_secrets.is_empty() {
        println!(
            "\n{} No secrets found in API response.",
            "[-]".green().bold()
        );
    } else {
        println!(
            "\n{} {} secret(s) found:",
            "[!]".red().bold(),
            all_secrets.len()
        );
        for (name, value, source) in &all_secrets {
            println!(
                "  {} {:20} in {} — {}...",
                "*".red(),
                name,
                source,
                value.chars().take(60).collect::<String>()
            );
        }
    }
    Ok(())
}

pub async fn docker(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Docker Layer Secret Hunter", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let layers = [
        ("Manifest", format!("{}/manifests/latest", url)),
        ("Config", format!("{}/blobs/sha256:config", url)),
        ("Layer 1", format!("{}/blobs/sha256:layer1", url)),
        ("Layer 2", format!("{}/blobs/sha256:layer2", url)),
        ("Layer 3", format!("{}/blobs/sha256:layer3", url)),
    ];

    let mut all_secrets = Vec::new();
    for (name, layer_url) in &layers {
        let mut req = client.get(layer_url);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.send().await {
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                scan_text(&body, name, &mut all_secrets);
            }
            Err(_) => {
                println!("  {} {:15} — error", "*".red(), name);
            }
        }
    }

    if all_secrets.is_empty() {
        println!(
            "\n{} No secrets found in Docker layers.",
            "[-]".green().bold()
        );
    } else {
        println!(
            "\n{} {} secret(s) found in Docker layers:",
            "[!]".red().bold(),
            all_secrets.len()
        );
        for (name, value, source) in &all_secrets {
            println!(
                "  {} {:20} in {} — {}...",
                "*".red(),
                name,
                source,
                value.chars().take(60).collect::<String>()
            );
        }
    }
    Ok(())
}

fn scan_text(text: &str, source: &str, results: &mut Vec<(String, String, String)>) {
    for (name, pattern) in SECRET_PATTERNS {
        if let Ok(regex) = regex::Regex::new(pattern) {
            for m in regex.find_iter(text) {
                let value = m.as_str().to_string();
                if !results.iter().any(|r| r.1 == value) {
                    results.push((name.to_string(), value, source.to_string()));
                }
            }
        }
    }
}
