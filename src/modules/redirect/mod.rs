use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::limited(10));
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const REDIRECT_PARAMS: &[&str] = &[
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_url",
    "returnUrl",
    "next",
    "next_url",
    "url",
    "target",
    "to",
    "goto",
    "dest",
    "destination",
    "continue",
    "callback",
    "callback_url",
    "redir",
    "redir_url",
    "rurl",
    "out",
    "view",
];

const BYPASS_PAYLOADS: &[&str] = &[
    "https://evil.com",
    "//evil.com",
    "//evil.com/",
    "https:evil.com",
    "https:/evil.com",
    "https://evil.com@example.com",
    "https://example.com@evil.com",
    "//evil%2ecom",
    "//evil%252ecom",
    "https://evil.com\\@example.com",
    "//evil.com\\",
    "/\\evil.com",
    "https://evil.com%23",
    "https://evil.com%00",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
];

pub async fn scan(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Open Redirect Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    for param in REDIRECT_PARAMS {
        for payload in &["https://evil.com", "//evil.com"] {
            let test_url = format!(
                "{}{}{}={}",
                url,
                if url.contains('?') { "&" } else { "?" },
                param,
                payload
            );
            if let Ok(resp) = client.get(&test_url).send().await {
                let status = resp.status();
                if status.is_redirection() {
                    let location = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if location.contains("evil.com") {
                        println!(
                            "{} [HIGH] Open redirect via '{}' param!",
                            "[!]".red().bold(),
                            param
                        );
                        println!("  {} Payload: {}={}", "•".cyan(), param, payload);
                        println!("  {} Redirects to: {}", "•".cyan(), location);
                        return Ok(());
                    }
                }
            }
        }
    }

    println!(
        "{} No open redirect detected with common params.",
        "[-]".yellow().bold()
    );
    Ok(())
}

pub async fn bypass(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Open Redirect Bypass", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    for payload in BYPASS_PAYLOADS {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            payload
        );
        if let Ok(resp) = client.get(&test_url).send().await {
            let status = resp.status();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if status.is_redirection()
                && (location.contains("evil.com") || location.contains("alert"))
            {
                println!("{} [HIGH] Bypass successful!", "[!]".red().bold());
                println!("  {} Payload: {}", "•".cyan(), payload);
                println!("  {} Redirects to: {}", "•".cyan(), location);
            } else {
                println!(
                    "  {} {:40} {} (no redirect to evil)",
                    "•".dimmed(),
                    payload,
                    status
                );
            }
        }
    }

    println!("\n{} Bypass scan complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn chain(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Open Redirect Chain Analysis", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let chain_payloads = [
        (
            "SSRF via redirect",
            "https://169.254.169.254/latest/meta-data/",
        ),
        ("XSS via redirect", "javascript:alert(document.domain)"),
        (
            "Phishing via redirect",
            "https://evil.com/login?target=https://target.com",
        ),
        ("Protocol redirect", "//evil.com"),
        (
            "Path traversal redirect",
            "/redirect/../redirect?url=https://evil.com",
        ),
    ];

    for (name, payload) in &chain_payloads {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            payload
        );
        if let Ok(resp) = client.get(&test_url).send().await {
            let status = resp.status();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            println!(
                "  {} {:30} status={} location={}",
                "•".cyan(),
                name,
                status,
                if location.is_empty() {
                    "none"
                } else {
                    location
                }
            );
        }
    }

    println!("\n{} Chain analysis complete.", "[*]".cyan().bold());
    Ok(())
}
