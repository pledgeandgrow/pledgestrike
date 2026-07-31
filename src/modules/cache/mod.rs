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

const UNKEYED_HEADERS: &[&str] = &[
    "X-Forwarded-Host", "X-Forwarded-For", "X-Host", "X-Forwarded-Server",
    "X-Real-IP", "X-Original-URL", "X-Rewrite-URL", "X-Custom-Header",
    "X-Forwarded-Scheme", "X-Forwarded-Proto", "CF-Connecting-IP",
    "True-Client-IP", "X-Forwarded-Port",
];

pub async fn poison(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Web Cache Poisoning", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    println!("{} Step 1: Fetching baseline response...", "[*]".cyan().bold());
    let baseline = client.get(url).send().await?;
    let baseline_body = baseline.text().await.unwrap_or_default();
    let baseline_len = baseline_body.len();

    println!("{} Baseline length: {} bytes", "[*]".cyan().bold(), baseline_len);
    println!("{} Testing unkeyed headers...", "[*]".cyan().bold());

    for header in UNKEYED_HEADERS {
        let value = format!("ps-cache-test-{}", rand::random::<u32>());
        let resp = client.get(url).header(*header, &value).send().await?;
        let body = resp.text().await.unwrap_or_default();

        if body.contains(&value) {
            println!("{} [HIGH] Cache poisoning via {}!", "[!]".red().bold(), header);
            println!("  {} Header value reflected in response", "•".cyan());
            println!("  {} If this response is cached, all users get poisoned content", "•".cyan());
        }
    }

    println!("\n{} Cache poisoning scan complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn deceive(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Cache Deception", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let suffixes = [".css", ".js", ".png", ".jpg", ".ico", ".txt"];

    for suffix in &suffixes {
        let test_url = format!("{}{}", url, suffix);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
                let cache = resp.headers().get("cache-control").and_then(|v| v.to_str().ok()).unwrap_or("none").to_string();
                let body = resp.text().await.unwrap_or_default();
                let body_len = body.len();

                if status.is_success() && ct.contains("text/html") {
                    println!("{} [HIGH] Cache deception possible with {}!", "[!]".red().bold(), suffix);
                    println!("  {} URL returns HTML with non-static suffix", "•".cyan());
                    println!("  {} Content-Type: {} (should be static)", "•".cyan(), ct);
                    println!("  {} Cache-Control: {}", "•".cyan(), cache);
                } else {
                    println!("  {} {:8} status={} ct={} len={}", "•".cyan(), suffix, status, ct, body_len);
                }
            }
            Err(_) => {}
        }
    }

    println!("\n{} Cache deception scan complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn key(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Cache Key Analysis", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let baseline = client.get(url).send().await?;
    let baseline_body = baseline.text().await.unwrap_or_default();
    let baseline_hash = simple_hash(&baseline_body);

    println!("{} Baseline hash: {:x}", "[*]".cyan().bold(), baseline_hash);

    let test_params = ["utm_source", "utm_medium", "fbclid", "gclid", "mc_eid", "_ga", "nr"];

    for param in &test_params {
        let test_url = format!("{}{}{}=test123", url, if url.contains('?') { "&" } else { "?" }, param);
        let resp = client.get(&test_url).send().await?;
        let body = resp.text().await.unwrap_or_default();
        let hash = simple_hash(&body);

        let same = hash == baseline_hash;
        let status = if same { "SAME (unkeyed — cacheable)".yellow().to_string() } else { "DIFFERENT (keyed)".green().to_string() };
        println!("  {} {:15} hash={:x}  {}", "•".cyan(), param, hash, status);
    }

    println!("\n{} Unkeyed params can be used for cache poisoning.", "[*]".cyan().bold());
    Ok(())
}

fn simple_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}
