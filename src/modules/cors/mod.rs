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

pub async fn origin(
    url: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} CORS Origin Reflection Test", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout);

    let origins = [
        "https://evil.com",
        "https://attacker.test",
        "http://localhost",
        "null",
    ];

    for origin in &origins {
        let resp = client.get(url).header("Origin", *origin).send().await?;
        let headers = resp.headers().clone();
        let acao = headers.get("access-control-allow-origin").and_then(|v| v.to_str().ok());
        let acac = headers.get("access-control-allow-credentials").and_then(|v| v.to_str().ok());

        let reflected = acao == Some(*origin) || acao == Some("*");
        let creds = acac == Some("true");

        let status_str = if reflected && creds {
            "VULN (reflects origin + credentials)".red().bold().to_string()
        } else if reflected {
            "REFLECTED (no credentials)".yellow().to_string()
        } else {
            "safe".green().to_string()
        };

        println!("  {} Origin: {:30} ACAO: {:10} Creds: {:5} {}", "•".cyan(), origin, acao.unwrap_or("none"), creds, status_str);
    }

    Ok(())
}

pub async fn creds(
    url: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} CORS Credentials Test", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout);

    let resp = client
        .get(url)
        .header("Origin", "https://evil.com")
        .send()
        .await?;

    let acao = resp.headers().get("access-control-allow-origin").and_then(|v| v.to_str().ok());
    let acac = resp.headers().get("access-control-allow-credentials").and_then(|v| v.to_str().ok());

    println!("{} ACAO: {}", "[*]".cyan().bold(), acao.unwrap_or("not set"));
    println!("{} ACAC: {}", "[*]".cyan().bold(), acac.unwrap_or("not set"));

    if (acao == Some("*") || acao == Some("https://evil.com")) && acac == Some("true") {
        println!("\n{} [CRITICAL] CORS misconfiguration — wildcard/reflected origin with credentials!", "[!]".red().bold());
        println!("  {} Attackers can read responses from authenticated requests", "•".cyan());
    } else if acao == Some("https://evil.com") {
        println!("\n{} [HIGH] Origin reflected but no credentials — limited impact", "[!]".yellow().bold());
    } else {
        println!("\n{} CORS appears properly configured.", "[-]".green().bold());
    }

    Ok(())
}

pub async fn wildcard(
    url: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} CORS Wildcard Test", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout);

    let resp = client.get(url).header("Origin", "https://evil.com").send().await?;
    let acao = resp.headers().get("access-control-allow-origin").and_then(|v| v.to_str().ok());

    if acao == Some("*") {
        println!("{} [MEDIUM] Wildcard ACAO detected — any origin can read responses", "[!]".yellow().bold());
        println!("  {} If responses contain sensitive data, this is exploitable", "•".cyan());
    } else {
        println!("{} No wildcard ACAO detected (value: {}).", "[-]".green().bold(), acao.unwrap_or("none"));
    }

    Ok(())
}

pub async fn null_origin(
    url: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} CORS Null Origin Test", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout);

    let resp = client.get(url).header("Origin", "null").send().await?;
    let acao = resp.headers().get("access-control-allow-origin").and_then(|v| v.to_str().ok());
    let acac = resp.headers().get("access-control-allow-credentials").and_then(|v| v.to_str().ok());

    println!("{} ACAO for null origin: {}", "[*]".cyan().bold(), acao.unwrap_or("not set"));
    println!("{} ACAC: {}", "[*]".cyan().bold(), acac.unwrap_or("not set"));

    if acao == Some("null") {
        println!("\n{} [HIGH] Null origin reflected!", "[!]".red().bold());
        println!("  {} Exploit via sandboxed iframe: <iframe sandbox='allow-scripts' src='...'>", "•".cyan());
        if acac == Some("true") {
            println!("  {} Credentials also allowed — full exploit possible", "•".cyan());
        }
    } else {
        println!("\n{} Null origin not reflected.", "[-]".green().bold());
    }

    Ok(())
}
