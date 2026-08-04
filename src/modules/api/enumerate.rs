use colored::Colorize;
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::sleep;

use super::client::{build_client, parse_status_filter};

pub async fn enumerate(
    base_url: &str,
    wordlist_path: &str,
    methods: &str,
    token: Option<&str>,
    api_key: Option<&str>,
    custom_headers: Option<&str>,
    timeout: u64,
    status_filter: Option<&str>,
    rate: u64,
) -> anyhow::Result<()> {
    let base = base_url.trim_end_matches('/');

    // Load wordlist
    let content = std::fs::read_to_string(wordlist_path)?;
    let paths: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let methods: Vec<&str> = methods.split(',').map(|m| m.trim()).collect();
    let filter_codes: Option<HashSet<u16>> =
        status_filter.map(|f| parse_status_filter(f).into_iter().collect());

    let client = build_client(timeout, token, api_key, custom_headers)?;

    let total = paths.len() * methods.len();
    println!("{} API Endpoint Enumeration", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} Base URL:  {}", "[*]".cyan().bold(), base.green());
    println!(
        "{} Wordlist:  {} ({} paths)",
        "[*]".cyan().bold(),
        wordlist_path,
        paths.len()
    );
    println!(
        "{} Methods:   {}",
        "[*]".cyan().bold(),
        methods.join(", ").yellow()
    );
    println!("{} Total req: {}", "[*]".cyan().bold(), total);
    if let Some(f) = &filter_codes {
        println!("{} Filter:    {:?}", "[*]".cyan().bold(), f);
    }
    if rate > 0 {
        println!("{} Rate:      {} req/s", "[*]".cyan().bold(), rate);
    }
    println!("{}", "─".repeat(60).dimmed());

    let mut found = Vec::new();
    let mut sent = 0u64;

    for path in &paths {
        let clean_path = if path.starts_with('/') {
            path.clone()
        } else {
            format!("/{}", path)
        };

        let url = format!("{}{}", base, clean_path);

        for method in &methods {
            sent += 1;

            let req = match *method {
                "GET" => client.get(&url),
                "POST" => client.post(&url),
                "PUT" => client.put(&url),
                "DELETE" => client.delete(&url),
                "PATCH" => client.patch(&url),
                "HEAD" => client.head(&url),
                "OPTIONS" => client.request(reqwest::Method::OPTIONS, &url),
                _ => continue,
            };

            if let Ok(resp) = req.send().await {
                let status = resp.status().as_u16();
                let len = resp.content_length().unwrap_or(0);
                let headers = resp.headers().clone();

                // Apply filter
                let passes = match &filter_codes {
                    Some(codes) => codes.contains(&status),
                    None => status != 404,
                };

                if passes {
                    let server = headers
                        .get("server")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_string();

                    let content_type = headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_string();

                    let allow = headers
                        .get("allow")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    let result = EndpointResult {
                        method: method.to_string(),
                        path: clean_path.clone(),
                        url: url.clone(),
                        status,
                        content_length: len,
                        server,
                        content_type,
                        allow,
                    };

                    print_result(&result);
                    found.push(result);
                }
            }

            // Rate limiting
            if let Some(delay) = (1000u64).checked_div(rate) {
                sleep(Duration::from_millis(delay)).await;
            }
        }
    }

    // Summary
    println!("\n{}", "═".repeat(60).cyan());
    println!("{} Enumeration complete", "[*]".cyan().bold());
    println!("{} Requests sent: {}", "[*]".cyan().bold(), sent);
    println!(
        "{} Endpoints found: {}",
        "[*]".cyan().bold(),
        found.len().to_string().green().bold()
    );

    if !found.is_empty() {
        println!("\n{} Discovered endpoints:", "[+]".green().bold());
        println!("{}", "─".repeat(60).dimmed());

        // Group by path
        let mut by_path: std::collections::BTreeMap<String, Vec<&EndpointResult>> =
            std::collections::BTreeMap::new();
        for r in &found {
            by_path.entry(r.path.clone()).or_default().push(r);
        }

        for (path, results) in &by_path {
            let methods: Vec<String> = results
                .iter()
                .map(|r| format!("{}({})", r.method, r.status))
                .collect();
            println!(
                "  {} {} — {}",
                "•".cyan(),
                path.white().bold(),
                methods.join(", ").yellow()
            );
        }
    }

    Ok(())
}

struct EndpointResult {
    method: String,
    path: String,
    url: String,
    status: u16,
    content_length: u64,
    server: String,
    content_type: String,
    allow: String,
}

fn print_result(r: &EndpointResult) {
    let status_str = match r.status {
        200..=299 => format!("{}", r.status).green().bold(),
        300..=399 => format!("{}", r.status).yellow().bold(),
        400..=499 => format!("{}", r.status).red().bold(),
        500..=599 => format!("{}", r.status).magenta().bold(),
        _ => format!("{}", r.status).white(),
    };

    eprintln!(
        "{} {:6} {} {} ({} bytes) {}",
        "[>]".cyan(),
        r.method.yellow(),
        status_str,
        r.path.white(),
        r.content_length,
        r.content_type.dimmed(),
    );

    if !r.allow.is_empty() {
        eprintln!("       Allow: {}", r.allow.cyan());
    }
}
