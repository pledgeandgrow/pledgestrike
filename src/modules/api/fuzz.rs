use colored::Colorize;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

use super::client::build_client;

pub async fn fuzz(
    target_url: &str,
    wordlist_path: &str,
    token: Option<&str>,
    fuzz_value: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(wordlist_path)?;
    let params: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let client = build_client(timeout, token, None, None)?;

    println!("{} Parameter Fuzzing", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} Target:    {}", "[*]".cyan().bold(), target_url.green());
    println!("{} Params:    {} from wordlist", "[*]".cyan().bold(), params.len());
    println!("{} Fuzz val:  {}", "[*]".cyan().bold(), fuzz_value.yellow());
    println!("{}", "─".repeat(60).dimmed());

    // Parse base URL
    let parsed = Url::parse(target_url)?;

    // Get baseline response (no extra params)
    let baseline_resp = client.get(target_url).send().await?;
    let baseline_status = baseline_resp.status().as_u16();
    let baseline_body = baseline_resp.text().await.unwrap_or_default();
    let baseline_len = baseline_body.len();
    let baseline_hash = simple_hash(&baseline_body);

    println!(
        "{} Baseline: {} ({} bytes, hash: {:x})",
        "[*]".cyan().bold(),
        baseline_status,
        baseline_len,
        baseline_hash,
    );
    println!("{}", "─".repeat(60).dimmed());

    let mut interesting = Vec::new();

    for param in &params {
        // Build URL with the fuzz param
        let mut url = parsed.clone();
        url.query_pairs_mut().append_pair(param, fuzz_value);

        let req_url = url.as_str();

        match client.get(req_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let len = body.len();
                let hash = simple_hash(&body);

                // Compare with baseline
                let status_diff = status != baseline_status;
                let len_diff = len.abs_diff(baseline_len);
                let hash_diff = hash != baseline_hash;
                let significant_len_change = len_diff > 50;

                if status_diff || significant_len_change {
                    let reason = if status_diff {
                        format!("status changed {} -> {}", baseline_status, status)
                    } else if len_diff > 0 {
                        format!("size changed {} -> {} (delta: {})", baseline_len, len, len_diff as i64 - baseline_len as i64)
                    } else {
                        "content changed".to_string()
                    };

                    let severity = if status_diff { "HIGH" } else if len_diff > 500 { "MEDIUM" } else { "LOW" };

                    eprintln!(
                        "{} [{:>6}] {} = {} — {}",
                        "[!]".yellow().bold(),
                        severity.dimmed(),
                        param.white().bold(),
                        fuzz_value.cyan(),
                        reason,
                    );

                    interesting.push(FuzzResult {
                        param: param.clone(),
                        status,
                        content_length: len,
                        status_diff,
                        len_diff: len_diff as i64 - baseline_len as i64,
                        reason,
                        severity: severity.to_string(),
                    });
                } else if hash_diff {
                    // Subtle content change
                    eprintln!(
                        "{} [{:>6}] {} = {} — content changed (same status/size)",
                        "[?]".dimmed(),
                        "INFO",
                        param,
                        fuzz_value,
                    );
                }
            }
            Err(_) => {}
        }

        sleep(Duration::from_millis(50)).await;
    }

    // Summary
    println!("\n{}", "═".repeat(60).cyan());
    println!("{} Fuzzing complete", "[*]".cyan().bold());
    println!("{} Parameters tested: {}", "[*]".cyan().bold(), params.len());
    println!(
        "{} Interesting params: {}",
        "[*]".cyan().bold(),
        interesting.len().to_string().green().bold(),
    );

    if !interesting.is_empty() {
        println!("\n{} Interesting parameters found:", "[+]".green().bold());
        println!("{}", "─".repeat(60).dimmed());

        for r in &interesting {
            let sev_colored = match r.severity.as_str() {
                "HIGH" => r.severity.red().bold(),
                "MEDIUM" => r.severity.yellow().bold(),
                _ => r.severity.cyan(),
            };
            println!(
                "  {} [{}] {} — {}",
                "•".cyan(),
                sev_colored,
                r.param.white().bold(),
                r.reason,
            );
        }
    }

    Ok(())
}

struct FuzzResult {
    param: String,
    status: u16,
    content_length: usize,
    status_diff: bool,
    len_diff: i64,
    reason: String,
    severity: String,
}

fn simple_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}
