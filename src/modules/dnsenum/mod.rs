use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn axfr(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} DNS Zone Transfer (AXFR) Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "dns_axfr", "domain": url});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    let nameservers = ["ns1", "ns2", "ns3", "ns4", "dns1", "dns2", "primary", "secondary"];
    println!("\n  {} Testing common nameservers for AXFR:", "[*]".cyan().bold());
    for ns in &nameservers {
        let ns_domain = format!("{}.{}", ns, url.trim_start_matches("https://").trim_start_matches("http://"));
        let req_body = serde_json::json!({"action": "dns_axfr", "domain": url, "server": ns_domain});
        match client.post(url).json(&req_body).send().await {
            Ok(r) => {
                let s = r.status().as_u16();
                let t = r.text().await.unwrap_or_default();
                if t.contains("XFR") || t.contains("transfer") || t.contains("record") || s == 200 {
                    println!("    {} {} — Zone transfer may be allowed!", "[!]".red().bold(), ns_domain);
                } else {
                    println!("    {} {} — Refused", "[-]".dimmed(), ns_domain);
                }
            }
            Err(_) => println!("    {} {} — Error", "[-]".dimmed(), ns_domain),
        }
    }

    if status == 200 && (text.contains("XFR") || text.contains("transfer")) {
        println!("\n{} AXFR response indicates zone transfer was permitted!", "[!]".red().bold());
    } else {
        println!("\n{} Zone transfer not permitted on tested servers.", "[-]".green().bold());
    }

    println!("\n{} Note: Full AXFR testing requires direct DNS protocol access (port 53).", "[*]".yellow().bold());
    println!("{} Use dig @server domain AXFR for direct testing.", "[*]".yellow().bold());
    Ok(())
}

pub async fn records(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} DNS Record Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "PTR", "CAA"];
    let domain = url.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/');

    for rt in &record_types {
        let body = serde_json::json!({"action": "dns_query", "domain": domain, "type": rt});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() && !text.contains("error") {
                    println!("  {} {:6} — {}", "[+]".green().bold(), rt, text.chars().take(80).collect::<String>());
                } else {
                    println!("  {} {:6} — No records", "[-]".dimmed(), rt);
                }
            }
            Err(_) => println!("  {} {:6} — Query failed", "[-]".dimmed(), rt),
        }
    }

    println!("\n{} Also checking common subdomain records:", "[*]".cyan().bold());
    let common_subs = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "remote", "portal"];
    for sub in &common_subs {
        let sub_domain = format!("{}.{}", sub, domain);
        let body = serde_json::json!({"action": "dns_query", "domain": sub_domain, "type": "A"});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let text = resp.text().await.unwrap_or_default();
                if !text.contains("error") && !text.contains("NXDOMAIN") && !text.is_empty() {
                    println!("  {} {:15} — {}", "[+]".green().bold(), sub_domain, text.chars().take(60).collect::<String>());
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn nsec(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NSEC/NSEC3 Zone Walking", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let domain = url.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/');

    let body = serde_json::json!({"action": "dns_query", "domain": domain, "type": "NSEC"});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if status == 200 && (text.contains("NSEC") || text.contains("NSEC3")) {
        println!("  {} DNSSEC is enabled — NSEC records found!", "[+]".green().bold());
        println!("  {} NSEC walking may enumerate hidden subdomains.", "[*]".cyan().bold());

        let mut current = domain.to_string();
        for i in 0..20 {
            let walk_body = serde_json::json!({"action": "dns_query", "domain": current, "type": "NSEC"});
            match client.post(url).json(&walk_body).send().await {
                Ok(r) => {
                    let t = r.text().await.unwrap_or_default();
                    if t.contains("NSEC") {
                        let next = t.split("NSEC").nth(1).unwrap_or("").trim();
                        if next.is_empty() { break; }
                        println!("  {} Hop {}: {} -> {}", "[*]".cyan().bold(), i + 1, current, next);
                        current = next.to_string();
                    } else {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    } else {
        println!("  {} No NSEC/NSEC3 records found — zone is not DNSSEC-signed or NSEC3 used.", "[-]".dimmed());
    }

    let nsec3_body = serde_json::json!({"action": "dns_query", "domain": domain, "type": "NSEC3PARAM"});
    let resp3 = client.post(url).json(&nsec3_body).send().await?;
    let text3 = resp3.text().await.unwrap_or_default();
    if text3.contains("NSEC3PARAM") {
        println!("\n  {} NSEC3PARAM found — NSEC3 walking is harder but possible with tools like nsec3walker.", "[*]".yellow().bold());
    }

    Ok(())
}

pub async fn snoop(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} DNS Cache Snooping", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Resolver: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let test_domains = [
        "google.com", "facebook.com", "twitter.com", "youtube.com",
        "github.com", "amazon.com", "netflix.com", "linkedin.com",
        "instagram.com", "reddit.com", "tiktok.com", "discord.com",
        "openai.com", "cloudflare.com", "microsoft.com",
    ];

    println!("  {} Querying resolver for cached domains (non-recursive):", "[*]".cyan().bold());
    for domain in &test_domains {
        let body = serde_json::json!({"action": "dns_query", "domain": domain, "type": "A", "rd": false});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() && !text.contains("error") {
                    println!("    {} {:20} — CACHED (recently visited)", "[+]".green().bold(), domain);
                } else {
                    println!("    {} {:20} — not cached", "[-]".dimmed(), domain);
                }
            }
            Err(_) => println!("    {} {:20} — query failed", "[-]".dimmed(), domain),
        }
    }

    println!("\n{} Cached domains indicate recent DNS lookups by users of this resolver.", "[*]".yellow().bold());
    Ok(())
}
