use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn scan(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} BLE Device Scanner", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "ble_scan", "duration": 10});

    match client.post(url).json(&body).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let has_devices = text.contains("device") || text.contains("addr") || text.contains("mac");
            let tag = if has_devices { "DEVICES FOUND".red().bold().to_string() } else { format!("status={}", status) };
            println!("  {} Scan result: {}", "*".cyan(), tag);

            let addr_re = regex::Regex::new(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}").ok();
            if let Some(re) = addr_re {
                let addrs: Vec<_> = re.find_iter(&text).map(|m| m.as_str().to_string()).collect();
                if !addrs.is_empty() {
                    println!("  {} Devices found:", "[*]".cyan().bold());
                    for addr in &addrs { println!("    {} {}", "*".cyan(), addr); }
                }
            }
        }
        Err(_) => { println!("  {} Scan error", "*".red()); }
    }

    let common_names = ["Fitbit", "Mi Band", "Apple Watch", "Galaxy Watch", "Tile", "AirTag", "Smart Lock", "Heart Rate", "Glucose", "Thermometer"];
    println!("\n  {} Common BLE device types to look for:", "[*]".cyan().bold());
    for name in &common_names { println!("    {} {}", "*".cyan(), name); }
    Ok(())
}

pub async fn gatt(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} GATT Characteristic Enumerator", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let services = [
        ("Generic Access", "00001800-0000-1000-8000-00805f9b34fb"),
        ("Generic Attribute", "00001801-0000-1000-8000-00805f9b34fb"),
        ("Device Information", "0000180a-0000-1000-8000-00805f9b34fb"),
        ("Battery Service", "0000180f-0000-1000-8000-00805f9b34fb"),
        ("Heart Rate", "0000180d-0000-1000-8000-00805f9b34fb"),
        ("Blood Pressure", "00001810-0000-1000-8000-00805f9b34fb"),
        ("Glucose", "00001808-0000-1000-8000-00805f9b34fb"),
        ("Custom/Proprietary", "0000ffe0-0000-1000-8000-00805f9b34fb"),
    ];

    for (name, uuid) in &services {
        let body = serde_json::json!({"action": "gatt_enum", "service_uuid": uuid});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let has_chars = text.contains("characteristic") || text.contains("uuid") || text.contains("value");
                let tag = if has_chars { "CHARACTERISTICS".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:25} {} {}", "*".cyan(), name, uuid, tag);
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    let dangerous_chars = [
        ("Write characteristic", "Allows unauthenticated writes"),
        ("Write without response", "Fire-and-forget writes — no ACK needed"),
        ("Notify/Indicate", "Server pushes data — potential data leak"),
        ("Read all", "Read all characteristics without pairing"),
        ("Security Level 1", "No encryption — all data in cleartext"),
    ];

    println!("\n  {} Dangerous characteristic types:", "[*]".cyan().bold());
    for (name, desc) in &dangerous_chars {
        println!("    {} {:25} — {}", "*".cyan(), name, desc);
    }
    Ok(())
}

pub async fn write_test(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} BLE Write Without Response Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let write_chars = [
        ("Write command", serde_json::json!({"action": "ble_write", "char_uuid": "0000ffe1-0000-1000-8000-00805f9b34fb", "value": "AA==", "response": false})),
        ("Write request", serde_json::json!({"action": "ble_write", "char_uuid": "0000ffe1-0000-1000-8000-00805f9b34fb", "value": "AA==", "response": true})),
        ("Long write", serde_json::json!({"action": "ble_write", "char_uuid": "0000ffe1-0000-1000-8000-00805f9b34fb", "value": "AAAAAA==", "response": true})),
        ("Reboot cmd", serde_json::json!({"action": "ble_write", "char_uuid": "0000ffe1-0000-1000-8000-00805f9b34fb", "value": "cmVib290", "response": false})),
        ("Config write", serde_json::json!({"action": "ble_write", "char_uuid": "00001802-0000-1000-8000-00805f9b34fb", "value": "dGVzdA==", "response": false})),
    ];

    for (name, body) in &write_chars {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let written = text.contains("success") || text.contains("written") || status == 200;
                let tag = if written { "WRITE OK".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    println!("\n{} Unauthenticated BLE writes can manipulate IoT devices.", "[*]".cyan().bold());
    Ok(())
}

pub async fn mitm(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} BLE MITM Relay Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let pairing_tests = [
        ("Just Works pairing", serde_json::json!({"action": "ble_pair", "method": "just_works"})),
        ("Passkey bypass", serde_json::json!({"action": "ble_pair", "method": "passkey", "passkey": "000000"})),
        ("Numeric comparison bypass", serde_json::json!({"action": "ble_pair", "method": "numeric", "confirm": true})),
        ("OOB bypass", serde_json::json!({"action": "ble_pair", "method": "oob", "oob_data": "00000000000000000000000000000000"})),
        ("Legacy pairing", serde_json::json!({"action": "ble_pair", "method": "legacy"})),
        ("Secure Connections downgrade", serde_json::json!({"action": "ble_pair", "method": "downgrade"})),
    ];

    for (name, body) in &pairing_tests {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let paired = text.contains("paired") || text.contains("success") || text.contains("bonded") || status == 200;
                let tag = if paired { "PAIRED".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:35} {}", "*".cyan(), name, tag);
            }
            Err(_) => { println!("  {} {:35} error", "*".red(), name); }
        }
    }

    println!("\n{} 'Just Works' pairing has no authentication — relay attack trivial.", "[*]".cyan().bold());
    Ok(())
}
