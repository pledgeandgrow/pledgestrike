use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;

#[allow(dead_code)]
pub struct JwtParts {
    pub header: Value,
    pub payload: Value,
    pub signature: Vec<u8>,
    pub header_raw: String,
    pub payload_raw: String,
    pub signature_raw: String,
}

pub fn decode(token: &str) -> anyhow::Result<JwtParts> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid JWT: expected 3 parts separated by '.', got {}", parts.len());
    }

    let header_raw = parts[0].to_string();
    let payload_raw = parts[1].to_string();
    let signature_raw = parts[2].to_string();

    let header_bytes = URL_SAFE_NO_PAD
        .decode(&header_raw)
        .map_err(|e| anyhow::anyhow!("Failed to decode header: {}", e))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&payload_raw)
        .map_err(|e| anyhow::anyhow!("Failed to decode payload: {}", e))?;
    let signature = URL_SAFE_NO_PAD
        .decode(&signature_raw)
        .map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?;

    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse header JSON: {}", e))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse payload JSON: {}", e))?;

    Ok(JwtParts {
        header,
        payload,
        signature,
        header_raw,
        payload_raw,
        signature_raw,
    })
}

pub fn format_decoded(parts: &JwtParts) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{} {}\n",
        "Header:".cyan().bold(),
        serde_json::to_string_pretty(&parts.header).unwrap_or_default()
    ));
    out.push_str(&format!(
        "{} {}\n",
        "Payload:".cyan().bold(),
        serde_json::to_string_pretty(&parts.payload).unwrap_or_default()
    ));
    out.push_str(&format!(
        "{} {} (hex: {})\n",
        "Signature:".cyan().bold(),
        parts.signature_raw,
        hex::encode(&parts.signature)
    ));

    // Show known claims
    if let Some(claims) = parts.payload.as_object() {
        let mut claim_info = Vec::new();

        if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
            let now = chrono::Utc::now().timestamp();
            let expired = exp < now;
            let status = if expired {
                "EXPIRED".red().bold().to_string()
            } else {
                "VALID".green().bold().to_string()
            };
            claim_info.push(format!("  exp: {} [{}]", exp, status));
        }

        if let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) {
            claim_info.push(format!("  iat: {}", iat));
        }

        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            let now = chrono::Utc::now().timestamp();
            let not_yet = nbf > now;
            let status = if not_yet {
                "NOT YET VALID".yellow().bold().to_string()
            } else {
                "VALID".green().bold().to_string()
            };
            claim_info.push(format!("  nbf: {} [{}]", nbf, status));
        }

        if let Some(sub) = claims.get("sub") {
            claim_info.push(format!("  sub: {}", sub));
        }

        if let Some(iss) = claims.get("iss") {
            claim_info.push(format!("  iss: {}", iss));
        }

        if let Some(aud) = claims.get("aud") {
            claim_info.push(format!("  aud: {}", aud));
        }

        if let Some(role) = claims.get("role").or_else(|| claims.get("roles")) {
            claim_info.push(format!("  role: {}", role));
        }

        if !claim_info.is_empty() {
            out.push_str(&format!("\n{}:\n", "Claims Analysis".cyan().bold()));
            for line in claim_info {
                out.push_str(&format!("{}\n", line));
            }
        }
    }

    out
}

use colored::Colorize;
