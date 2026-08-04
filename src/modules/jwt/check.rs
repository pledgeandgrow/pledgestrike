use crate::modules::jwt::decode::decode;
use colored::Colorize;

#[allow(dead_code)]
pub struct VulnResult {
    pub name: String,
    pub severity: String,
    pub description: String,
}

pub fn check(token: &str) -> anyhow::Result<Vec<VulnResult>> {
    let parts = decode(token)?;
    let mut results = Vec::new();

    let alg = parts
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Check alg=none
    if alg.eq_ignore_ascii_case("none") {
        results.push(VulnResult {
            name: "alg=none".to_string(),
            severity: "CRITICAL".to_string(),
            description: "Token uses 'none' algorithm — no signature verification. \
                Server may accept forged tokens without a valid signature."
                .to_string(),
        });
    }

    // Check for missing alg
    if alg == "unknown" {
        results.push(VulnResult {
            name: "Missing algorithm".to_string(),
            severity: "HIGH".to_string(),
            description: "Token header has no 'alg' field. Server behavior is unpredictable."
                .to_string(),
        });
    }

    // Check for HS256 with weak key (we can't know without cracking, but we can warn)
    if alg.eq_ignore_ascii_case("HS256")
        || alg.eq_ignore_ascii_case("HS384")
        || alg.eq_ignore_ascii_case("HS512")
    {
        results.push(VulnResult {
            name: "Symmetric algorithm (HMAC)".to_string(),
            severity: "INFO".to_string(),
            description: format!(
                "Token uses {} — vulnerable to offline brute-force if the secret is weak. \
                Run 'pledgestrike jwt crack' to test.",
                alg
            ),
        });
    }

    // Check for RS256/RS512 key confusion
    if alg.eq_ignore_ascii_case("RS256")
        || alg.eq_ignore_ascii_case("RS384")
        || alg.eq_ignore_ascii_case("RS512")
    {
        results.push(VulnResult {
            name: "Asymmetric algorithm (RSA)".to_string(),
            severity: "MEDIUM".to_string(),
            description: format!(
                "Token uses {} — check for algorithm confusion attack. \
                If server accepts HS256 with the RSA public key as HMAC secret, \
                you can forge tokens using the public key.",
                alg
            ),
        });

        // Check if we can extract the public key from header
        if parts.header.get("jwk").is_some() {
            results.push(VulnResult {
                name: "Embedded JWK in header".to_string(),
                severity: "HIGH".to_string(),
                description: "Token header contains a JWK (JSON Web Key). \
                    Server may trust embedded keys — try injecting your own public key."
                    .to_string(),
            });
        }

        if parts.header.get("x5u").is_some() || parts.header.get("jku").is_some() {
            results.push(VulnResult {
                name: "External key reference".to_string(),
                severity: "HIGH".to_string(),
                description: "Token header references an external key URL (x5u/jku). \
                    Server may fetch attacker-controlled keys."
                    .to_string(),
            });
        }
    }

    // Check for kid injection
    if let Some(kid) = parts.header.get("kid").and_then(|v| v.as_str()) {
        if kid.contains("../") || kid.contains("..\\") {
            results.push(VulnResult {
                name: "Path traversal in kid".to_string(),
                severity: "HIGH".to_string(),
                description: format!(
                    "kid field contains path traversal: '{}'. \
                    Server may load secret from arbitrary file path.",
                    kid
                ),
            });
        }
        if kid.contains("')") || kid.contains("' ||") || kid.to_uppercase().contains("UNION") {
            results.push(VulnResult {
                name: "SQL injection in kid".to_string(),
                severity: "HIGH".to_string(),
                description: format!(
                    "kid field contains SQL injection payload: '{}'. \
                    Server may be vulnerable to SQLi via kid header.",
                    kid
                ),
            });
        }
    }

    // Check expiry
    if let Some(exp) = parts.payload.get("exp").and_then(|v| v.as_i64()) {
        let now = chrono::Utc::now().timestamp();
        if exp < now {
            results.push(VulnResult {
                name: "Expired token".to_string(),
                severity: "INFO".to_string(),
                description: format!(
                    "Token expired at {} ({} seconds ago). \
                    Some servers accept expired tokens — test if the server validates expiry.",
                    exp,
                    now - exp
                ),
            });
        }
    }

    // Check for no expiry
    if parts.payload.get("exp").is_none() {
        results.push(VulnResult {
            name: "No expiry claim".to_string(),
            severity: "LOW".to_string(),
            description:
                "Token has no 'exp' claim — it may be valid forever if the server doesn't check."
                    .to_string(),
        });
    }

    Ok(results)
}

pub fn format_results(results: &[VulnResult]) -> String {
    let mut out = String::new();

    if results.is_empty() {
        out.push_str(&format!(
            "{} No vulnerabilities found.\n",
            "[-]".green().bold()
        ));
        return out;
    }

    for r in results {
        let severity_colored = match r.severity.as_str() {
            "CRITICAL" => r.severity.red().bold().on_bright_red(),
            "HIGH" => r.severity.red().bold(),
            "MEDIUM" => r.severity.yellow().bold(),
            "LOW" => r.severity.blue(),
            "INFO" => r.severity.cyan(),
            _ => r.severity.normal(),
        };

        out.push_str(&format!(
            "{} [{}] {}\n    {}\n\n",
            "[!]".red().bold(),
            severity_colored,
            r.name.white().bold(),
            r.description,
        ));
    }

    out
}
