use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use colored::Colorize;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub fn forge(secret: &str, payload_json: &str, alg: &str) -> anyhow::Result<String> {
    // Parse payload JSON
    let payload: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| anyhow::anyhow!("Invalid payload JSON: {}", e))?;

    // Build header
    let header = serde_json::json!({
        "alg": alg,
        "typ": "JWT"
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature: Vec<u8> = match alg {
        "HS256" => {
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS384" => {
            let mut mac = HmacSha384::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac = HmacSha512::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "none" => Vec::new(),
        _ => anyhow::bail!(
            "Unsupported algorithm: {}. Use HS256, HS384, HS512, or none.",
            alg
        ),
    };

    let sig_b64 = if signature.is_empty() {
        String::new()
    } else {
        URL_SAFE_NO_PAD.encode(&signature)
    };

    let token = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    Ok(token)
}

pub fn print_forge_result(token: &str, secret: &str, alg: &str, payload: &str) {
    println!("{} Forged JWT token:", "[+]".green().bold());
    println!();
    println!("{}", token.green());
    println!();
    println!("{} Algorithm: {}", "[*]".cyan().bold(), alg);
    println!("{} Secret:   {}", "[*]".cyan().bold(), secret);
    println!("{} Payload:  {}", "[*]".cyan().bold(), payload);
    println!();
    println!(
        "{} Use this token in the Authorization header:",
        "[*]".cyan().bold()
    );
    println!("    Authorization: Bearer {}", token);
}
