use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use colored::Colorize;
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use sha2::{Sha256, Sha384, Sha512};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub fn crack(
    token: &str,
    wordlist_path: &str,
    threads: usize,
) -> anyhow::Result<Option<String>> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid JWT: expected 3 parts, got {}", parts.len());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_b64 = parts[2];
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?;

    // Parse header to get algorithm
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| anyhow::anyhow!("Failed to decode header: {}", e))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("HS256");

    eprintln!("{} Algorithm: {}", "[*]".cyan().bold(), alg);

    // Load wordlist
    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);
    let words: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
    let total = words.len();

    eprintln!("{} Loaded {} words from {}", "[*]".cyan().bold(), total, wordlist_path);
    eprintln!("{} Signing input: {}.{}", "[*]".cyan().bold(), &parts[0][..parts[0].len().min(20)], "...");

    if threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .ok();
    }

    let found = Arc::new(AtomicBool::new(false));
    let tried = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let result: Option<String> = words
        .par_iter()
        .map(|word| {
            if found.load(Ordering::Relaxed) {
                return None;
            }

            let count = tried.fetch_add(1, Ordering::Relaxed);
            if count % 100000 == 0 && count > 0 {
                let elapsed = start.elapsed().as_secs_f64();
                let rate = count as f64 / elapsed;
                eprintln!(
                    "\r{} Tried {} words ({:.0}/s, {:.1}% done)",
                    "[*]".cyan().bold(),
                    count,
                    rate,
                    (count as f64 / total as f64) * 100.0
                );
            }

            let is_match = match alg {
                "HS256" => {
                    let mut mac = HmacSha256::new_from_slice(word.as_bytes()).unwrap();
                    mac.update(signing_input.as_bytes());
                    mac.finalize().into_bytes().to_vec() == signature
                }
                "HS384" => {
                    let mut mac = HmacSha384::new_from_slice(word.as_bytes()).unwrap();
                    mac.update(signing_input.as_bytes());
                    mac.finalize().into_bytes().to_vec() == signature
                }
                "HS512" => {
                    let mut mac = HmacSha512::new_from_slice(word.as_bytes()).unwrap();
                    mac.update(signing_input.as_bytes());
                    mac.finalize().into_bytes().to_vec() == signature
                }
                _ => false,
            };

            if is_match {
                found.store(true, Ordering::Relaxed);
                Some(word.clone())
            } else {
                None
            }
        })
        .find_any(|r| r.is_some())
        .flatten();

    let elapsed = start.elapsed();
    let total_tried = tried.load(Ordering::Relaxed);

    eprintln!(
        "\n{} Cracked {} words in {:.2}s ({:.0}/s)",
        "[*]".cyan().bold(),
        total_tried,
        elapsed.as_secs_f64(),
        total_tried as f64 / elapsed.as_secs_f64().max(0.01)
    );

    Ok(result)
}
