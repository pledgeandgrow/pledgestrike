use colored::Colorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::BufRead;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub ioc_type: String,
    pub value: String,
    pub line_number: usize,
    pub context: String,
}

pub async fn extract(
    file_path: &str,
    types: &str,
    format: &str,
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    let patterns = compile_patterns(types);

    println!("{} IOC Extraction", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} File:  {}", "[*]".cyan().bold(), file_path.green());
    println!("{} Types: {}", "[*]".cyan().bold(), types.yellow());
    println!("{}", "─".repeat(60).dimmed());

    let iocs = extract_from_file(file_path, &patterns)?;

    println!("{} Extracted {} IOCs", "[*]".cyan().bold(), iocs.len());

    // Group by type
    let mut by_type: HashMap<String, Vec<&Ioc>> = HashMap::new();
    for ioc in &iocs {
        by_type.entry(ioc.ioc_type.clone()).or_default().push(ioc);
    }

    let mut sorted_types: Vec<String> = by_type.keys().cloned().collect();
    sorted_types.sort();

    for ioc_type in &sorted_types {
        let items = by_type.get(ioc_type).unwrap();
        let unique: std::collections::HashSet<&str> =
            items.iter().map(|i| i.value.as_str()).collect();
        println!(
            "  {} {:10} {} occurrences ({} unique)",
            "•".cyan(),
            ioc_type.white().bold(),
            items.len(),
            unique.len(),
        );
    }

    // Output
    let output = match format {
        "json" => format_json(&iocs),
        "csv" => format_csv(&iocs),
        _ => format_text(&iocs),
    };

    match output_path {
        Some(path) => {
            std::fs::write(path, &output)?;
            println!("\n{} Results saved to {}", "[+]".green().bold(), path);
        }
        None => {
            println!("\n{}", "─".repeat(60).dimmed());
            print!("{}", output);
        }
    }

    Ok(())
}

pub async fn hunt(
    file_path: &str,
    pattern: &str,
    context_lines: usize,
) -> anyhow::Result<()> {
    println!("{} IOC Hunt", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} File:    {}", "[*]".cyan().bold(), file_path.green());
    println!("{} Pattern: {}", "[*]".cyan().bold(), pattern.yellow());
    println!("{}", "─".repeat(60).dimmed());

    // Try to detect pattern type
    let regex = detect_pattern(pattern)?;

    let file = std::fs::File::open(file_path)?;
    let reader = std::io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    let mut matches = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        if regex.is_match(line) {
            matches.push((idx, line.clone()));
        }
    }

    if matches.is_empty() {
        println!("{} No matches found", "[-]".red().bold());
        return Ok(());
    }

    println!("{} Found {} matches\n", "[+]".green().bold(), matches.len());

    for (idx, line) in &matches {
        let line_num = idx + 1;
        println!("{} Line {}:", "[>]".cyan().bold(), line_num.to_string().yellow());

        // Print context before
        for c in (1..=context_lines).rev() {
            if let Some(ctx_line) = lines.get(idx.saturating_sub(c)) {
                println!("  {} {:>5} │ {}", " ".dimmed(), idx + 1 - c, ctx_line.dimmed());
            }
        }

        // Print matching line
        println!("  {} {:>5} │ {}", ">>".cyan().bold(), line_num, line.white().bold());

        // Print context after
        for c in 1..=context_lines {
            if let Some(ctx_line) = lines.get(idx + c) {
                println!("  {} {:>5} │ {}", " ".dimmed(), idx + 1 + c, ctx_line.dimmed());
            }
        }

        println!();
    }

    Ok(())
}

pub async fn stats(file_path: &str, min_occurrences: usize) -> anyhow::Result<()> {
    let patterns = compile_patterns("all");

    println!("{} IOC Statistics", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} File: {}", "[*]".cyan().bold(), file_path.green());
    println!("{} Min occurrences: {}", "[*]".cyan().bold(), min_occurrences);
    println!("{}", "─".repeat(60).dimmed());

    let iocs = extract_from_file(file_path, &patterns)?;

    // Count by value
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for ioc in &iocs {
        *counts.entry((ioc.ioc_type.clone(), ioc.value.clone())).or_insert(0) += 1;
    }

    // Sort by count descending
    let mut sorted: Vec<((String, String), usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    // Group by type
    let mut by_type: HashMap<String, Vec<(String, usize)>> = HashMap::new();
    for ((ioc_type, value), count) in &sorted {
        if *count >= min_occurrences {
            by_type
                .entry(ioc_type.clone())
                .or_default()
                .push((value.clone(), *count));
        }
    }

    let mut types: Vec<String> = by_type.keys().cloned().collect();
    types.sort();

    for ioc_type in &types {
        let items = by_type.get(ioc_type).unwrap();
        println!("\n{} ({} unique values)", ioc_type.white().bold(), items.len());
        println!("{}", "─".repeat(40).dimmed());

        for (value, count) in items.iter().take(50) {
            let bar = "█".repeat((*count).min(30));
            let bar_colored = if *count > 10 { bar.red() } else if *count > 3 { bar.yellow() } else { bar.green() };
            println!(
                "  {} {:>5} {} {}",
                "•".cyan(),
                format!("({})", count).yellow(),
                bar_colored,
                value.white(),
            );
        }
    }

    // Summary
    println!("\n{}", "═".repeat(60).cyan());
    println!("{} Total IOCs: {}", "[*]".cyan().bold(), iocs.len());
    println!("{} Unique IOCs: {}", "[*]".cyan().bold(), sorted.len());

    Ok(())
}

struct IocPattern {
    ioc_type: String,
    regex: Regex,
}

fn compile_patterns(types: &str) -> Vec<IocPattern> {
    let requested: Vec<String> = types.split(',').map(|s| s.trim().to_lowercase()).collect();
    let all = requested.iter().any(|t| t == "all");

    let mut patterns = Vec::new();

    let ip_regex = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).unwrap();

    let ipv6_regex = Regex::new(
        r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"
    ).unwrap();

    let url_regex = Regex::new(
        r#"\bhttps?://[^\s<>'"{}|\\^`\[\]]+"#
    ).unwrap();

    let email_regex = Regex::new(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ).unwrap();

    let md5_regex = Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap();
    let sha1_regex = Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap();
    let sha256_regex = Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    let sha512_regex = Regex::new(r"\b[a-fA-F0-9]{128}\b").unwrap();

    let domain_regex = Regex::new(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ).unwrap();

    let mac_regex = Regex::new(
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
    ).unwrap();

    let cve_regex = Regex::new(r"\bCVE-\d{4}-\d{4,}\b").unwrap();

    let credit_card_regex = Regex::new(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ).unwrap();

    let ssn_regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();

    let add = |patterns: &mut Vec<IocPattern>, ioc_type: &str, regex: Regex, requested: &[String], all: bool| {
        if all || requested.iter().any(|t| t == ioc_type) {
            patterns.push(IocPattern {
                ioc_type: ioc_type.to_string(),
                regex,
            });
        }
    };

    add(&mut patterns, "ipv4", ip_regex, &requested, all);
    add(&mut patterns, "ipv6", ipv6_regex, &requested, all);
    add(&mut patterns, "url", url_regex, &requested, all);
    add(&mut patterns, "email", email_regex, &requested, all);
    add(&mut patterns, "md5", md5_regex, &requested, all);
    add(&mut patterns, "sha1", sha1_regex, &requested, all);
    add(&mut patterns, "sha256", sha256_regex, &requested, all);
    add(&mut patterns, "sha512", sha512_regex, &requested, all);
    add(&mut patterns, "domain", domain_regex, &requested, all);
    add(&mut patterns, "mac", mac_regex, &requested, all);
    add(&mut patterns, "cve", cve_regex, &requested, all);
    add(&mut patterns, "credit_card", credit_card_regex, &requested, all);
    add(&mut patterns, "ssn", ssn_regex, &requested, all);

    patterns
}

fn extract_from_file(file_path: &str, patterns: &[IocPattern]) -> anyhow::Result<Vec<Ioc>> {
    let mut iocs = Vec::new();

    let reader: Box<dyn BufRead> = if file_path == "-" {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        Box::new(std::io::BufReader::new(std::fs::File::open(file_path)?))
    };

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        if line.trim().is_empty() {
            continue;
        }

        for pattern in patterns {
            for m in pattern.regex.find_iter(&line) {
                // Skip common false positives
                let value = m.as_str();
                if is_false_positive(value, &pattern.ioc_type) {
                    continue;
                }

                iocs.push(Ioc {
                    ioc_type: pattern.ioc_type.clone(),
                    value: value.to_string(),
                    line_number: line_num + 1,
                    context: line.trim().to_string(),
                });
            }
        }
    }

    Ok(iocs)
}

fn is_false_positive(value: &str, ioc_type: &str) -> bool {
    match ioc_type {
        "ipv4" => {
            // Skip version-like patterns
            value.starts_with("0.0.0.0")
                || value == "127.0.0.1"
                || value.starts_with("255.255.255")
                || value.starts_with("0.")
        }
        "domain" => {
            // Skip file extensions and common non-domains
            value.ends_with(".example.com")
                || value.ends_with(".example.org")
                || value == "localhost."
        }
        "md5" | "sha1" | "sha256" | "sha512" => {
            // Filter out strings that are just hex but not really hashes
            // (too short context like single hex words)
            false
        }
        _ => false,
    }
}

fn detect_pattern(pattern: &str) -> anyhow::Result<Regex> {
    // Check if it looks like an IP
    let ip_re = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
    if ip_re.is_match(pattern) {
        return Ok(Regex::new(&regex::escape(pattern))?);
    }

    // Check if it looks like a hash
    if pattern.len() == 32 || pattern.len() == 40 || pattern.len() == 64 {
        if pattern.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(Regex::new(&regex::escape(pattern))?);
        }
    }

    // Check if it looks like an email
    if pattern.contains('@') {
        return Ok(Regex::new(&regex::escape(pattern))?);
    }

    // Check if it looks like a URL
    if pattern.starts_with("http://") || pattern.starts_with("https://") {
        return Ok(Regex::new(&regex::escape(pattern))?);
    }

    // Check if it looks like a CVE
    if pattern.starts_with("CVE-") {
        return Ok(Regex::new(&regex::escape(pattern))?);
    }

    // Otherwise treat as regex
    Regex::new(pattern).map_err(|e| anyhow::anyhow!("Invalid regex pattern: {}", e))
}

fn format_text(iocs: &[Ioc]) -> String {
    let mut output = String::new();

    let mut by_type: HashMap<String, Vec<&Ioc>> = HashMap::new();
    for ioc in iocs {
        by_type.entry(ioc.ioc_type.clone()).or_default().push(ioc);
    }

    let mut types: Vec<String> = by_type.keys().cloned().collect();
    types.sort();

    for ioc_type in &types {
        let items = by_type.get(ioc_type).unwrap();
        output.push_str(&format!("\n{} ({}):\n", ioc_type.to_uppercase(), items.len()));

        let mut seen = std::collections::HashSet::new();
        for ioc in items {
            if seen.insert(&ioc.value) {
                output.push_str(&format!("  {} {}\n", "•", ioc.value));
            }
        }
    }

    output
}

fn format_json(iocs: &[Ioc]) -> String {
    serde_json::to_string_pretty(iocs).unwrap_or_else(|_| "[]".to_string())
}

fn format_csv(iocs: &[Ioc]) -> String {
    let mut csv = String::from("type,value,line_number,context\n");
    for ioc in iocs {
        let context = ioc.context.replace('"', "\"\"");
        csv.push_str(&format!(
            "{},{},{},\"{}\"\n",
            ioc.ioc_type, ioc.value, ioc.line_number, context
        ));
    }
    csv
}
