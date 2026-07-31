use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

const BRUTE_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "ns3",
    "test", "dev", "staging", "stage", "prod", "production", "beta", "alpha", "demo",
    "admin", "administrator", "portal", "api", "app", "apps", "internal", "intranet",
    "vpn", "remote", "secure", "login", "sso", "auth", "oauth", "id", "account",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy", "release",
    "docs", "wiki", "confluence", "jira", "redmine", "help", "support", "kb",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic",
    "backup", "backups", "old", "new", "tmp", "temp", "archive", "files", "static",
    "cdn", "assets", "media", "img", "images", "upload", "uploads", "download",
    "shop", "store", "cart", "checkout", "pay", "payment", "billing", "invoice",
    "m", "mobile", "wap", "mobile-api", "m-api", "graphql", "gql", "rest", "rpc",
    "status", "health", "monitor", "grafana", "prometheus", "kibana", "elastic",
    "panel", "cpanel", "whm", "plesk", "manage", "manager", "console", "dashboard",
    "aws", "s3", "cloud", "cloudfront", "ec2", "lambda", "eks", "gke", "k8s",
    "docker", "registry", "harbor", "quay", "nexus", "artifactory",
    "chat", "chatbot", "bot", "webhook", "callback", "hook", "notify",
    "analytics", "track", "tracking", "log", "logs", "audit", "siem",
];

pub async fn brute(domain: &str, timeout: u64, wordlist: Option<&str>) -> anyhow::Result<()> {
    println!("{} Subdomain Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), domain);
    println!("{} Wordlist: {} entries", "[*]".cyan().bold(), BRUTE_WORDLIST.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut found = Vec::new();

    for word in BRUTE_WORDLIST {
        let subdomain = format!("{}.{}", word, domain);
        let url = format!("https://{}", subdomain);
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status != 404 && status != 0 {
                    let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
                    println!("  {} {:30} status={} server={}", "*".green(), subdomain, status, server);
                    found.push((subdomain.clone(), status, server));
                }
            }
            Err(_) => {}
        }
        // Also try HTTP
        let http_url = format!("http://{}", subdomain);
        if let Ok(resp) = client.get(&http_url).send().await {
            let status = resp.status().as_u16();
            if status != 404 && status != 0 && !found.iter().any(|(s, _, _)| s == &subdomain) {
                let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
                println!("  {} {:30} status={} server={}", "*".green(), subdomain, status, server);
                found.push((subdomain, status, server));
            }
        }
    }

    println!("\n{} {} subdomain(s) found", "[*]".cyan().bold(), found.len());
    Ok(())
}

pub async fn ct(domain: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Certificate Transparency Log Search", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), domain);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let ct_urls = [
        format!("https://crt.sh/?q=%25.{}&output=json", domain),
        format!("https://api.hackertarget.com/certtrans/?q={}", domain),
    ];

    let mut all_subs = std::collections::BTreeSet::new();

    for ct_url in &ct_urls {
        match client.get(ct_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if let Ok(entries) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(arr) = entries.as_array() {
                        for entry in arr {
                            if let Some(names) = entry.get("name_value").and_then(|n| n.as_str()) {
                                for name in names.split('\n') {
                                    let name = name.trim().trim_start_matches("*.");
                                    if name.ends_with(domain) { all_subs.insert(name.to_string()); }
                                }
                            }
                        }
                    }
                } else {
                    // Non-JSON response (hackertarget returns text)
                    for line in body.lines() {
                        let line = line.trim();
                        if line.ends_with(domain) { all_subs.insert(line.to_string()); }
                    }
                }
            }
            Err(_) => {}
        }
    }

    if all_subs.is_empty() {
        println!("{} No subdomains found via CT logs.", "[-]".yellow().bold());
    } else {
        println!("{} {} unique subdomain(s) found:", "[*]".cyan().bold(), all_subs.len());
        for sub in &all_subs { println!("  {} {}", "*".green(), sub); }
    }
    Ok(())
}

pub async fn passive(domain: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Passive Subdomain Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), domain);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let sources = [
        ("crt.sh", format!("https://crt.sh/?q=%25.{}&output=json", domain)),
        ("Hackertarget", format!("https://api.hackertarget.com/hostsearch/?q={}", domain)),
        ("ThreatCrowd", format!("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}", domain)),
        ("BufferOver", format!("https://tls.bufferover.run/dns?q={}", domain)),
        ("RapidDNS", format!("https://rapiddns.io/subdomain/{}?full=1", domain)),
    ];

    let mut all_subs = std::collections::BTreeSet::new();

    for (name, url) in &sources {
        match client.get(url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                let count_before = all_subs.len();
                for line in body.split(|c: char| c == '\n' || c == ',' || c == '"' || c == ' ') {
                    let line = line.trim().trim_start_matches("*.");
                    if line.ends_with(domain) && line != domain { all_subs.insert(line.to_string()); }
                }
                let new = all_subs.len() - count_before;
                println!("  {} {:15} — {} new subdomains", "*".cyan(), name, new);
            }
            Err(_) => { println!("  {} {:15} — error", "*".red(), name); }
        }
    }

    println!("\n{} {} total unique subdomain(s) from passive sources:", "[*]".cyan().bold(), all_subs.len());
    for sub in &all_subs { println!("  {} {}", "*".green(), sub); }
    Ok(())
}

pub async fn permutate(domain: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Subdomain Permutation Generation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), domain);
    println!("{}", "-".repeat(60).dimmed());

    let prefixes = ["dev", "stg", "staging", "prod", "test", "qa", "uat", "pre", "post", "v1", "v2", "new", "old", "beta", "alpha", "internal", "ext", "int"];
    let separators = ["-", ".", "_", ""];
    let base_words = ["api", "app", "web", "admin", "portal", "mail", "git", "ci", "vpn", "auth", "sso", "grafana", "k8s", "docker", "cloud", "shop", "store", "mobile", "cdn"];

    let mut permutations = std::collections::BTreeSet::new();
    for prefix in &prefixes {
        for sep in &separators {
            for word in &base_words {
                permutations.insert(format!("{}{}{}.{}", prefix, sep, word, domain));
            }
        }
    }
    for word in &base_words {
        permutations.insert(format!("{}.{}", word, domain));
        permutations.insert(format!("{}-{}.{}", word, "internal", domain));
        permutations.insert(format!("{}-{}.{}", word, "external", domain));
    }

    println!("{} {} permutations generated, resolving...", "[*]".cyan().bold(), permutations.len());

    let client = build_client(timeout);
    let mut found = Vec::new();

    for sub in &permutations {
        let url = format!("https://{}", sub);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status != 404 && status != 0 {
                println!("  {} {:35} status={}", "*".green(), sub, status);
                found.push(sub.clone());
            }
        }
    }

    println!("\n{} {} / {} permutations resolved", "[*]".cyan().bold(), found.len(), permutations.len());
    Ok(())
}
