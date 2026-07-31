use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(
            reqwest::header::HeaderMap::from_iter([(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
            )]),
        );
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

#[derive(Debug, Serialize, Deserialize)]
struct GraphQLResponse {
    data: Option<serde_json::Value>,
    errors: Option<Vec<serde_json::Value>>,
}

pub async fn introspect(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} GraphQL Introspection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let query = r#"{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name description type { name kind ofType { name kind } } args { name description type { name kind ofType { name kind } } } } inputFields { name description type { name kind ofType { name kind } } } enums { name description } interfaces { name } } directives { name description locations args { name description type { name kind ofType { name kind } } } } } }"}"#;

    let resp = client.post(url).header("Content-Type", "application/json").body(query.to_string()).send().await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    println!("{} Status: {}", "[*]".cyan().bold(), status);

    if body.contains("__schema") {
        println!("{} [HIGH] Introspection enabled!", "[!]".red().bold());
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        if let Some(types) = parsed["data"]["__schema"]["types"].as_array() {
            println!("{} Found {} types:", "[*]".cyan().bold(), types.len());
            for t in types.iter().take(30) {
                let name = t["name"].as_str().unwrap_or("?");
                let kind = t["kind"].as_str().unwrap_or("?");
                if !name.starts_with("__") {
                    println!("  {} {} ({})", "*".cyan(), name.yellow(), kind);
                    if let Some(fields) = t["fields"].as_array() {
                        for f in fields.iter().take(5) {
                            let fname = f["name"].as_str().unwrap_or("?");
                            println!("    {} {}", ">".dimmed(), fname);
                        }
                    }
                }
            }
        }
    } else if body.contains("errors") {
        println!("{} Introspection disabled or errors returned.", "[-]".yellow().bold());
        println!("  {} {}", "*".cyan(), body.chars().take(300).collect::<String>());
    } else {
        println!("{} Unexpected response.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn batch(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    count: usize,
) -> anyhow::Result<()> {
    println!("{} GraphQL Batch Query DoS", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Batch size: {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let single_query = r#"{"query":"{ __typename }"}"#;
    let batch: Vec<&str> = vec![single_query; count];
    let batch_json = format!("[{}]", batch.join(","));

    println!("{} Sending batch of {} queries...", "[*]".cyan().bold(), count);
    let start = std::time::Instant::now();
    let resp = client.post(url).header("Content-Type", "application/json").body(batch_json).send().await?;
    let elapsed = start.elapsed();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    println!("{} Status: {}", "[*]".cyan().bold(), status);
    println!("{} Time: {:.2}s", "[*]".cyan().bold(), elapsed.as_secs_f64());
    println!("{} Response length: {} bytes", "[*]".cyan().bold(), body.len());

    if elapsed.as_secs() > 5 {
        println!("{} [HIGH] Server vulnerable to batch query DoS — {}s response time", "[!]".red().bold(), elapsed.as_secs());
    } else {
        println!("{} No significant delay detected.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn suggest(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    wordlist: Option<&str>,
) -> anyhow::Result<()> {
    println!("{} GraphQL Field Suggestion Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let fields: Vec<String> = if let Some(wl) = wordlist {
        std::fs::read_to_string(wl)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        vec![
            "user", "users", "admin", "id", "email", "name", "password", "token",
            "session", "account", "post", "posts", "comment", "comments",
            "product", "products", "order", "orders", "payment", "payments",
            "file", "files", "upload", "config", "settings", "debug",
            "query", "mutation", "subscription", "node", "nodes", "edges",
            "createdAt", "updatedAt", "deletedAt", "role", "permissions",
            "apiKey", "secret", "key", "hash", "salt", "otp", "mfa",
        ].iter().map(|s| s.to_string()).collect()
    };

    let mut found = Vec::new();

    for field in &fields {
        let query = format!(r#"{{"query":"{{ {} }}"}}"#, field);
        let resp = client.post(url).header("Content-Type", "application/json").body(query).send().await;
        if let Ok(r) = resp {
            let body = r.text().await.unwrap_or_default();
            if body.contains("Did you mean") || body.contains("did you mean") {
                if let Some(start_idx) = body.find("did you mean") {
                    let snippet = &body[start_idx..body.len().min(start_idx + 100)];
                    found.push((field.clone(), snippet.to_string()));
                    println!("{} [+] Field suggestion for '{}': {}", "[+]".green().bold(), field.yellow(), snippet);
                }
            }
        }
    }

    if found.is_empty() {
        println!("{} No field suggestions leaked.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} field(s) leaked via suggestions", "[*]".cyan().bold(), found.len());
    }
    Ok(())
}

pub async fn depth(
    url: &str,
    token: Option<&str>,
    timeout: u64,
    max_depth: usize,
) -> anyhow::Result<()> {
    println!("{} GraphQL Query Depth Limit Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Max depth: {}", "[*]".cyan().bold(), max_depth);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    for depth in 1..=max_depth {
        let mut query = String::from("{ user { id");
        for _ in 0..depth {
            query.push_str(" user { id");
        }
        for _ in 0..depth {
            query.push_str(" }");
        }
        query.push_str(" } }");

        let payload = format!(r#"{{"query":"{}"}}"#, query.replace("\"", "\\\""));
        let start = std::time::Instant::now();
        let resp = client.post(url).header("Content-Type", "application/json").body(payload).send().await;
        let elapsed = start.elapsed();

        match resp {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let has_error = body.contains("depth") || body.contains("too deep") || body.contains("maximum");
                let status_str = if has_error { "BLOCKED".green().to_string() } else if elapsed.as_secs() > 3 { "SLOW".red().bold().to_string() } else { "ok".to_string() };
                println!("  {} depth={:3} status={} time={:.2}s {}", "*".cyan(), depth, status, elapsed.as_secs_f64(), status_str);

                if has_error {
                    println!("{} Depth limit found at depth {}", "[+]".green().bold(), depth);
                    break;
                }
            }
            Err(_) => {
                println!("  {} depth={:3} ERROR (timeout/refused)", "*".cyan(), depth);
                println!("{} Server may have crashed or rate-limited at depth {}", "[!]".red().bold(), depth);
                break;
            }
        }
    }

    println!("\n{} Depth limit test complete.", "[*]".cyan().bold());
    Ok(())
}
