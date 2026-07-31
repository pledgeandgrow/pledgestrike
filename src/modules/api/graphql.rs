use colored::Colorize;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::sleep;

use super::client::build_client;

pub async fn graphql(
    endpoint_url: &str,
    token: Option<&str>,
    suggest: bool,
    wordlist_path: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    let client = build_client(timeout, token, None, None)?;

    println!("{} GraphQL Discovery", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} Endpoint: {}", "[*]".cyan().bold(), endpoint_url.green());
    println!("{}", "─".repeat(60).dimmed());

    // 1. Check if endpoint exists and responds to GraphQL
    println!("\n{} Checking endpoint...", "[*]".cyan().bold());

    let probe_query = json!({
        "query": "{ __typename }"
    });

    let resp = client.post(endpoint_url).json(&probe_query).send().await;

    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();

            if status == 200 && (body.contains("__typename") || body.contains("data")) {
                println!("{} GraphQL endpoint confirmed! (HTTP {})", "[+]".green().bold(), status);
            } else if body.to_lowercase().contains("graphql") {
                println!("{} Likely GraphQL endpoint (HTTP {})", "[+]".green().bold(), status);
            } else {
                println!("{} Endpoint responded (HTTP {}) — may not be GraphQL", "[?]".yellow().bold(), status);
                println!("    Response: {}", &body[..body.len().min(200)]);
            }
        }
        Err(e) => {
            println!("{} Endpoint unreachable: {}", "[-]".red().bold(), e);
            return Ok(());
        }
    }

    // 2. Introspection query
    println!("\n{} Testing introspection...", "[*]".cyan().bold());

    let introspection = json!({
        "query": r#"
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name
              kind
              description
              fields {
                name
                description
                type {
                  name
                  kind
                  ofType { name kind }
                }
                args {
                  name
                  description
                  type {
                    name
                    kind
                    ofType { name kind }
                  }
                }
              }
            }
          }
        }
        "#
    });

    match client.post(endpoint_url).json(&introspection).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();

            if status == 200 {
                match serde_json::from_str::<Value>(&body) {
                    Ok(v) => {
                        if let Some(schema) = v.get("data").and_then(|d| d.get("__schema")) {
                            println!("{} Introspection ENABLED — schema leaked!", "[+]".green().bold().blink());

                            let types = schema.get("types").and_then(|t| t.as_array()).map(|a| a.len()).unwrap_or(0);
                            let query_type = schema.get("queryType").and_then(|q| q.get("name")).and_then(|n| n.as_str()).unwrap_or("unknown");
                            let mutation_type = schema.get("mutationType").and_then(|m| m.get("name")).and_then(|n| n.as_str()).unwrap_or("none");
                            let sub_type = schema.get("subscriptionType").and_then(|s| s.get("name")).and_then(|n| n.as_str()).unwrap_or("none");

                            println!("    Query type:        {}", query_type.cyan());
                            println!("    Mutation type:     {}", mutation_type.cyan());
                            println!("    Subscription type: {}", sub_type.cyan());
                            println!("    Types discovered:  {}", types);

                            // Print interesting types (not built-in)
                            if let Some(types_arr) = schema.get("types").and_then(|t| t.as_array()) {
                                let custom: Vec<&Value> = types_arr.iter().filter(|t| {
                                    let kind = t.get("kind").and_then(|k| k.as_str()).unwrap_or("");
                                    let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
                                    kind == "OBJECT" && !name.starts_with("__") && !name.starts_with("String") && !name.starts_with("Int") && !name.starts_with("Boolean") && !name.starts_with("ID") && !name.starts_with("Float")
                                }).collect();

                                if !custom.is_empty() {
                                    println!("\n    {} Custom types:", "[*]".cyan().bold());
                                    for t in custom.iter().take(20) {
                                        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                                        let fields = t.get("fields").and_then(|f| f.as_array()).map(|a| a.len()).unwrap_or(0);
                                        println!("      {} {} ({} fields)", "•".cyan(), name.white().bold(), fields);
                                    }
                                }
                            }
                        } else if let Some(errors) = v.get("errors") {
                            println!("{} Introspection disabled — errors returned:", "[-]".red().bold());
                            if let Some(arr) = errors.as_array() {
                                for e in arr.iter().take(3) {
                                    let msg = e.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
                                    println!("    {}", msg.dimmed());
                                }
                            }
                        }
                    }
                    Err(_) => {
                        println!("{} Introspection returned non-JSON response", "[-]".red().bold());
                    }
                }
            } else {
                println!("{} Introspection returned HTTP {}", "[-]".red().bold(), status);
            }
        }
        Err(e) => {
            println!("{} Introspection request failed: {}", "[-]".red().bold(), e);
        }
    }

    // 3. Field suggestion attack
    if suggest {
        println!("\n{} Field suggestion attack...", "[*]".cyan().bold());

        let wordlist = match wordlist_path {
            Some(path) => std::fs::read_to_string(path)?
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect::<Vec<_>>(),
            None => {
                // Built-in common field names
                vec![
                    "id", "name", "email", "username", "password", "token", "role",
                    "admin", "user", "users", "posts", "comments", "products",
                    "orders", "sessions", "apiKey", "secret", "ssn", "creditCard",
                    "phone", "address", "avatar", "bio", "status", "createdAt",
                    "updatedAt", "deletedAt", "isActive", "isAdmin", "permissions",
                    "settings", "config", "debug", "internal", "private", "public",
                    "title", "description", "content", "url", "image", "file",
                    "upload", "download", "export", "import", "search", "filter",
                    "sort", "page", "limit", "offset", "cursor", "total", "count",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect()
            }
        };

        println!("{} Testing {} field names...", "[*]".cyan().bold(), wordlist.len());

        let mut found_fields = Vec::new();

        for field in &wordlist {
            // Try querying the field on Query type
            let query = json!({
                "query": format!("{{ {} }}", field)
            });

            match client.post(endpoint_url).json(&query).send().await {
                Ok(r) => {
                    let body = r.text().await.unwrap_or_default();

                    // GraphQL errors often suggest correct field names
                    // "Cannot query field 'xxx'. Did you mean 'yyy'?"
                    if body.contains("Did you mean") {
                        let suggestions = extract_suggestions(&body);
                        for s in &suggestions {
                            if !found_fields.contains(s) {
                                found_fields.push(s.clone());
                                eprintln!(
                                    "{} Field suggested: {} (from probing '{}')",
                                    "[+]".green().bold(),
                                    s.yellow().bold(),
                                    field,
                                );
                            }
                        }
                    }

                    // If the field is valid, we get data not errors
                    if body.contains("\"data\"") && !body.contains("\"errors\"") {
                        if !found_fields.contains(field) {
                            found_fields.push(field.clone());
                            eprintln!(
                                "{} Valid field: {}",
                                "[+]".green().bold(),
                                field.yellow().bold(),
                            );
                        }
                    }
                }
                Err(_) => {}
            }

            sleep(Duration::from_millis(50)).await;
        }

        println!("\n{} Field suggestion results:", "[*]".cyan().bold());
        if found_fields.is_empty() {
            println!("{} No fields discovered via suggestion", "[-]".red().bold());
        } else {
            println!("{} {} field(s) discovered:", "[+]".green().bold(), found_fields.len());
            for f in &found_fields {
                println!("  {} {}", "•".cyan(), f.white().bold());
            }
        }
    }

    // 4. Common GraphQL vulnerabilities
    println!("\n{} Testing common GraphQL vulns...", "[*]".cyan().bold());

    // Batch query attack
    let batch = json!([
        { "query": "{ __typename }" },
        { "query": "{ __typename }" },
        { "query": "{ __typename }" },
    ]);

    match client.post(endpoint_url).json(&batch).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            if status == 200 && body.starts_with('[') {
                println!("{} Batch queries ENABLED — potential DoS vector", "[!]".yellow().bold());
            } else {
                println!("{} Batch queries not supported", "[-]".dimmed());
            }
        }
        Err(_) => {}
    }

    // Query depth attack detection
    let deep_query = json!({
        "query": "{ __schema { types { fields { type { ofType { ofType { ofType { ofType { name } } } } } } } } }"
    });

    match client.post(endpoint_url).json(&deep_query).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            if status == 200 && !body.contains("depth") && !body.contains("Depth") {
                println!("{} No query depth limit — potential DoS via deep nesting", "[!]".yellow().bold());
            } else if body.to_lowercase().contains("depth") {
                println!("{} Query depth limit enforced", "[-]".dimmed());
            }
        }
        Err(_) => {}
    }

    println!("\n{}", "═".repeat(60).cyan());
    println!("{} GraphQL discovery complete", "[*]".cyan().bold());

    Ok(())
}

fn extract_suggestions(body: &str) -> Vec<String> {
    let mut suggestions = Vec::new();

    // Parse "Did you mean 'xxx'?" patterns
    let mut rest = body;
    while let Some(idx) = rest.find("Did you mean") {
        rest = &rest[idx..];
        // Find quoted strings after "Did you mean"
        if let Some(start) = rest.find('\'') {
            let after_start = &rest[start + 1..];
            if let Some(end) = after_start.find('\'') {
                let suggestion = &after_start[..end];
                if !suggestion.is_empty() {
                    suggestions.push(suggestion.to_string());
                }
                rest = &after_start[end + 1..];
            } else {
                break;
            }
        } else {
            break;
        }
    }

    suggestions
}
