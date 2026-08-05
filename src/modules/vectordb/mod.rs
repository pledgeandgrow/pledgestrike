use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .unwrap_or_else(|_| Client::new())
}

const VECTORDB_ENDPOINTS: &[(&str, &str, &str)] = &[
    // (path, method, description)
    ("/v1/collections", "GET", "Pinecone — list collections"),
    ("/v1/indexes", "GET", "Pinecone — list indexes"),
    ("/v1/vector/upsert", "POST", "Pinecone — upsert test"),
    ("/v1/vector/query", "POST", "Pinecone — query test"),
    ("/v1/describe-index-stats", "POST", "Pinecone — index stats"),
    ("/v1/schema", "GET", "Weaviate — get schema"),
    ("/v1/meta", "GET", "Weaviate — get meta"),
    ("/v1/objects", "GET", "Weaviate — list objects"),
    (
        "/v1/classifications",
        "GET",
        "Weaviate — list classifications",
    ),
    ("/v1/nodes", "GET", "Weaviate — cluster nodes"),
    ("/api/v1/collections", "GET", "Chroma — list collections"),
    (
        "/api/v1/collections/count",
        "GET",
        "Chroma — collection count",
    ),
    ("/api/v1/heartbeat", "GET", "Chroma — heartbeat"),
    ("/api/v2/collections", "GET", "Chroma v2 — list collections"),
    (
        "/api/v1/tenants/default_tenant",
        "GET",
        "Chroma — default tenant",
    ),
    ("/v1/collections", "GET", "Milvus — list collections (REST)"),
    ("/v1/partitions", "GET", "Milvus — list partitions"),
    ("/health", "GET", "Generic — health check"),
    ("/healthz", "GET", "Generic — healthz"),
    ("/readyz", "GET", "Generic — readyz"),
    ("/metrics", "GET", "Generic — Prometheus metrics"),
    ("/debug", "GET", "Generic — debug endpoint"),
    ("/api", "GET", "Generic — API root"),
    ("/api/v1", "GET", "Generic — API v1 root"),
    ("/", "GET", "Generic — root"),
];

const PROBE_PAYLOADS: &[(&str, &str)] = &[
    // Weaviate object query
    (
        "POST",
        r#"{"query":"{ Get { __schema { types { name } } } }"}"#,
    ),
    // Weaviate GraphQL
    ("POST", r#"{"query":"{ Aggregate { __typename } }"}"#),
    // Pinecone query
    (
        "POST",
        r#"{"vector":[0.1,0.2,0.3,0.4,0.5],"topK":10,"includeMetadata":true}"#,
    ),
    // Pinecone upsert
    (
        "POST",
        r#"{"vectors":[{"id":"test1","values":[0.1,0.2,0.3],"metadata":{"test":"true"}}]}"#,
    ),
    // Chroma list
    ("POST", r#"{"limit":100}"#),
    // Milvus search
    (
        "POST",
        r#"{"collection_name":"default","search_params":{"anns_field":"vector","topk":10}}"#,
    ),
    // Generic vector query
    ("POST", r#"{"query":[0.0,0.0,0.0,0.0,0.0],"n_results":10}"#),
];

pub async fn extract(
    url: &str,
    limit: u32,
    timeout: u64,
    token: Option<&str>,
) -> anyhow::Result<()> {
    println!("{} Vector DB Data Extraction", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Limit: {} records per query", "[*]".cyan().bold(), limit);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut extracted = 0u32;
    let mut accessible_endpoints = Vec::new();

    println!(
        "\n{} Probing vector DB API endpoints...",
        "[*]".cyan().bold()
    );
    for (path, method, desc) in VECTORDB_ENDPOINTS {
        let full_url = format!("{}{}", url.trim_end_matches('/'), path);
        let mut req = if *method == "POST" {
            client
                .post(&full_url)
                .header("Content-Type", "application/json")
        } else {
            client.get(&full_url)
        };
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let accessible = status == 200 || status == 201;
                let has_data = !text.is_empty()
                    && !text.contains("Not Found")
                    && !text.contains("Unauthorized")
                    && !text.contains("Forbidden");
                let tag = if accessible && has_data {
                    "ACCESSIBLE".green().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth-required".yellow().to_string()
                } else {
                    "not-found".dimmed().to_string()
                };
                println!(
                    "  {} {:6} {:30} status={} {} — {}",
                    "*".cyan(),
                    method,
                    path,
                    status,
                    tag,
                    desc
                );
                if accessible && has_data {
                    accessible_endpoints.push((path, method, text.clone()));
                }
            }
            Err(_) => {
                println!("  {} {:6} {:30} error", "*".red(), method, path);
            }
        }
    }

    if accessible_endpoints.is_empty() {
        println!("\n{} No accessible endpoints found.", "[-]".red().bold());
        return Ok(());
    }

    println!(
        "\n{} {} accessible endpoints found — attempting data extraction...",
        "[*]".cyan().bold(),
        accessible_endpoints.len()
    );

    for (path, method, initial_data) in &accessible_endpoints {
        println!(
            "\n{} Extracting from {} {}",
            "[*]".cyan().bold(),
            method,
            path
        );

        if initial_data.len() > 100 {
            println!(
                "  {} Initial response ({} bytes):",
                ">".cyan(),
                initial_data.len()
            );
            println!("    {}", initial_data.chars().take(500).collect::<String>());
            extracted += 1;
        }

        for (payload_method, payload) in PROBE_PAYLOADS {
            let full_url = format!("{}{}", url.trim_end_matches('/'), path);
            let mut req = if *payload_method == "POST" {
                client
                    .post(&full_url)
                    .header("Content-Type", "application/json")
                    .body(payload.to_string())
            } else {
                client.get(&full_url)
            };
            if let Some(t) = token {
                req = req.header("Authorization", format!("Bearer {}", t));
            }
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    if status == 200 && !text.is_empty() {
                        let has_vectors = text.contains("vector")
                            || text.contains("values")
                            || text.contains("embedding")
                            || text.contains("vectors")
                            || text.contains("score")
                            || text.contains("metadata")
                            || text.contains("id");
                        let tag = if has_vectors {
                            "VECTORS".green().bold().to_string()
                        } else {
                            "data".yellow().to_string()
                        };
                        println!(
                            "  {} [{:02}] status={} {} resp_len={}",
                            "*".cyan(),
                            extracted + 1,
                            status,
                            tag,
                            text.len()
                        );
                        if has_vectors {
                            println!(
                                "    {} {}",
                                ">".green().bold(),
                                text.chars().take(400).collect::<String>()
                            );
                            extracted += 1;
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    println!(
        "\n{} Extraction complete: {} data sources accessed",
        "[*]".cyan().bold(),
        extracted
    );
    if extracted > 0 {
        println!(
            "{} Vector embeddings and/or metadata accessible — sensitive data may be exposed.",
            "[!]".red().bold()
        );
    }
    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Vector DB Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut collections = Vec::new();

    println!(
        "\n{} Enumerating collections and schema...",
        "[*]".cyan().bold()
    );

    let enum_endpoints = [
        ("/v1/collections", "Pinecone collections"),
        ("/v1/indexes", "Pinecone indexes"),
        ("/v1/schema", "Weaviate schema"),
        ("/api/v1/collections", "Chroma collections"),
        ("/v1/collections", "Milvus collections"),
    ];

    for (path, desc) in &enum_endpoints {
        let full_url = format!("{}{}", url.trim_end_matches('/'), path);
        let mut req = client.get(&full_url);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {} — status=200 resp_len={}",
                        "*".green(),
                        desc,
                        text.len()
                    );
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(names) = json.get("names").and_then(|n| n.as_array()) {
                            for name in names {
                                if let Some(s) = name.as_str() {
                                    collections.push(s.to_string());
                                    println!("    {} collection: {}", ">".cyan(), s);
                                }
                            }
                        }
                        if let Some(arr) = json.as_array() {
                            for item in arr {
                                if let Some(s) = item.as_str() {
                                    collections.push(s.to_string());
                                    println!("    {} collection: {}", ">".cyan(), s);
                                } else if let Some(name) = item.get("name").and_then(|n| n.as_str())
                                {
                                    collections.push(name.to_string());
                                    println!("    {} collection: {}", ">".cyan(), name);
                                }
                            }
                        }
                        if let Some(classes) = json.get("classes").and_then(|c| c.as_array()) {
                            for class in classes {
                                if let Some(name) = class.get("class").and_then(|c| c.as_str()) {
                                    collections.push(name.to_string());
                                    println!("    {} class: {}", ">".cyan(), name);
                                }
                            }
                        }
                        if let Some(indexes) = json.get("indexes").and_then(|i| i.as_array()) {
                            for idx in indexes {
                                if let Some(name) = idx.get("name").and_then(|n| n.as_str()) {
                                    collections.push(name.to_string());
                                    println!("    {} index: {}", ">".cyan(), name);
                                }
                            }
                        }
                    } else {
                        println!(
                            "    {} {}",
                            ">".dimmed(),
                            text.chars().take(200).collect::<String>()
                        );
                    }
                } else {
                    println!("  {} {} — status={}", "*".dimmed(), desc, status);
                }
            }
            Err(_) => {
                println!("  {} {} — error", "*".red(), desc);
            }
        }
    }

    println!(
        "\n{} Found {} collections/indexes/classes",
        "[*]".cyan().bold(),
        collections.len()
    );
    if !collections.is_empty() {
        println!("{} Collections:", "[*]".cyan().bold());
        for c in &collections {
            println!("  {} {}", "-".cyan(), c);
        }
    }
    Ok(())
}

pub async fn probe(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Vector DB Unauthenticated Access Probe",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut open_count = 0u32;

    println!(
        "\n{} Testing without authentication...",
        "[*]".cyan().bold()
    );
    for (path, method, desc) in VECTORDB_ENDPOINTS {
        let full_url = format!("{}{}", url.trim_end_matches('/'), path);
        let req = if *method == "POST" {
            client
                .post(&full_url)
                .header("Content-Type", "application/json")
        } else {
            client.get(&full_url)
        };
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();
                let text = resp.text().await.unwrap_or_default();
                let is_html = content_type.contains("text/html")
                    || text.trim_start().starts_with("<!doctype")
                    || text.trim_start().starts_with("<html");
                let open = (status == 200 || status == 201) && !is_html && !text.is_empty();
                let tag = if open {
                    "OPEN".red().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else {
                    "closed".dimmed().to_string()
                };
                println!(
                    "  {} {:30} status={} {} — {}",
                    "*".cyan(),
                    path,
                    status,
                    tag,
                    desc
                );
                if open {
                    open_count += 1;
                    if text.len() > 50 {
                        println!(
                            "    {} {}",
                            ">".red().bold(),
                            text.chars().take(200).collect::<String>()
                        );
                    }
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".red(), path);
            }
        }
    }

    println!(
        "\n{} {}/{} endpoints accessible without authentication",
        "[*]".cyan().bold(),
        open_count,
        VECTORDB_ENDPOINTS.len()
    );
    if open_count > 0 {
        println!(
            "{} Vector DB is exposed without authentication — immediate data breach risk.",
            "[!]".red().bold()
        );
    } else {
        println!(
            "{} All endpoints require authentication.",
            "[+]".green().bold()
        );
    }
    Ok(())
}
