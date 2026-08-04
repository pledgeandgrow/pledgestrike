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

const GCP_ENDPOINTS: &[(&str, &str)] = &[
    ("Cloud Resource Manager — projects", "https://cloudresourcemanager.googleapis.com/v1/projects"),
    ("IAM — service accounts", "https://iam.googleapis.com/v1/projects/-/serviceAccounts"),
    ("IAM — roles", "https://iam.googleapis.com/v1/roles"),
    ("Compute — instances", "https://compute.googleapis.com/compute/v1/projects/-/zones/-/instances"),
    ("Storage — buckets", "https://storage.googleapis.com/storage/v1/b"),
    ("Cloud Functions", "https://cloudfunctions.googleapis.com/v1/projects/-/locations/-/functions"),
    ("Cloud Run services", "https://run.googleapis.com/v1/projects/-/locations/-/services"),
    ("Secret Manager", "https://secretmanager.googleapis.com/v1/projects/-/secrets"),
    ("KMS key rings", "https://cloudkms.googleapis.com/v1/projects/-/locations/-/keyRings"),
    ("GKE clusters", "https://container.googleapis.com/v1/projects/-/locations/-/clusters"),
    ("BigQuery datasets", "https://bigquery.googleapis.com/bigquery/v2/projects/-/datasets"),
    ("Pub/Sub topics", "https://pubsub.googleapis.com/v1/projects/-/topics"),
    ("Cloud SQL instances", "https://sqladmin.googleapis.com/v1/projects/-/instances"),
    ("App Engine apps", "https://appengine.googleapis.com/v1/apps/-"),
    ("Logging — entries", "https://logging.googleapis.com/v2/entries:list"),
    ("Cloud Build triggers", "https://cloudbuild.googleapis.com/v1/projects/-/triggers"),
    ("Artifact Registry", "https://artifactregistry.googleapis.com/v1/projects/-/locations/-/repositories"),
    ("Firestore", "https://firestore.googleapis.com/v1/projects/-/databases"),
];

const SA_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/devstorage.full_control",
    "https://www.googleapis.com/auth/devstorage.read_write",
    "https://www.googleapis.com/auth/datastore",
    "https://www.googleapis.com/auth/iam",
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/cloud-debugger",
];

pub async fn abuse(token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} GCP Service Account Abuse Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Testing {} GCP API endpoints", "[*]".cyan().bold(), GCP_ENDPOINTS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut accessible = Vec::new();

    for (name, url) in GCP_ENDPOINTS {
        match client.get(*url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let allowed = status == 200;
                let tag = if allowed {
                    "ACCESSIBLE".red().bold().to_string()
                } else if status == 401 || status == 403 {
                    "denied".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:45} status={} {}",
                    "*".cyan(),
                    name,
                    status,
                    tag
                );
                if allowed {
                    accessible.push((*name, body.chars().take(200).collect::<String>()));
                }
            }
            Err(_) => {
                println!("  {} {:45} error", "*".red(), name);
            }
        }
    }

    println!("\n{} Testing service account token scopes...", "[*]".cyan().bold());
    let token_info_url = "https://www.googleapis.com/oauth2/v1/tokeninfo";
    match client.get(token_info_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status == 200 {
                println!("  {} Token info: {}", "*".cyan(), body.chars().take(300).collect::<String>());
                for scope in SA_SCOPES {
                    if body.contains(scope) {
                        let risk = if scope.contains("cloud-platform") || scope.contains("iam") {
                            "CRITICAL".red().bold().to_string()
                        } else if scope.contains("full_control") || scope.contains("read_write") || scope.contains("admin") {
                            "HIGH".red().to_string()
                        } else {
                            "medium".yellow().to_string()
                        };
                        println!("    {} scope: {} — {}", ">".cyan(), scope.split('/').last().unwrap_or(scope), risk);
                    }
                }
            } else {
                println!("  {} Token info status={} — may need token parameter", "*".yellow(), status);
            }
        }
        Err(_) => {
            println!("  {} Token info error", "*".red());
        }
    }

    println!("\n{} Testing IAM signBlob / generateAccessToken...", "[*]".cyan().bold());
    let iam_endpoints = [
        ("Sign JWT", "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/-:signJwt"),
        ("Sign Blob", "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/-:signBlob"),
        ("Generate Access Token", "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/-:generateAccessToken"),
    ];
    for (name, url) in &iam_endpoints {
        match client.post(*url).header("Content-Type", "application/json").body(r#"{"payload":"test","delegates":[]}"#).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let tag = if status == 200 {
                    "ACCESSIBLE".red().bold().to_string()
                } else {
                    "denied".yellow().to_string()
                };
                println!("  {} {:30} status={} {}", "*".cyan(), name, status, tag);
                if status == 200 {
                    println!("    {} {}", ">".red().bold(), body.chars().take(200).collect::<String>());
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} {}/{} endpoints accessible",
        "[*]".cyan().bold(),
        accessible.len(),
        GCP_ENDPOINTS.len()
    );
    if !accessible.is_empty() {
        println!("{} Accessible GCP resources:", "[!]".red().bold());
        for (name, body) in &accessible {
            println!("  {} {} — {}", "*".red(), name, body.chars().take(80).collect::<String>());
        }
    }
    Ok(())
}
