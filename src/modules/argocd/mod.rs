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

const ARGOCD_ENDPOINTS: &[(&str, &str, &str)] = &[
    ("API versions", "/api/v1/version", "GET"),
    ("Applications", "/api/v1/applications", "GET"),
    ("Application (default)", "/api/v1/applications/default", "GET"),
    ("Clusters", "/api/v1/clusters", "GET"),
    ("Repositories", "/api/v1/repositories", "GET"),
    ("Repo certs", "/api/v1/certificates", "GET"),
    ("Accounts", "/api/v1/account", "GET"),
    ("Settings", "/api/v1/settings", "GET"),
    ("Projects", "/api/v1/projects", "GET"),
    ("Project (default)", "/api/v1/projects/default", "GET"),
    ("GPG keys", "/api/v1/gpgkeys", "GET"),
    ("Notifications", "/api/v1/notifications/services", "GET"),
    ("Application sync (POST)", "/api/v1/applications/default/sync", "POST"),
    ("Application refresh (GET)", "/api/v1/applications/default?refresh=true", "GET"),
    ("Cluster info", "/api/v1/clusters/https%3A%2F%2Fkubernetes.default.svc", "GET"),
    ("Repo connection", "/api/v1/repositories/https%3A%2F%2Fgithub.com%2Ftarget%2Frepo", "GET"),
    ("Stream logs", "/api/v1/stream/applications/default/logs", "GET"),
    ("Resource tree", "/api/v1/applications/default/resource-tree", "GET"),
    ("Manifests", "/api/v1/applications/default/manifests", "GET"),
    ("Operation logs", "/api/v1/applications/default/operation", "GET"),
    ("User info", "/api/v1/session", "GET"),
    ("Dex login", "/api/dex", "GET"),
    ("Health", "/api/v1/stream/applications/default/resource-tree", "GET"),
];

pub async fn enumerate(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} ArgoCD Enumeration & Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Testing {} ArgoCD endpoints", "[*]".cyan().bold(), ARGOCD_ENDPOINTS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');
    let mut accessible = Vec::new();

    for (name, path, method) in ARGOCD_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        let req = if *method == "POST" {
            client.post(&full_url).header("Content-Type", "application/json")
        } else {
            client.get(&full_url)
        };
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let allowed = status == 200 && !body.is_empty();
                let tag = if allowed {
                    "ACCESSIBLE".red().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:35} {:45} status={} {}",
                    "*".cyan(),
                    name,
                    path,
                    status,
                    tag
                );
                if allowed {
                    accessible.push((*name, *path, body.clone()));
                }
            }
            Err(_) => {
                println!("  {} {:35} error", "*".red(), name);
            }
        }
    }

    if !accessible.is_empty() {
        println!("\n{} Extracting data from accessible endpoints...", "[*]".cyan().bold());

        for (name, path, body) in &accessible {
            if *name == "Applications" {
                println!("\n{} Application listing:", "[!]".red().bold());
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
                        for app in items.iter().take(20) {
                            let app_name = app.get("metadata")
                                .and_then(|m| m.get("name"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("unknown");
                            let dest_namespace = app.get("spec")
                                .and_then(|s| s.get("destination"))
                                .and_then(|d| d.get("namespace"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("unknown");
                            let dest_server = app.get("spec")
                                .and_then(|s| s.get("destination"))
                                .and_then(|d| d.get("server"))
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown");
                            let sync_status = app.get("status")
                                .and_then(|s| s.get("sync"))
                                .and_then(|s| s.get("status"))
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown");
                            let repo_url = app.get("spec")
                                .and_then(|s| s.get("source"))
                                .and_then(|s| s.get("repoURL"))
                                .and_then(|r| r.as_str())
                                .unwrap_or("unknown");
                            println!(
                                "  {} app={:25} ns={:15} sync={:10} repo={}",
                                "*".cyan(),
                                app_name,
                                dest_namespace,
                                sync_status,
                                repo_url
                            );
                        }
                    }
                }
            }

            if *name == "Clusters" {
                println!("\n{} Cluster configuration:", "[!]".red().bold());
                println!("  {} {}", ">".red().bold(), body.chars().take(400).collect::<String>());
            }

            if *name == "Repositories" {
                println!("\n{} Repository credentials:", "[!]".red().bold());
                println!("  {} {}", ">".red().bold(), body.chars().take(400).collect::<String>());
            }

            if *name == "Settings" {
                println!("\n{} ArgoCD settings:", "[!]".red().bold());
                if body.contains("password") || body.contains("secret") || body.contains("credential") {
                    println!("  {} Contains sensitive configuration!", "[!]".red().bold());
                }
                println!("  {} {}", ">".red().bold(), body.chars().take(400).collect::<String>());
            }

            if *name == "Accounts" {
                println!("\n{} ArgoCD accounts:", "[!]".red().bold());
                println!("  {} {}", ">".red().bold(), body.chars().take(300).collect::<String>());
            }
        }

        let can_sync = accessible.iter().any(|(n, _, _)| *n == "Application sync (POST)");
        let can_refresh = accessible.iter().any(|(n, _, _)| *n == "Application refresh (GET)");
        if can_sync {
            println!("\n{} [CRITICAL] Can trigger application sync — deploy malicious manifests!", "[!]".red().bold());
        }
        if can_refresh {
            println!("{} [HIGH] Can refresh applications — force reconciliation with Git repo", "[!]".red().bold());
        }
    }

    println!(
        "\n{} {}/{} ArgoCD endpoints accessible",
        "[*]".cyan().bold(),
        accessible.len(),
        ARGOCD_ENDPOINTS.len()
    );
    if accessible.is_empty() {
        println!("{} ArgoCD requires authentication or is not exposed.", "[-]".green().bold());
    }
    Ok(())
}

pub async fn probe(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} ArgoCD Unauthenticated Probe", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, None);
    let base = url.trim_end_matches('/');
    let mut open = 0;

    for (name, path, method) in ARGOCD_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        let req = if *method == "POST" {
            client.post(&full_url)
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
                let body = resp.text().await.unwrap_or_default();
                let is_html = content_type.contains("text/html")
                    || body.trim_start().starts_with("<!doctype")
                    || body.trim_start().starts_with("<html");
                let is_open = status == 200 && !body.is_empty() && !is_html;
                let tag = if is_open {
                    "OPEN".red().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else {
                    "closed".dimmed().to_string()
                };
                println!("  {} {:35} status={} {}", "*".cyan(), name, status, tag);
                if is_open {
                    open += 1;
                    if body.len() > 100 {
                        println!("    {} {}", ">".red().bold(), body.chars().take(200).collect::<String>());
                    }
                }
            }
            Err(_) => {
                println!("  {} {:35} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} {}/{} endpoints open without authentication",
        "[*]".cyan().bold(),
        open,
        ARGOCD_ENDPOINTS.len()
    );
    if open > 0 {
        println!("{} ArgoCD is exposed without authentication — full cluster compromise possible!", "[!]".red().bold());
    }
    Ok(())
}
