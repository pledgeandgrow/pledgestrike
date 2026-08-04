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

pub async fn scan(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Debug Endpoint Scanner", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let debug_paths = [
        "/debug",
        "/debug/pprof",
        "/debug/vars",
        "/debug/requests",
        "/_debug",
        "/_debug/phpinfo.php",
        "/debug.php",
        "/status",
        "/server-status",
        "/server-info",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config",
        "/config.json",
        "/config.yml",
        "/config.yaml",
        "/info.php",
        "/phpinfo.php",
        "/test.php",
        "/console",
        "/admin/console",
        "/system/console",
        "/actuator",
        "/manage",
        "/management",
        "/swagger",
        "/swagger-ui",
        "/swagger-ui.html",
        "/api-docs",
        "/v1/api-docs",
        "/openapi.json",
        "/swagger.json",
        "/graphql",
        "/graphiql",
        "/playground",
        "/.git",
        "/.git/config",
        "/.svn/entries",
        "/backup",
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.sql",
        "/.well-known/security.txt",
        "/robots.txt",
        "/sitemap.xml",
        "/crossdomain.xml",
        "/trace",
        "/admin",
        "/admin/login",
        "/wp-admin",
        "/wp-login.php",
        "/wp-config.php",
        "/.DS_Store",
        "/Thumbs.db",
        "/web.config",
        "/error",
        "/500.html",
        "/debug.log",
        "/access.log",
    ];

    let mut found = 0u32;
    for path in &debug_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:30} — {} bytes",
                    "[+]".green().bold(),
                    path,
                    text.len()
                );
                found += 1;
                if text.contains("password") || text.contains("secret") || text.contains("api_key")
                {
                    println!("    {} Sensitive data detected!", "[!]".red().bold());
                }
            } else if status == 403 {
                println!("  {} {:30} — forbidden", "[!]".yellow().bold(), path);
            }
        }
    }

    println!(
        "\n  {} {} debug endpoints found",
        "[*]".cyan().bold(),
        found
    );

    Ok(())
}

pub async fn trace(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} HTTP Trace Method Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    match client.request(reqwest::Method::TRACE, url).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 {
                println!(
                    "  {} TRACE method enabled — request reflected",
                    "[!]".red().bold()
                );
                let preview: String = text.chars().take(200).collect();
                println!("  Response: {}", preview);
            } else {
                println!("  {} TRACE method — status={}", "[-]".dimmed(), status);
            }
        }
        Err(_) => println!("  {} TRACE method — error", "[-]".dimmed()),
    }

    let methods = ["OPTIONS", "DEBUG", "TRACK", "CONNECT"];
    for method in &methods {
        if let Ok(r) = client
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url)
            .send()
            .await
        {
            let status = r.status().as_u16();
            let allow = r
                .headers()
                .get("allow")
                .map(|v| v.to_str().unwrap_or(""))
                .unwrap_or("");
            if status == 200 || !allow.is_empty() {
                println!(
                    "  {} {:10} — status={} allow={}",
                    "[+]".green().bold(),
                    method,
                    status,
                    allow
                );
            }
        }
    }

    Ok(())
}

pub async fn stack(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Stack Trace Exposure", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let trigger_paths = [
        "/error",
        "/exception",
        "/throw",
        "/crash",
        "/nonexistent",
        "/null",
        "/undefined",
        "/api/v1/error",
        "/api/error",
        "/500",
    ];

    for path in &trigger_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if text.contains("StackTrace")
                || text.contains("at java.")
                || text.contains("at org.")
                || text.contains("Traceback")
            {
                println!(
                    "  {} {:20} — STACK TRACE EXPOSED (status={})",
                    "[!]".red().bold(),
                    path,
                    status
                );
            } else if text.contains("Exception") || text.contains("Error") {
                println!(
                    "  {} {:20} — error info leaked (status={})",
                    "[+]".green().bold(),
                    path,
                    status
                );
            }
        }
    }

    Ok(())
}

pub async fn source(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Source Code Exposure", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let source_paths = [
        "/.git/config",
        "/.git/HEAD",
        "/.git/index",
        "/.svn/entries",
        "/.svn/wc.db",
        "/.hg/store",
        "/.bzr/branch-format",
        "/CVS/Root",
        "/CVS/Entries",
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.rar",
        "/www.zip",
        "/site.zip",
        "/web.zip",
        "/html.zip",
        "/archive.zip",
        "/dist.zip",
        "/release.zip",
        "/config.php.bak",
        "/config.php~",
        "/config.php.old",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.backup",
        "/Dockerfile",
        "/docker-compose.yml",
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/Gemfile",
        "/Gemfile.lock",
        "/requirements.txt",
        "/composer.json",
        "/composer.lock",
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/.htaccess",
        "/.htpasswd",
        "/web.config",
        "/app.config",
        "/id_rsa",
        "/id_dsa",
        "/.ssh/id_rsa",
    ];

    let mut found = 0u32;
    for path in &source_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:30} — {} bytes",
                    "[!]".red().bold(),
                    path,
                    text.len()
                );
                found += 1;
            }
        }
    }

    println!("\n  {} {} source files exposed", "[*]".cyan().bold(), found);
    if found > 5 {
        println!("  {} Critical source code exposure!", "[!]".red().bold());
    }

    Ok(())
}
