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

const AZURE_ENDPOINTS: &[(&str, &str)] = &[
    (
        "Graph — applications",
        "https://graph.microsoft.com/v1.0/applications",
    ),
    (
        "Graph — service principals",
        "https://graph.microsoft.com/v1.0/servicePrincipals",
    ),
    ("Graph — users", "https://graph.microsoft.com/v1.0/users"),
    ("Graph — groups", "https://graph.microsoft.com/v1.0/groups"),
    (
        "Graph — directory roles",
        "https://graph.microsoft.com/v1.0/directoryRoles",
    ),
    (
        "Graph — role assignments",
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments",
    ),
    (
        "Graph — app role assignments",
        "https://graph.microsoft.com/v1.0/servicePrincipals/appRoleAssignedTo",
    ),
    (
        "Graph — oauth2 permission grants",
        "https://graph.microsoft.com/v1.0/oauth2PermissionGrants",
    ),
    (
        "Graph — conditional access",
        "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
    ),
    (
        "Graph — access reviews",
        "https://graph.microsoft.com/v1.0/accessReviews",
    ),
    (
        "ARM — subscriptions",
        "https://management.azure.com/subscriptions?api-version=2020-01-01",
    ),
    (
        "ARM — resource groups",
        "https://management.azure.com/subscriptions/-/resourceGroups?api-version=2021-04-01",
    ),
    (
        "ARM — key vaults",
        "https://management.azure.com/subscriptions/-/resources?api-version=2021-04-01&$filter=resourceType eq 'Microsoft.KeyVault/vaults'",
    ),
    (
        "Key Vault — secrets",
        "https://.vault.azure.net/secrets?api-version=7.3",
    ),
    (
        "Key Vault — keys",
        "https://.vault.azure.net/keys?api-version=7.3",
    ),
    (
        "Storage — accounts",
        "https://management.azure.com/subscriptions/-/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01",
    ),
    (
        "Azure AD — tenant info",
        "https://graph.microsoft.com/v1.0/organization",
    ),
    (
        "Azure AD — domains",
        "https://graph.microsoft.com/v1.0/domains",
    ),
];

pub async fn app(tenant: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Azure AD Application Abuse Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Tenant: {}", "[*]".cyan().bold(), tenant);
    println!(
        "{} Testing {} Azure AD endpoints",
        "[*]".cyan().bold(),
        AZURE_ENDPOINTS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut accessible = Vec::new();

    for (name, url_template) in AZURE_ENDPOINTS {
        let url = url_template.replace('-', tenant);
        match client.get(&url).send().await {
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
                println!("  {} {:45} status={} {}", "*".cyan(), name, status, tag);
                if allowed {
                    accessible.push((*name, body.chars().take(300).collect::<String>()));
                }
            }
            Err(_) => {
                println!("  {} {:45} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} Checking for excessive app permissions...",
        "[*]".cyan().bold()
    );
    let graph_url = "https://graph.microsoft.com/v1.0/applications";
    if let Ok(resp) = client.get(graph_url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(apps) = json.get("value").and_then(|v| v.as_array()) {
                    for app in apps.iter().take(20) {
                        let display_name = app
                            .get("displayName")
                            .and_then(|d| d.as_str())
                            .unwrap_or("unknown");
                        let app_id = app
                            .get("appId")
                            .and_then(|a| a.as_str())
                            .unwrap_or("unknown");
                        let required_access = app.get("requiredResourceAccess");
                        let perm_count = required_access
                            .and_then(|r| r.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        let tag = if perm_count > 5 {
                            "HIGH PERMS".red().bold().to_string()
                        } else if perm_count > 2 {
                            "medium".yellow().to_string()
                        } else {
                            "low".green().to_string()
                        };
                        println!(
                            "  {} {:30} appId={} perms={} {}",
                            "*".cyan(),
                            display_name,
                            &app_id[..app_id.len().min(20)],
                            perm_count,
                            tag
                        );
                    }
                }
            }
        }
    }

    println!(
        "\n{} Checking service principal role assignments...",
        "[*]".cyan().bold()
    );
    let roles_url = "https://graph.microsoft.com/v1.0/directoryRoles";
    if let Ok(resp) = client.get(roles_url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(roles) = json.get("value").and_then(|v| v.as_array()) {
                    for role in roles.iter().take(10) {
                        let desc = role
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("");
                        let display = role
                            .get("displayName")
                            .and_then(|d| d.as_str())
                            .unwrap_or("unknown");
                        let risk = if display.contains("Global") || display.contains("Admin") {
                            "CRITICAL".red().bold().to_string()
                        } else {
                            "info".green().to_string()
                        };
                        println!(
                            "  {} {:30} {} — {}",
                            "*".cyan(),
                            display,
                            risk,
                            desc.chars().take(50).collect::<String>()
                        );
                    }
                }
            }
        }
    }

    println!(
        "\n{} {}/{} endpoints accessible",
        "[*]".cyan().bold(),
        accessible.len(),
        AZURE_ENDPOINTS.len()
    );
    if !accessible.is_empty() {
        println!("{} Accessible Azure AD resources:", "[!]".red().bold());
        for (name, body) in &accessible {
            println!(
                "  {} {} — {}",
                "*".red(),
                name,
                body.chars().take(80).collect::<String>()
            );
        }
    }
    Ok(())
}
