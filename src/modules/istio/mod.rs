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

const ISTIO_ENDPOINTS: &[(&str, &str, &str, &str)] = &[
    ("Istiod debug", "/debug", "GET", "Istiod debug endpoint"),
    ("Istiod syncz", "/debug/syncz", "GET", "Istiod sync status"),
    (
        "Istiod configz",
        "/debug/configz",
        "GET",
        "Istiod config dump",
    ),
    (
        "Istiod endpointsz",
        "/debug/endpointsz",
        "GET",
        "Istiod endpoints",
    ),
    (
        "Istiod registryz",
        "/debug/registryz",
        "GET",
        "Istiod service registry",
    ),
    (
        "Istiod clusterz",
        "/debug/clusterz",
        "GET",
        "Istiod cluster config",
    ),
    (
        "Istiod secretz",
        "/debug/secretz",
        "GET",
        "Istiod secrets dump",
    ),
    (
        "Istiod networkz",
        "/debug/networkz",
        "GET",
        "Istiod network config",
    ),
    ("Istiod istsz", "/debug/istsz", "GET", "Istiod IST status"),
    ("Envoy admin", "/stats", "GET", "Envoy admin stats"),
    (
        "Envoy config dump",
        "/config_dump",
        "POST",
        "Envoy full config",
    ),
    ("Envoy clusters", "/clusters", "GET", "Envoy cluster info"),
    (
        "Envoy listeners",
        "/listeners",
        "GET",
        "Envoy listener info",
    ),
    (
        "Envoy server info",
        "/server_info",
        "GET",
        "Envoy server info",
    ),
    ("Envoy certs", "/certs", "GET", "Envoy TLS certificates"),
    ("Envoy ready", "/ready", "GET", "Envoy readiness"),
    ("Envoy logging", "/logging", "GET", "Envoy log levels"),
    ("Envoy tap", "/tap", "POST", "Envoy traffic tap"),
];

const ISTIO_PORTS: &[u16] = &[15010, 15012, 15014, 15017, 15020, 15021, 15000, 8080, 9090];

pub async fn enumerate(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Istio Service Mesh Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!(
        "{} Testing {} endpoints",
        "[*]".cyan().bold(),
        ISTIO_ENDPOINTS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');
    let mut accessible = Vec::new();

    for (name, path, method, desc) in ISTIO_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        let req = if *method == "POST" {
            client
                .post(&full_url)
                .header("Content-Type", "application/json")
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
                } else if status == 403 {
                    "forbidden".yellow().to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:30} {:15} status={} {} — {}",
                    "*".cyan(),
                    name,
                    path,
                    status,
                    tag,
                    desc
                );
                if allowed {
                    accessible.push((*name, *path, body.chars().take(300).collect::<String>()));
                }
            }
            Err(_) => {
                println!("  {} {:30} {:15} error", "*".red(), name, path);
            }
        }
    }

    println!(
        "\n{} Testing mTLS bypass — sending without client cert...",
        "[*]".cyan().bold()
    );
    let mtls_test_urls = [
        format!("{}/debug/registryz", base),
        format!("{}/debug/secretz", base),
        format!("{}/debug/configz", base),
    ];
    for test_url in &mtls_test_urls {
        match client
            .get(test_url)
            .header("X-Forwarded-Client-Cert", "")
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let bypassed = status == 200 && !body.is_empty();
                let tag = if bypassed {
                    "BYPASSED".red().bold().to_string()
                } else {
                    "blocked".green().to_string()
                };
                println!("  {} {:50} status={} {}", "*".cyan(), test_url, status, tag);
                if bypassed {
                    println!(
                        "    {} {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:50} error", "*".red(), test_url);
            }
        }
    }

    println!(
        "\n{} Testing Istio policy bypass headers...",
        "[*]".cyan().bold()
    );
    let bypass_headers = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "10.0.0.1"),
        ("X-Request-Id", "test"),
        ("X-Envoy-Internal", "true"),
        ("X-Istio-External-Address", "127.0.0.1"),
    ];
    for (header, value) in &bypass_headers {
        let test_url = format!("{}/debug/syncz", base);
        match client.get(&test_url).header(*header, *value).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let tag = if status == 200 {
                    "BYPASSED".red().bold().to_string()
                } else {
                    "blocked".green().to_string()
                };
                println!(
                    "  {} {:30}={:15} status={} {}",
                    "*".cyan(),
                    header,
                    value,
                    status,
                    tag
                );
            }
            Err(_) => {
                println!("  {} {:30} error", "*".red(), header);
            }
        }
    }

    println!(
        "\n{} {}/{} Istio endpoints accessible",
        "[*]".cyan().bold(),
        accessible.len(),
        ISTIO_ENDPOINTS.len()
    );
    if !accessible.is_empty() {
        println!("{} Accessible Istio resources:", "[!]".red().bold());
        for (name, path, body) in &accessible {
            println!(
                "  {} {} {} — {}",
                "*".red(),
                name,
                path,
                body.chars().take(80).collect::<String>()
            );
        }
    }
    Ok(())
}

pub async fn probe(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Istio Unauthenticated Probe", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, None);
    let base = url.trim_end_matches('/');
    let mut open = 0;

    for (name, path, method, desc) in ISTIO_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        let req = if *method == "POST" {
            client.post(&full_url)
        } else {
            client.get(&full_url)
        };
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let is_open = status == 200 && !body.is_empty();
                let tag = if is_open {
                    "OPEN".red().bold().to_string()
                } else if status == 401 || status == 403 {
                    "auth".yellow().to_string()
                } else {
                    "closed".dimmed().to_string()
                };
                println!(
                    "  {} {:30} status={} {} — {}",
                    "*".cyan(),
                    name,
                    status,
                    tag,
                    desc
                );
                if is_open {
                    open += 1;
                    println!(
                        "    {} {}",
                        ">".red().bold(),
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} {}/{} endpoints open without authentication",
        "[*]".cyan().bold(),
        open,
        ISTIO_ENDPOINTS.len()
    );
    if open > 0 {
        println!(
            "{} Istio control plane exposed — mesh can be enumerated and manipulated!",
            "[!]".red().bold()
        );
    }
    Ok(())
}
