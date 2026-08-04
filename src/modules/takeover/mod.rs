use colored::Colorize;
use hickory_resolver::{TokioAsyncResolver, name_server::TokioConnectionProvider};
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

async fn build_resolver() -> anyhow::Result<TokioAsyncResolver> {
    let mut config = hickory_resolver::config::ResolverConfig::new();
    config.add_name_server(hickory_resolver::config::NameServerConfig {
        socket_addr: std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            53,
        ),
        protocol: hickory_resolver::config::Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    config.add_name_server(hickory_resolver::config::NameServerConfig {
        socket_addr: std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            53,
        ),
        protocol: hickory_resolver::config::Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    let mut opts = hickory_resolver::config::ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    Ok(TokioAsyncResolver::new(
        config,
        opts,
        TokioConnectionProvider::default(),
    ))
}

struct DnsInfo {
    cname: Option<String>,
    a_records: Vec<String>,
    is_wildcard: bool,
}

async fn lookup_dns(resolver: &TokioAsyncResolver, domain: &str, wildcard_domain: &str) -> DnsInfo {
    let cname = match resolver
        .lookup(
            domain.to_string(),
            hickory_resolver::proto::rr::RecordType::CNAME,
        )
        .await
    {
        Ok(r) => r.iter().next().map(|c| c.to_string()),
        Err(_) => None,
    };

    let a_records = match resolver
        .lookup(
            domain.to_string(),
            hickory_resolver::proto::rr::RecordType::A,
        )
        .await
    {
        Ok(r) => r.iter().map(|ip| ip.to_string()).collect(),
        Err(_) => Vec::new(),
    };

    let wildcard_a = match resolver
        .lookup(
            wildcard_domain.to_string(),
            hickory_resolver::proto::rr::RecordType::A,
        )
        .await
    {
        Ok(r) => r.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };

    let is_wildcard = !wildcard_a.is_empty()
        && !a_records.is_empty()
        && a_records.iter().all(|ip| wildcard_a.contains(ip));

    DnsInfo {
        cname,
        a_records,
        is_wildcard,
    }
}

struct Fingerprint {
    service: &'static str,
    cname: &'static str,
    response: &'static str,
    body: &'static str,
}

const FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        service: "GitHub Pages",
        cname: "github.io",
        response: "404",
        body: "There isn't a GitHub Pages site here",
    },
    Fingerprint {
        service: "AWS S3",
        cname: "s3.amazonaws.com",
        response: "404",
        body: "The specified bucket does not exist",
    },
    Fingerprint {
        service: "AWS S3",
        cname: "s3-website",
        response: "404",
        body: "The specified bucket does not exist",
    },
    Fingerprint {
        service: "Heroku",
        cname: "herokuapp.com",
        response: "404",
        body: "No such app",
    },
    Fingerprint {
        service: "Heroku",
        cname: "herokussl.com",
        response: "404",
        body: "No such app",
    },
    Fingerprint {
        service: "Shopify",
        cname: "myshopify.com",
        response: "404",
        body: "Sorry, this shop is currently unavailable",
    },
    Fingerprint {
        service: "Tumblr",
        cname: "tumblr.com",
        response: "404",
        body: "Whatever you were looking for doesn't currently exist at this address",
    },
    Fingerprint {
        service: "Bitbucket",
        cname: "bitbucket.io",
        response: "404",
        body: "Repository not found",
    },
    Fingerprint {
        service: "Fastly",
        cname: "fastly.net",
        response: "404",
        body: "Fastly error: unknown domain",
    },
    Fingerprint {
        service: "Ghost",
        cname: "ghost.io",
        response: "404",
        body: "The page you are looking for doesn't exist",
    },
    Fingerprint {
        service: "Pantheon",
        cname: "pantheonsite.io",
        response: "404",
        body: "The gods are wise",
    },
    Fingerprint {
        service: "Tilda",
        cname: "tilda.ws",
        response: "404",
        body: "Please renew your subscription",
    },
    Fingerprint {
        service: "Unbounce",
        cname: "unbouncepages.com",
        response: "404",
        body: "The requested URL was not found",
    },
    Fingerprint {
        service: "Webflow",
        cname: "webflow.io",
        response: "404",
        body: "The page you are looking for doesn't exist",
    },
    Fingerprint {
        service: "Wordpress",
        cname: "wordpress.com",
        response: "404",
        body: "Do you want to register",
    },
    Fingerprint {
        service: "Cargo",
        cname: "cargocollective.com",
        response: "404",
        body: "404 Not Found",
    },
    Fingerprint {
        service: "Smugmug",
        cname: "smugmug.com",
        response: "404",
        body: "404 Not Found",
    },
    Fingerprint {
        service: "Surge.sh",
        cname: "surge.sh",
        response: "404",
        body: "project not found",
    },
    Fingerprint {
        service: "Netlify",
        cname: "netlify.app",
        response: "404",
        body: "Not Found - Request ID",
    },
    Fingerprint {
        service: "Vercel",
        cname: "vercel.app",
        response: "404",
        body: "The deployment could not be found",
    },
];

pub async fn scan(domains_file: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    #![allow(unused_assignments)]
    println!(
        "{} Subdomain Takeover Scan (with DNS verification)",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} File: {}", "[*]".cyan().bold(), domains_file);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let resolver = build_resolver().await?;

    let domains: Vec<String> = std::fs::read_to_string(domains_file)?
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    println!("{} Loaded {} domains", "[*]".cyan().bold(), domains.len());

    let base_domain = domains
        .first()
        .map(|d| {
            d.split('.')
                .rev()
                .take(2)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(".")
        })
        .unwrap_or_default();
    let wildcard_probe = format!("zzz-not-real-{}.{}", rand::random::<u32>(), base_domain);
    println!("{} Wildcard probe: {}", "[*]".cyan().bold(), wildcard_probe);

    let wildcard_a = match resolver
        .lookup(
            wildcard_probe.clone(),
            hickory_resolver::proto::rr::RecordType::A,
        )
        .await
    {
        Ok(r) => r.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    if !wildcard_a.is_empty() {
        println!(
            "{} Wildcard DNS detected — IPs: {}",
            "[!]".yellow().bold(),
            wildcard_a.join(", ")
        );
        println!(
            "{} Subdomains resolving to these IPs will be filtered as wildcard false positives.",
            "[*]".cyan().bold()
        );
    } else {
        println!("{} No wildcard DNS detected.", "[+]".green().bold());
    }
    println!();

    let mut vulnerable: Vec<(String, &str, &str, u16, String)> = Vec::new();
    let mut not_vulnerable: Vec<(String, u16)> = Vec::new();
    let mut wildcard_filtered: Vec<(String, u16)> = Vec::new();
    let mut dns_failed: Vec<String> = Vec::new();
    let mut dangling_cname: Vec<(String, String)> = Vec::new();

    for domain in &domains {
        let url = if domain.starts_with("http") {
            domain.clone()
        } else {
            format!("https://{}", domain)
        };
        let http_url = if domain.starts_with("http") {
            domain.replace("https://", "http://")
        } else {
            format!("http://{}", domain)
        };

        let dns = lookup_dns(&resolver, domain, &wildcard_probe).await;

        let mut found_vuln = false;
        #[allow(unused_assignments)]
        let mut resolved = false;

        for test_url in [&url, &http_url] {
            match client.get(test_url).send().await {
                Ok(resp) => {
                    resolved = true;
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();

                    for fp in FINGERPRINTS {
                        if (status == 404 || status == 502 || status == 503)
                            && body.contains(fp.body)
                        {
                            if dns.is_wildcard && dns.cname.is_none() {
                                wildcard_filtered.push((domain.clone(), status));
                            } else if let Some(ref cname) = dns.cname {
                                if cname.contains(fp.cname) {
                                    vulnerable.push((
                                        domain.clone(),
                                        fp.service,
                                        fp.cname,
                                        status,
                                        cname.clone(),
                                    ));
                                } else {
                                    wildcard_filtered.push((domain.clone(), status));
                                }
                            } else if dns.is_wildcard {
                                wildcard_filtered.push((domain.clone(), status));
                            } else {
                                vulnerable.push((
                                    domain.clone(),
                                    fp.service,
                                    fp.cname,
                                    status,
                                    "no CNAME".to_string(),
                                ));
                            }
                            found_vuln = true;
                            break;
                        }
                    }
                    if !found_vuln {
                        not_vulnerable.push((domain.clone(), status));
                    }
                    break;
                }
                Err(e) => {
                    let err_str = format!("{}", e);
                    if err_str.contains("dns")
                        || err_str.contains("resolve")
                        || err_str.contains("name resolution")
                    {
                        if let Some(ref cname) = dns.cname {
                            dangling_cname.push((domain.clone(), cname.clone()));
                        } else {
                            dns_failed.push(domain.clone());
                        }
                    }
                }
            }
            if found_vuln || resolved {
                break;
            }
        }
    }

    println!(
        "{} Not Vulnerable ({}):",
        "[-]".green().bold(),
        not_vulnerable.len()
    );
    println!("{}", "-".repeat(60).dimmed());
    for (domain, status) in &not_vulnerable {
        println!("  {} {:40} status={}", "[+]".green().bold(), domain, status);
    }

    if !wildcard_filtered.is_empty() {
        println!(
            "\n{} Wildcard DNS False Positives ({}):",
            "[*]".dimmed(),
            wildcard_filtered.len()
        );
        println!("{}", "-".repeat(60).dimmed());
        for (domain, status) in &wildcard_filtered {
            println!(
                "  {} {:40} status={} (wildcard DNS, not exploitable)",
                "[-]".dimmed(),
                domain,
                status
            );
        }
    }

    if !dangling_cname.is_empty() {
        println!(
            "\n{} Dangling CNAME — Takeover Likely ({}):",
            "[!]".red().bold(),
            dangling_cname.len()
        );
        println!("{}", "-".repeat(60).dimmed());
        for (domain, cname) in &dangling_cname {
            println!(
                "  {} {:40} CNAME -> {} (HTTP failed, DNS resolves)",
                "[!]".red().bold(),
                domain,
                cname
            );
        }
    }

    if !dns_failed.is_empty() {
        println!(
            "\n{} DNS Resolution Failed ({}):",
            "[?]".yellow().bold(),
            dns_failed.len()
        );
        println!("{}", "-".repeat(60).dimmed());
        for domain in &dns_failed {
            println!(
                "  {} {:40} — no A/CNAME records",
                "[?]".yellow().bold(),
                domain
            );
        }
    }

    if vulnerable.is_empty() {
        println!(
            "\n{} No takeover vulnerabilities found.",
            "[-]".yellow().bold()
        );
    } else {
        println!(
            "\n{} Vulnerable — CNAME-Verified Takeover Possible ({}):",
            "[!]".red().bold(),
            vulnerable.len()
        );
        println!("{}", "-".repeat(60).dimmed());
        for (domain, service, cname, status, cname_val) in &vulnerable {
            println!(
                "  {} {:40} {} ({}) status={}",
                "[!]".red().bold(),
                domain,
                service,
                cname,
                status
            );
            println!("    {} CNAME: {}", "*".red(), cname_val);
        }
    }

    let total_safe = not_vulnerable.len() + wildcard_filtered.len();
    let total_real_risk = vulnerable.len() + dangling_cname.len();
    println!(
        "\n{} Summary: {} safe, {} wildcard false positives, {} real risk, {} DNS failed",
        "[*]".cyan().bold(),
        total_safe,
        wildcard_filtered.len(),
        total_real_risk,
        dns_failed.len()
    );

    Ok(())
}

pub async fn verify(domain: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Subdomain Takeover Verification", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), domain);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };
    let http_url = if domain.starts_with("http") {
        domain.replace("https://", "http://")
    } else {
        format!("http://{}", domain)
    };

    let mut found = false;

    for test_url in [&url, &http_url] {
        match client.get(test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();

                println!("{} Testing: {}", "[*]".cyan().bold(), test_url);
                println!("  {} Status: {}", "*".cyan(), status);
                println!("  {} Body length: {} bytes", "*".cyan(), body.len());

                if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
                    println!("  {} Server: {}", "*".cyan(), server);
                }

                for fp in FINGERPRINTS {
                    if body.contains(fp.body) {
                        println!("\n{} [VULN] Takeover confirmed!", "[!]".red().bold());
                        println!("  {} Service:  {}", "*".red(), fp.service);
                        println!("  {} CNAME:    {}", "*".red(), fp.cname);
                        println!("  {} Marker:   {}", "*".red(), fp.body);
                        found = true;
                        break;
                    }
                }

                if !found && (status == 404 || status == 502 || status == 503) {
                    println!(
                        "\n{} Status {} but no known fingerprint matched.",
                        "[-]".yellow().bold(),
                        status
                    );
                    println!(
                        "  {} First 200 chars: {}",
                        "*".cyan(),
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if err_str.contains("dns")
                    || err_str.contains("resolve")
                    || err_str.contains("name resolution")
                {
                    println!(
                        "{} [?] DNS resolution failed — domain may have dangling CNAME",
                        "[?]".yellow().bold()
                    );
                    println!("  {} Run: nslookup -type=cname {}", "*".cyan(), domain);
                    found = true;
                } else {
                    println!("{} Connection error: {}", "[-]".red().bold(), err_str);
                }
            }
        }
    }

    if !found {
        println!(
            "\n{} No takeover vulnerability detected.",
            "[-]".yellow().bold()
        );
    }
    Ok(())
}

pub async fn fingerprint(domain: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Subdomain Fingerprinting", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), domain);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let body = resp.text().await.unwrap_or_default();

            println!("{} Response Analysis:", "[*]".cyan().bold());
            println!("  {} Status: {}", "*".cyan(), status);
            println!("  {} Body length: {} bytes", "*".cyan(), body.len());

            let interesting_headers = [
                "server",
                "x-powered-by",
                "x-amz-request-id",
                "x-served-by",
                "x-cache",
                "via",
                "x-fastly-request-id",
                "x-vercel-id",
                "x-netlify-request-id",
                "x-pantheon-request-id",
                "x-tumblr-user",
                "x-github-request",
            ];

            for h in &interesting_headers {
                if let Some(val) = headers.get(*h).and_then(|v| v.to_str().ok()) {
                    println!("  {} {}: {}", "*".cyan(), h, val);
                }
            }

            println!("\n{} Fingerprint Matching:", "[*]".cyan().bold());
            let mut matched = false;
            for fp in FINGERPRINTS {
                if body.contains(fp.body) {
                    println!(
                        "  {} [MATCH] {} — CNAME: {}",
                        "*".green().bold(),
                        fp.service,
                        fp.cname
                    );
                    matched = true;
                }
            }

            if !matched {
                println!("  {} No known service fingerprint matched.", "[-]".dimmed());
                if !body.is_empty() {
                    println!("\n  {} Body preview:", "*".cyan());
                    println!("  {}", body.chars().take(300).collect::<String>());
                }
            }
        }
        Err(e) => {
            let err_str = format!("{}", e);
            if err_str.contains("dns") || err_str.contains("resolve") {
                println!(
                    "{} DNS resolution failed — likely dangling CNAME",
                    "[?]".yellow().bold()
                );
            } else {
                println!("{} Error: {}", "[-]".red().bold(), err_str);
            }
        }
    }

    println!("\n{} Fingerprinting complete.", "[*]".cyan().bold());
    Ok(())
}
