use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::time::Duration;

pub fn build_client(
    timeout: u64,
    token: Option<&str>,
    api_key: Option<&str>,
    custom_headers: Option<&str>,
) -> anyhow::Result<reqwest::Client> {
    let mut headers = HeaderMap::new();

    headers.insert("User-Agent", HeaderValue::from_static("PledgeStrike/0.1"));

    if let Some(t) = token {
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", t))?,
        );
    }

    if let Some(key) = api_key
        && let Some((name, value)) = key.split_once(':')
    {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
    }

    if let Some(custom) = custom_headers {
        for pair in custom.split(',') {
            if let Some((name, value)) = pair.trim().split_once(':') {
                headers.insert(
                    HeaderName::from_bytes(name.trim().as_bytes())?,
                    HeaderValue::from_str(value.trim())?,
                );
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    Ok(client)
}

pub fn parse_status_filter(filter: &str) -> Vec<u16> {
    filter
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect()
}

pub fn status_color(code: u16) -> &'static str {
    match code {
        200..=299 => "\x1b[32m", // green
        300..=399 => "\x1b[33m", // yellow
        400..=499 => "\x1b[31m", // red
        500..=599 => "\x1b[35m", // magenta
        _ => "\x1b[37m",         // white
    }
}
