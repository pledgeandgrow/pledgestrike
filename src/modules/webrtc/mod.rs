use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn leak(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebRTC IP Leak Detector", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let has_webrtc = body.contains("RTCPeerConnection") || body.contains("webkitRTCPeerConnection")
        || body.contains("mozRTCPeerConnection") || body.contains("createDataChannel")
        || body.contains("onicecandidate") || body.contains("ICE");

    if has_webrtc {
        println!("  {} WebRTC API detected in page", "[!]".red().bold());
        println!("  {} The page uses RTCPeerConnection — potential IP leak", "*".yellow());
        println!("  {} Local and public IPs may be exposed bypassing VPN/proxy", "*".yellow());
    } else {
        println!("  {} No WebRTC API usage detected", "*".green());
    }

    // Check for STUN/TURN server configurations
    let stun_pattern = regex::Regex::new(r##"stun:([^"'\s]+)"##).ok();
    let turn_pattern = regex::Regex::new(r##"turn:([^"'\s]+)"##).ok();

    if let Some(re) = stun_pattern {
        let stuns: Vec<_> = re.find_iter(&body).map(|m| m.as_str().to_string()).collect();
        if !stuns.is_empty() {
            println!("\n  {} STUN servers found:", "[*]".cyan().bold());
            for s in &stuns { println!("    {} {}", "*".cyan(), s); }
        }
    }

    if let Some(re) = turn_pattern {
        let turns: Vec<_> = re.find_iter(&body).map(|m| m.as_str().to_string()).collect();
        if !turns.is_empty() {
            println!("\n  {} TURN servers found:", "[*]".cyan().bold());
            for t in &turns { println!("    {} {} (may contain credentials)", "*".red(), t); }
        }
    }

    println!("\n{} WebRTC can leak real IP even behind VPN/proxy.", "[*]".cyan().bold());
    Ok(())
}

pub async fn stun(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebRTC STUN/TURN Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let stun_re = regex::Regex::new(r##"stun:([^:\"'\s]+):(\d+)?"##).ok();
    let mut stun_servers = Vec::new();
    if let Some(re) = stun_re {
        for m in re.find_iter(&body) { stun_servers.push(m.as_str().to_string()); }
    }

    let turn_re = regex::Regex::new(r##"turn:([^:\"'\s]+):(\d+)?[^\"'\s]*"##).ok();
    let mut turn_servers = Vec::new();
    if let Some(re) = turn_re {
        for m in re.find_iter(&body) { turn_servers.push(m.as_str().to_string()); }
    }

    if stun_servers.is_empty() && turn_servers.is_empty() {
        // Try common STUN servers
        let common_stun = [
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302",
            "stun:stun2.l.google.com:19302",
            "stun:stun3.l.google.com:19302",
            "stun:stun4.l.google.com:19302",
            "stun:stun.cloudflare.com:3478",
            "stun:stun.amazon.com:3478",
            "stun:stun.microsoft.com:3478",
        ];
        println!("  {} No STUN/TURN found in page. Testing common servers:", "[*]".cyan().bold());
        for s in &common_stun { println!("    {} {}", "*".cyan(), s); }
        stun_servers = common_stun.iter().map(|s| s.to_string()).collect();
    }

    println!("\n  {} STUN servers (can reveal public IP):", "[*]".cyan().bold());
    for s in &stun_servers { println!("    {} {}", "*".cyan(), s); }

    if !turn_servers.is_empty() {
        println!("\n  {} TURN servers (relay — can access internal network):", "[*]".cyan().bold());
        for t in &turn_servers {
            let has_creds = t.contains("credential") || t.contains("username") || t.contains(":") && t.split(':').count() > 3;
            let tag = if has_creds { "HAS CREDS".red().bold().to_string() } else { "no creds".to_string() };
            println!("    {} {} {}", "*".red(), t, tag);
        }
    }

    println!("\n{} STUN can be used for internal network discovery via ICE candidates.", "[*]".cyan().bold());
    Ok(())
}

pub async fn relay(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebRTC Relay for Internal Network Discovery", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let has_webrtc = body.contains("RTCPeerConnection") || body.contains("createDataChannel");
    if !has_webrtc {
        println!("  {} No WebRTC detected — cannot relay.", "[-]".yellow().bold());
        return Ok(());
    }

    let internal_ranges = [
        ("10.0.0.0/8", "10."),
        ("172.16.0.0/12", "172.16."),
        ("192.168.0.0/16", "192.168."),
        ("169.254.0.0/16", "169.254."),
        ("127.0.0.0/8", "127."),
    ];

    println!("  {} WebRTC detected — checking for internal IP leak vectors:", "[*]".cyan().bold());
    for (range, prefix) in &internal_ranges {
        if body.contains(prefix) {
            println!("    {} [LEAK] Internal IP range {} detected in page!", "[!]".red().bold(), range);
        } else {
            println!("    {} {} — not found in page", "*".green(), range);
        }
    }

    // Check for ICE candidate gathering patterns
    let ice_patterns = ["onicecandidate", "iceServers", "iceTransportPolicy", "RTCIceCandidate", "candidate:", "srflx", "host", "relay"];
    let mut found_patterns = Vec::new();
    for p in &ice_patterns {
        if body.contains(p) { found_patterns.push(p.to_string()); }
    }

    if !found_patterns.is_empty() {
        println!("\n  {} ICE candidate patterns found:", "[*]".cyan().bold());
        for p in &found_patterns { println!("    {} {}", "*".cyan(), p); }
    }

    println!("\n{} WebRTC can discover internal network topology via host ICE candidates.", "[*]".cyan().bold());
    Ok(())
}

pub async fn fingerprint(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebRTC Browser Fingerprinting", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let fp_vectors = [
        ("RTCPeerConnection", "Browser supports WebRTC"),
        ("webkitRTCPeerConnection", "WebKit-prefixed WebRTC"),
        ("mozRTCPeerConnection", "Mozilla-prefixed WebRTC"),
        ("RTCDataChannel", "Data channel support"),
        ("RTCDtlsTransport", "DTLS transport"),
        ("RTCIceTransport", "ICE transport"),
        ("RTCRtpSender", "RTP sender"),
        ("RTCRtpReceiver", "RTP receiver"),
        ("MediaStreamTrack", "Media stream access"),
        ("getUserMedia", "Camera/mic access"),
        ("getDisplayMedia", "Screen capture"),
        ("RTCIceCandidate", "ICE candidate parsing"),
        ("RTCSessionDescription", "Session description"),
        ("RTCPeerConnection.generateCertificate", "Certificate generation"),
        ("RTCError", "Error handling"),
    ];

    let mut found = Vec::new();
    for (api, desc) in &fp_vectors {
        if body.contains(api) {
            println!("  {} {:45} — {}", "*".red(), api, desc);
            found.push(api.to_string());
        }
    }

    if found.is_empty() {
        println!("  {} No WebRTC fingerprinting vectors found.", "[-]".green().bold());
    } else {
        println!("\n{} {} WebRTC fingerprinting vector(s) found.", "[!]".red().bold(), found.len());
        println!("{} These can be used for browser fingerprinting and tracking.", "[*]".cyan().bold());
    }
    Ok(())
}
