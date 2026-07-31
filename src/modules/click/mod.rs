use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn frame(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} X-Frame-Options Bypass Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let xfo = resp.headers().get("x-frame-options").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let csp = resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let body = resp.text().await.unwrap_or_default();

    if xfo.is_empty() && !csp.contains("frame-ancestors") {
        println!("  {} No X-Frame-Options or CSP frame-ancestors — CLICKJACKING POSSIBLE!", "[!]".red().bold());
    } else if !xfo.is_empty() {
        println!("  {} X-Frame-Options: {}", "[*]".cyan().bold(), xfo);
        if xfo.to_lowercase().contains("deny") {
            println!("  {} XFO: DENY — framing blocked by most browsers.", "[-]".green().bold());
        } else if xfo.to_lowercase().contains("sameorigin") {
            println!("  {} XFO: SAMEORIGIN — cross-origin framing blocked.", "[-]".green().bold());
            println!("  {} Bypass: try ancestor chain, iframe within same origin, or open redirect.", "[*]".yellow().bold());
        } else if xfo.to_lowercase().contains("allow-all") {
            println!("  {} XFO: ALLOW-ALL — framing allowed from any origin!", "[!]".red().bold());
        }
    }

    if csp.contains("frame-ancestors") {
        println!("  {} CSP frame-ancestors: {}", "[*]".cyan().bold(), csp);
        if csp.contains("frame-ancestors *") || csp.contains("frame-ancestors 'none'") == false && csp.contains("frame-ancestors 'self'") == false {
            println!("  {} CSP frame-ancestors may allow framing from external origins.", "[!]".red().bold());
        }
    }

    println!("\n  {} Generating PoC HTML:", "[*]".cyan().bold());
    let poc = format!(
        "<html><body>\n<iframe src=\"{}\" style=\"opacity:0;position:absolute;top:0;left:0;width:100%;height:100%;z-index:99\"></iframe>\n<div style=\"position:absolute;top:50px;left:50px;z-index:100;color:white;font-size:24px\">Click here for free stuff!</div>\n</body></html>",
        url
    );
    println!("  ---");
    for line in poc.lines() {
        println!("  {}", line);
    }
    println!("  ---");

    Ok(())
}

pub async fn overlay(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Iframe Overlay Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await.unwrap_or_default();

    let overlay_patterns = ["opacity:0", "opacity: 0", "filter:alpha(opacity=0)", "transparent", "z-index", "position:absolute", "position: absolute", "pointer-events:none"];
    let mut found = Vec::new();
    for p in &overlay_patterns {
        if body.contains(p) { found.push(*p); }
    }

    if !found.is_empty() {
        println!("  {} Overlay-related CSS patterns found:", "[+]".yellow().bold());
        for f in &found {
            println!("    {} {}", "*".cyan(), f);
        }
    } else {
        println!("  {} No overlay CSS patterns detected.", "[-]".dimmed());
    }

    let poc_overlays = [
        ("Transparent button overlay", "opacity:0 button positioned over decoy"),
        ("Full-page iframe overlay", "100% width/height transparent iframe over page"),
        ("Cursor offset trick", "cursor: none with fake cursor at offset position"),
        ("Drag-and-drop capture", "hidden draggable element capturing mouse events"),
    ];

    println!("\n  {} PoC overlay techniques:", "[*]".cyan().bold());
    for (name, desc) in &poc_overlays {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    Ok(())
}

pub async fn pointer(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Pointer Event Hijacking Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await.unwrap_or_default();

    let patterns = ["touchstart", "touchend", "touchmove", "pointerdown", "pointerup", "pointermove", "addEventListener('click'", "onmousedown", "onmouseup", "dblclick"];
    let mut found = Vec::new();
    for p in &patterns {
        if body.contains(p) { found.push(*p); }
    }

    if !found.is_empty() {
        println!("  {} Pointer/touch event handlers detected:", "[+]".yellow().bold());
        for f in &found {
            println!("    {} {}", "*".cyan(), f);
        }
    } else {
        println!("  {} No pointer event handlers detected.", "[-]".dimmed());
    }

    let techniques = [
        ("Touch event interception", "Transparent iframe captures touchstart/touchend on mobile"),
        ("Double-click timing", "First click activates iframe, second click hits target"),
        ("Pointer capture abuse", "setPointerCapture() to redirect pointer events"),
        ("Drag event hijacking", "dragstart/dragend events to trigger actions in hidden iframe"),
    ];

    println!("\n  {} Pointer hijacking techniques:", "[*]".cyan().bold());
    for (name, desc) in &techniques {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    Ok(())
}

pub async fn cursor(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Cursor Spoofing Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await.unwrap_or_default();

    let cursor_patterns = ["cursor:none", "cursor: none", "cursor:url", "cursor: url", "cursor:crosshair", "cursor: pointer", "custom cursor"];
    let mut found = Vec::new();
    for p in &cursor_patterns {
        if body.contains(p) { found.push(*p); }
    }

    if !found.is_empty() {
        println!("  {} Custom cursor patterns detected:", "[+]".yellow().bold());
        for f in &found {
            println!("    {} {}", "*".cyan(), f);
        }
    } else {
        println!("  {} No custom cursor patterns found.", "[-]".dimmed());
    }

    let techniques = [
        ("Invisible cursor", "cursor:none + fake cursor at offset to misdirect clicks"),
        ("SVG cursor overlay", "Custom SVG cursor that appears as normal but clicks at offset"),
        ("Animated cursor", "Animated cursor that moves independently of actual pointer"),
        ("Cursor lag exploit", "CSS transition on cursor position to create lag-based misclicks"),
    ];

    println!("\n  {} Cursor spoofing techniques:", "[*]".cyan().bold());
    for (name, desc) in &techniques {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    Ok(())
}
