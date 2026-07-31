use colored::Colorize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct CallbackHit {
    pub timestamp: u64,
    pub remote_ip: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub payload_id: String,
}

pub struct CallbackServer {
    pub hits: Arc<Mutex<Vec<CallbackHit>>>,
    pub port: u16,
}

impl CallbackServer {
    pub async fn start(port: u16) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        let hits = Arc::new(Mutex::new(Vec::new()));
        let hits_clone = hits.clone();

        let actual_port = listener.local_addr()?.port();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, addr)) => {
                        let hits = hits_clone.clone();
                        tokio::spawn(async move {
                            let remote_ip = addr.ip().to_string();

                            // Read HTTP request
                            let mut buf = vec![0u8; 8192];
                            let n = match stream.read(&mut buf).await {
                                Ok(n) => n,
                                Err(_) => return,
                            };

                            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                            let mut lines = raw.lines();
                            let request_line = lines.next().unwrap_or("");
                            let parts: Vec<&str> = request_line.split_whitespace().collect();
                            let method = parts.first().unwrap_or(&"").to_string();
                            let path = parts.get(1).unwrap_or(&"").to_string();

                            // Parse headers
                            let mut headers = HashMap::new();
                            for line in lines {
                                if line.is_empty() {
                                    break;
                                }
                                if let Some((key, value)) = line.split_once(": ") {
                                    headers.insert(key.to_lowercase(), value.trim().to_string());
                                }
                            }

                            // Extract payload ID from path
                            let payload_id = path.trim_start_matches('/').to_string();

                            let timestamp = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();

                            let hit = CallbackHit {
                                timestamp,
                                remote_ip,
                                method,
                                path: path.clone(),
                                headers,
                                body: String::new(),
                                payload_id,
                            };

                            // Send HTTP response
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                            use tokio::io::AsyncWriteExt;
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.flush().await;

                            // Log the hit
                            {
                                let mut hits_lock = hits.lock().await;
                                hits_lock.push(hit.clone());
                            }

                            eprintln!(
                                "{} Callback hit from {} — {} {} (payload: {})",
                                "[+]".green().bold(),
                                hit.remote_ip.red(),
                                hit.method.yellow(),
                                hit.path,
                                hit.payload_id.cyan(),
                            );
                        });
                    }
                    Err(e) => {
                        eprintln!("{} Accept error: {}", "[-]".red().bold(), e);
                    }
                }
            }
        });

        eprintln!(
            "{} Callback listener started on port {}",
            "[*]".cyan().bold(),
            actual_port
        );

        Ok(CallbackServer {
            hits,
            port: actual_port,
        })
    }

    pub async fn get_hits(&self) -> Vec<CallbackHit> {
        self.hits.lock().await.clone()
    }

    pub async fn has_hits(&self) -> bool {
        !self.hits.lock().await.is_empty()
    }
}

pub fn print_hits(hits: &[CallbackHit]) {
    if hits.is_empty() {
        println!("{} No callback hits received.", "[-]".red().bold());
        return;
    }

    println!(
        "\n{} {} callback hit(s) received:",
        "[+]".green().bold(),
        hits.len()
    );
    println!("{}", "─".repeat(60).dimmed());

    for (i, hit) in hits.iter().enumerate() {
        println!(
            "{} #{} from {} at {}",
            "[!]".yellow().bold(),
            i + 1,
            hit.remote_ip.red().bold(),
            hit.payload_id.cyan(),
        );
        println!("    Method: {}", hit.method);
        println!("    Path:   {}", hit.path);
        if !hit.headers.is_empty() {
            println!("    Headers:");
            for (k, v) in &hit.headers {
                println!("      {}: {}", k.dimmed(), v);
            }
        }
        println!();
    }
}
