use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn docker(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Docker API Escape Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let endpoints = [
        ("Version info", "/version"),
        ("Info", "/info"),
        ("Containers", "/containers/json?all=1"),
        ("Images", "/images/json"),
        ("Networks", "/networks"),
        ("Volumes", "/volumes"),
        ("Create container", "/containers/create"),
        ("Exec", "/containers/exec"),
        ("Events", "/events"),
        ("Swarm", "/swarm"),
        ("Services", "/services"),
        ("Secrets", "/secrets"),
        ("Configs", "/configs"),
        ("Plugins", "/plugins"),
    ];

    let mut exposed = Vec::new();
    for (name, path) in &endpoints {
        let full = format!("{}{}", url, path);
        match client.get(&full).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200 && !body.is_empty();
                let tag = if accessible { "EXPOSED".red().bold().to_string() } else { "blocked".green().to_string() };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accessible { exposed.push((name.to_string(), path.to_string(), body.chars().take(200).collect::<String>())); }
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    if !exposed.is_empty() {
        println!("\n{} Docker API is exposed! {} endpoints accessible.", "[!]".red().bold(), exposed.len());
        for (name, path, body) in &exposed {
            println!("  {} {} ({}) — {}", "*".red(), name, path, body.chars().take(100).collect::<String>());
        }
    } else {
        println!("\n{} Docker API not exposed or requires auth.", "[-]".green().bold());
    }
    Ok(())
}

pub async fn kubelet(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Kubelet API Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let endpoints = [
        ("Pod list", "/pods"),
        ("Running pods", "/runningpods"),
        ("Metrics", "/metrics"),
        ("Stats summary", "/stats/summary"),
        ("Cadvisor", "/metrics/cadvisor"),
        ("Container logs", "/containerLogs/default/pod/container"),
        ("Exec in pod", "/exec/default/pod/container?command=id&output=1"),
        ("Run command", "/run/default/pod/container?cmd=id"),
        ("Port forward", "/portForward/default/pod"),
        ("Attach", "/attach/default/pod/container"),
        ("Healthz", "/healthz"),
        ("Debug", "/debug/pprof/"),
    ];

    let mut exposed = Vec::new();
    for (name, path) in &endpoints {
        let full = format!("{}{}", url, path);
        match client.get(&full).header("Authorization", "Bearer ").send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let tag = if accessible { "ACCESSIBLE".red().bold().to_string() } else { "blocked".green().to_string() };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accessible { exposed.push((name.to_string(), body.chars().take(200).collect::<String>())); }
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), name); }
        }
    }

    if !exposed.is_empty() {
        println!("\n{} Kubelet API exposed! {} endpoints accessible.", "[!]".red().bold(), exposed.len());
        for (name, body) in &exposed { println!("  {} {} — {}", "*".red(), name, body.chars().take(100).collect::<String>()); }
    } else {
        println!("\n{} Kubelet API requires auth or not exposed.", "[-]".green().bold());
    }
    Ok(())
}

pub async fn cap(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Container Capabilities Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let caps = [
        ("CAP_SYS_ADMIN", "Mount, remount, load kernel modules"),
        ("CAP_SYS_PTRACE", "Inject into processes, read memory"),
        ("CAP_SYS_MODULE", "Load/unload kernel modules"),
        ("CAP_DAC_OVERRIDE", "Bypass file read/write/execute checks"),
        ("CAP_SETUID", "Manipulate process UID"),
        ("CAP_SETGID", "Manipulate process GID"),
        ("CAP_NET_RAW", "Raw network access (packet sniffing)"),
        ("CAP_NET_ADMIN", "Network configuration, iptables"),
        ("CAP_SYS_RAWIO", "Direct disk I/O, kernel memory access"),
        ("CAP_SYS_BOOT", "Reboot system"),
        ("CAP_WAKE_ALARM", "Set alarms, timers"),
        ("CAP_AUDIT_CONTROL", "Audit logging control"),
    ];

    for (cap, desc) in &caps {
        let body = serde_json::json!({"action": "check_capability", "capability": cap}).to_string();
        match client.post(url).header("Content-Type", "application/json").body(body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let has_cap = resp_body.contains("true") || resp_body.contains("granted") || status == 200;
                let tag = if has_cap { "GRANTED".red().bold().to_string() } else { "denied".green().to_string() };
                println!("  {} {:25} {} — {}", "*".cyan(), cap, tag, desc);
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), cap); }
        }
    }

    println!("\n{} Dangerous capabilities can enable container escape.", "[*]".cyan().bold());
    Ok(())
}

pub async fn mount(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Host Mount Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mounts = [
        ("Host /etc", "/host_etc", "/etc"),
        ("Host /root", "/host_root", "/root"),
        ("Host /var/run/docker.sock", "/docker.sock", "/var/run/docker.sock"),
        ("Host /proc", "/host_proc", "/proc"),
        ("Host /sys", "/host_sys", "/sys"),
        ("Host /dev", "/host_dev", "/dev"),
        ("Host /home", "/host_home", "/home"),
        ("Host /tmp", "/host_tmp", "/tmp"),
        ("Host /var/log", "/host_logs", "/var/log"),
        ("Host /opt", "/host_opt", "/opt"),
        ("Containerd socket", "/containerd.sock", "/run/containerd/containerd.sock"),
        ("Cgroup", "/host_cgroup", "/sys/fs/cgroup"),
    ];

    let mut accessible = Vec::new();
    for (name, container_path, host_path) in &mounts {
        let body = serde_json::json!({"action": "read_mount", "path": container_path, "host_path": host_path}).to_string();
        match client.post(url).header("Content-Type", "application/json").body(body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let readable = resp_body.contains("passwd") || resp_body.contains("shadow") || resp_body.contains("root")
                    || resp_body.contains("docker") || resp_body.contains("containerd") || !resp_body.is_empty();
                let tag = if readable && status == 200 { "READABLE".red().bold().to_string() } else { "not mounted".green().to_string() };
                println!("  {} {:30} → {:20} {}", "*".cyan(), name, host_path, tag);
                if readable && status == 200 { accessible.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:30} error", "*".red(), name); }
        }
    }

    if !accessible.is_empty() {
        println!("\n{} {} host mount(s) accessible — escape possible!", "[!]".red().bold(), accessible.len());
    } else {
        println!("\n{} No host mounts accessible.", "[-]".green().bold());
    }
    Ok(())
}
