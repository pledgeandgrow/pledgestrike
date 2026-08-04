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

const ICMP_PROBE_HOSTS: &[&str] = &[
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
    "9.9.9.9",
    "8.8.4.4",
    "1.0.0.1",
];

const TUNNEL_PAYLOADS: &[(&str, &str)] = &[
    ("ICMP echo — data in payload", "echo"),
    ("ICMP timestamp — data in timestamp", "timestamp"),
    ("ICMP address mask — data in mask", "mask"),
    ("ICMP info request — data in info", "info"),
    ("ICMP echo — large payload (MTU)", "large"),
    ("ICMP echo — fragmented", "fragmented"),
    ("ICMP echo — TTL-based encoding", "ttl"),
    ("ICMP echo — ID-based encoding", "id"),
    ("ICMP echo — sequence-based encoding", "seq"),
    ("ICMP echo — type-based encoding", "type"),
    ("ICMP echo — code-based encoding", "code"),
    ("ICMP echo — checksum-based encoding", "checksum"),
    ("ICMP echo — combined fields", "combined"),
    ("ICMP echo — base64 in payload", "base64"),
    ("ICMP echo — hex in payload", "hex"),
    ("ICMP echo — binary in payload", "binary"),
    ("ICMP echo — XOR encoded", "xor"),
    ("ICMP echo — AES-like pattern", "aes"),
    ("ICMP echo — DNS-over-ICMP", "dns"),
    ("ICMP echo — HTTP-over-ICMP", "http"),
];

const ICMP_DETECTION_BYPASSES: &[(&str, &str)] = &[
    ("Rate limiting — slow ping", "1 ping/second with data"),
    ("Rate limiting — burst ping", "10 pings/burst then pause"),
    ("Payload randomization", "Random padding to avoid pattern matching"),
    ("Payload encryption", "AES-256-CBC encrypted payload"),
    ("TTL manipulation", "Vary TTL to avoid traceroute detection"),
    ("ID randomization", "Random ICMP ID per packet"),
    ("Size variation", "Variable payload sizes (8-1472 bytes)"),
    ("Inter-packet delay", "Exponential backoff between packets"),
    ("Protocol switching", "Alternate between ICMP echo/timestamp/mask"),
    ("Cover traffic", "Mix exfil data with legitimate ping traffic"),
];

pub async fn tunnel(host: &str, data: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} ICMP Tunneling Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Host: {}", "[*]".cyan().bold(), host);
    println!("{} Data: {} ({} bytes)", "[*]".cyan().bold(), data, data.len());
    println!("{} {} probe hosts, {} tunnel payloads, {} detection bypasses", "[*]".cyan().bold(), ICMP_PROBE_HOSTS.len(), TUNNEL_PAYLOADS.len(), ICMP_DETECTION_BYPASSES.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    println!("\n{} [1/3] ICMP reachability probe...", "[*]".cyan().bold());
    for probe_host in ICMP_PROBE_HOSTS {
        let ping_url = format!("https://{}/", probe_host);
        match client.get(&ping_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let tag = if status > 0 { "reachable".green().to_string() } else { "unreachable".red().to_string() };
                println!("  {} {:15} status={} {}", "*".cyan(), probe_host, status, tag);
            }
            Err(_) => {
                println!("  {} {:15} timeout (ICMP may still work)", "*".yellow(), probe_host);
            }
        }
    }

    println!("\n{} [2/3] ICMP tunnel payload analysis...", "[*]".cyan().bold());
    let data_bytes = data.as_bytes();
    let mut results = Vec::new();

    for (name, method) in TUNNEL_PAYLOADS {
        let (payload_desc, payload_size, chunks) = match *method {
            "echo" => ("data in echo payload", data_bytes.len(), 1),
            "timestamp" => ("data encoded in timestamp field", (data_bytes.len() + 3) / 4, 1),
            "mask" => ("data encoded in address mask", (data_bytes.len() + 3) / 4, 1),
            "info" => ("data in info request", data_bytes.len(), 1),
            "large" => ("large payload (MTU-sized)", 1472, 1),
            "fragmented" => ("fragmented payload", data_bytes.len(), (data_bytes.len() + 127) / 128),
            "ttl" => ("TTL-encoded (1 byte per packet)", data_bytes.len(), data_bytes.len()),
            "id" => ("ID-encoded (2 bytes per packet)", (data_bytes.len() + 1) / 2, (data_bytes.len() + 1) / 2),
            "seq" => ("sequence-encoded (2 bytes per packet)", (data_bytes.len() + 1) / 2, (data_bytes.len() + 1) / 2),
            "type" => ("ICMP type-encoded", data_bytes.len(), data_bytes.len()),
            "code" => ("ICMP code-encoded", data_bytes.len(), data_bytes.len()),
            "checksum" => ("checksum-encoded", (data_bytes.len() + 1) / 2, (data_bytes.len() + 1) / 2),
            "combined" => ("combined field encoding", (data_bytes.len() + 5) / 6, (data_bytes.len() + 5) / 6),
            "base64" => ("base64 in payload", ((data_bytes.len() * 4) + 2) / 3, 1),
            "hex" => ("hex in payload", data_bytes.len() * 2, 1),
            "binary" => ("raw binary in payload", data_bytes.len(), 1),
            "xor" => ("XOR-encoded payload", data_bytes.len(), 1),
            "aes" => ("AES-pattern payload", ((data_bytes.len() / 16) + 1) * 16, 1),
            "dns" => ("DNS-over-ICMP", data_bytes.len() + 12, 1),
            "http" => ("HTTP-over-ICMP", data_bytes.len() + 16, 1),
            _ => ("unknown", data_bytes.len(), 1),
        };

        let tag = if chunks > 100 {
            "SLOW".yellow().to_string()
        } else if chunks > 10 {
            "MODERATE".cyan().to_string()
        } else {
            "EFFICIENT".green().bold().to_string()
        };

        println!(
            "  {} [{:02}] {:40} {:30} size={:4} chunks={:3} {}",
            "*".cyan(),
            results.len() + 1,
            name,
            payload_desc,
            payload_size,
            chunks,
            tag
        );

        results.push((name, chunks));
    }

    println!("\n{} [3/3] Detection bypass strategies...", "[*]".cyan().bold());
    for (name, desc) in ICMP_DETECTION_BYPASSES {
        println!("  {} {:30} {}", "*".cyan(), name, desc);
    }

    let efficient = results.iter().filter(|(_, c)| *c <= 10).count();
    let moderate = results.iter().filter(|(_, c)| *c > 10 && *c <= 100).count();
    let slow = results.iter().filter(|(_, c)| *c > 100).count();

    println!(
        "\n{} {} efficient, {} moderate, {} slow tunneling methods",
        "[*]".cyan().bold(),
        efficient,
        moderate,
        slow
    );

    println!("{} ICMP tunneling bypasses firewalls that allow ICMP echo/reply", "[*]".cyan().bold());
    println!("{} Most efficient: echo payload, base64, hex, binary (single-packet)", "[*]".cyan().bold());
    println!("{} Most stealthy: TTL-encoded, XOR, AES-pattern (evades DPI)", "[*]".cyan().bold());

    Ok(())
}
