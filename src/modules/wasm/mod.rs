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

pub async fn analyze(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WebAssembly Module Analyzer", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.bytes().await?;

    let is_wasm = body.starts_with(b"\0asm") || body.starts_with(&[0x00, 0x61, 0x73, 0x6d]);
    if !is_wasm {
        let body_str = String::from_utf8_lossy(&body);
        if body_str.contains("application/wasm")
            || body_str.contains(".wasm")
            || body_str.contains("WebAssembly")
        {
            println!(
                "  {} Page references WASM but didn't fetch a .wasm file directly.",
                "*".yellow()
            );
            let wasm_re = regex::Regex::new(r#"(?:src|href)=["']([^"']+\.wasm)["']"#).ok();
            if let Some(re) = wasm_re {
                let matches: Vec<_> = re
                    .find_iter(&body_str)
                    .map(|m| m.as_str().to_string())
                    .collect();
                if !matches.is_empty() {
                    println!("  {} WASM files referenced:", "[*]".cyan().bold());
                    for m in &matches {
                        println!("    {} {}", "*".cyan(), m);
                    }
                }
            }
        } else {
            println!("  {} No WASM content detected.", "[-]".yellow().bold());
        }
        return Ok(());
    }

    println!(
        "  {} Valid WASM binary detected ({} bytes)",
        "[+]".green().bold(),
        body.len()
    );
    println!("  {} Content-Type: {}", "*".cyan(), content_type);

    if body.len() >= 8 {
        let version = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        println!("  {} WASM version: {}", "*".cyan(), version);
    }

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut i = 8;
    while i < body.len() {
        if i + 1 > body.len() {
            break;
        }
        let section_id = body[i];
        i += 1;
        let (section_size, consumed) = read_leb128(&body, i);
        i += consumed;
        let section_end = i + section_size as usize;
        if section_end > body.len() {
            break;
        }

        match section_id {
            2 => {
                let mut j = i;
                let (count, c) = read_leb128(&body, j);
                j += c;
                for _ in 0..count {
                    if j >= section_end {
                        break;
                    }
                    let (mod_len, c) = read_leb128(&body, j);
                    j += c;
                    let mod_name =
                        String::from_utf8_lossy(&body[j..j + mod_len as usize]).to_string();
                    j += mod_len as usize;
                    let (name_len, c) = read_leb128(&body, j);
                    j += c;
                    let name = String::from_utf8_lossy(&body[j..j + name_len as usize]).to_string();
                    j += name_len as usize;
                    j += 1;
                    let (_, c) = read_leb128(&body, j);
                    j += c;
                    imports.push(format!("{}::{}", mod_name, name));
                }
            }
            7 => {
                let mut j = i;
                let (count, c) = read_leb128(&body, j);
                j += c;
                for _ in 0..count {
                    if j >= section_end {
                        break;
                    }
                    let (name_len, c) = read_leb128(&body, j);
                    j += c;
                    let name = String::from_utf8_lossy(&body[j..j + name_len as usize]).to_string();
                    j += name_len as usize;
                    j += 1;
                    let (_, c) = read_leb128(&body, j);
                    j += c;
                    exports.push(name);
                }
            }
            _ => {}
        }
        i = section_end;
    }

    if !imports.is_empty() {
        println!("\n  {} Imports ({}):", "[*]".cyan().bold(), imports.len());
        for imp in imports.iter().take(20) {
            println!("    {} {}", "*".cyan(), imp);
        }
        if imports.len() > 20 {
            println!("    ... and {} more", imports.len() - 20);
        }
    }
    if !exports.is_empty() {
        println!("\n  {} Exports ({}):", "[*]".cyan().bold(), exports.len());
        for exp in exports.iter().take(20) {
            println!("    {} {}", "*".cyan(), exp);
        }
        if exports.len() > 20 {
            println!("    ... and {} more", exports.len() - 20);
        }
    }

    let dangerous_imports = imports
        .iter()
        .filter(|i| {
            i.contains("fd_write")
                || i.contains("abort")
                || i.contains("env")
                || i.contains("memory")
                || i.contains("eval")
        })
        .count();
    if dangerous_imports > 0 {
        println!(
            "\n{} {} potentially dangerous import(s) found.",
            "[!]".red().bold(),
            dangerous_imports
        );
    }
    Ok(())
}

pub async fn memory(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WASM Memory Inspection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let patterns = [
        (
            "instance.exports.memory",
            "Memory export — JS can read/write WASM memory",
        ),
        (".buffer", "ArrayBuffer access to WASM memory"),
        ("HEAPU8", "emscripten HEAP access"),
        ("HEAPU32", "emscripten 32-bit HEAP"),
        ("HEAPF64", "emscripten float HEAP"),
        ("growMemory", "Memory growth function"),
        ("maximumMemory", "Maximum memory limit"),
        ("memory.grow()", "Dynamic memory growth"),
    ];

    let mut found = Vec::new();
    for (pattern, desc) in &patterns {
        if body.contains(pattern) {
            println!("  {} {:30} — {}", "[!]".red().bold(), pattern, desc);
            found.push(pattern.to_string());
        }
    }

    if found.is_empty() {
        println!(
            "  {} No WASM memory access patterns found.",
            "[-]".green().bold()
        );
    } else {
        println!(
            "\n{} {} memory access pattern(s) — secrets in WASM memory may be readable.",
            "[!]".red().bold(),
            found.len()
        );
    }
    Ok(())
}

pub async fn import(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WASM Import Function Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.text().await?;

    let import_patterns = [
        (
            "env.fd_write",
            "File descriptor write — can intercept output",
        ),
        ("env.fd_read", "File descriptor read — can intercept input"),
        ("env.abort", "Abort handler — can trigger crash"),
        ("env.exit", "Exit handler — can terminate process"),
        ("env.args_get", "Argument access — can read CLI args"),
        ("env.environ_get", "Environment access — can read env vars"),
        ("env.proc_exit", "Process exit — can terminate"),
        (
            "env.emscripten_run_script",
            "Script execution — RCE via emscripten",
        ),
        ("env.system", "System call — command execution"),
        ("env.pthread", "Threading — race condition potential"),
    ];

    let mut found = Vec::new();
    for (pattern, desc) in &import_patterns {
        if body.contains(pattern) {
            println!("  {} {:35} — {}", "[!]".red().bold(), pattern, desc);
            found.push(pattern.to_string());
        }
    }

    if found.is_empty() {
        println!(
            "  {} No dangerous import patterns found.",
            "[-]".green().bold()
        );
    } else {
        println!(
            "\n{} {} dangerous import(s) — hook these to intercept WASM behavior.",
            "[!]".red().bold(),
            found.len()
        );
    }
    Ok(())
}

pub async fn reverse(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WASM Reverse Engineering", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let body = resp.bytes().await?;

    let is_wasm = body.starts_with(b"\0asm");
    if !is_wasm {
        println!("  {} Not a valid WASM binary.", "[-]".red().bold());
        return Ok(());
    }

    println!("  {} Binary size: {} bytes", "*".cyan(), body.len());

    let mut sections = Vec::new();
    let mut i = 8;
    while i < body.len() {
        if i + 1 > body.len() {
            break;
        }
        let section_id = body[i];
        i += 1;
        let (size, consumed) = read_leb128(&body, i);
        i += consumed;
        let section_names = [
            "Custom",
            "Type",
            "Import",
            "Function",
            "Table",
            "Memory",
            "Global",
            "Export",
            "Start",
            "Element",
            "Code",
            "Data",
            "DataCount",
        ];
        let name = section_names
            .get(section_id as usize)
            .copied()
            .unwrap_or("Unknown");
        sections.push((name, size));
        i += size as usize;
    }

    println!("\n  {} Sections:", "[*]".cyan().bold());
    for (name, size) in &sections {
        println!("    {} {:15} {} bytes", "*".cyan(), name, size);
    }

    let code_section = sections.iter().find(|(n, _)| n == &"Code");
    if let Some((_, size)) = code_section {
        println!(
            "\n  {} Code section: {} bytes — use wasm2wat or wasm-decompile for full decompilation.",
            "[*]".cyan().bold(),
            size
        );
    }

    println!(
        "\n  {} Tools: wasm2wat, wasm-decompile, wasm-objdump, ghidra-wasm-plugin",
        "[*]".cyan().bold()
    );
    Ok(())
}

fn read_leb128(data: &[u8], start: usize) -> (u32, usize) {
    let mut result = 0u32;
    let mut shift = 0u32;
    let mut i = start;
    while i < data.len() {
        let byte = data[i];
        result |= ((byte & 0x7f) as u32) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (result, i - start)
}
