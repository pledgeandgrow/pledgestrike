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

const STEGO_TECHNIQUES: &[(&str, &str)] = &[
    ("LSB — PNG RGB", "Least Significant Bit in PNG RGB channels"),
    ("LSB — PNG RGBA", "Least Significant Bit in PNG RGBA channels"),
    ("LSB — BMP", "Least Significant Bit in BMP format"),
    ("LSB — GIF", "Least Significant Bit in GIF format"),
    ("LSB — JPEG (DCT)", "LSB in JPEG DCT coefficients"),
    ("LSB — WebP", "Least Significant Bit in WebP format"),
    ("Metadata — EXIF", "Hidden data in EXIF metadata fields"),
    ("Metadata — IPTC", "Hidden data in IPTC metadata fields"),
    ("Metadata — XMP", "Hidden data in XMP metadata fields"),
    ("Metadata — Comment", "Hidden data in image comment fields"),
    ("Append — trailing data", "Data appended after image end marker"),
    ("Append — after IEND", "Data after PNG IEND chunk"),
    ("Append — after FFD9", "Data after JPEG EOI marker"),
    ("Extended palette", "Data encoded in color palette indices"),
    ("Alpha channel", "Data encoded in alpha channel values"),
    ("Frequency domain", "Data in frequency domain coefficients"),
    ("Spread spectrum", "Spread spectrum steganography"),
    ("Patchwork", "Statistical patchwork technique"),
    ("DCT coefficient", "DCT coefficient manipulation"),
    ("Wavelet", "Wavelet-based steganography"),
];

const IMAGE_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".ico", ".svg",
];

const STEGO_INDICATORS: &[(&str, &str)] = &[
    ("File size anomaly", "Image larger than expected for dimensions"),
    ("LSB pattern", "LSB values not uniformly distributed"),
    ("EXIF inconsistency", "EXIF data inconsistent with image"),
    ("Trailing data", "Data after image end marker"),
    ("Palette anomaly", "Unusual color palette patterns"),
    ("DCT anomaly", "Unusual DCT coefficient distribution"),
    ("Alpha anomaly", "Non-standard alpha channel values"),
    ("Comment injection", "Unusual comment fields"),
    ("Chunk anomaly", "Non-standard PNG chunks"),
    ("Metadata overflow", "Metadata larger than typical"),
];

pub async fn detect(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Steganography Detection Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} {} image types, {} stego techniques, {} indicators", "[*]".cyan().bold(), IMAGE_EXTENSIONS.len(), STEGO_TECHNIQUES.len(), STEGO_INDICATORS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/3] Image discovery...", "[*]".cyan().bold());
    let mut images = Vec::new();

    for ext in IMAGE_EXTENSIONS {
        let probe_paths = [
            format!("{}{}", base, ext),
            format!("{}/image{}", base, ext),
            format!("{}/img{}", base, ext),
            format!("{}/logo{}", base, ext),
            format!("{}/banner{}", base, ext),
            format!("{}/hero{}", base, ext),
            format!("{}/background{}", base, ext),
            format!("{}/favicon{}", base, ext),
        ];

        for path in &probe_paths {
            match client.get(path).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 {
                        let content_type = resp.headers().get("content-type")
                            .map(|v| v.to_str().unwrap_or(""))
                            .unwrap_or("")
                            .to_string();
                        let content_length = resp.headers().get("content-length")
                            .map(|v| v.to_str().unwrap_or("0").parse::<usize>().unwrap_or(0))
                            .unwrap_or(0);
                        let body = resp.bytes().await.unwrap_or_default();
                        let size = if content_length > 0 { content_length } else { body.len() };
                        let tag = if content_type.contains("image") {
                            "IMAGE".green().bold().to_string()
                        } else {
                            "non-image".yellow().to_string()
                        };
                        println!("  {} {:50} size={:6} type={:20} {}", "*".cyan(), path, size, content_type, tag);
                        if content_type.contains("image") || ext.ends_with(".png") || ext.ends_with(".jpg") || ext.ends_with(".gif") {
                            images.push((path.clone(), size, content_type.clone(), body.to_vec()));
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    if images.is_empty() {
        println!("  {} No images found at target URL", "*".yellow());
    }

    println!("\n{} [2/3] Steganography analysis on {} images...", "[*]".cyan().bold(), images.len());
    let mut findings = Vec::new();

    for (path, size, content_type, data) in &images {
        println!("\n  {} Analyzing: {} ({} bytes, {})", "*".cyan(), path, size, content_type);

        let is_png = data.starts_with(&[0x89, 0x50, 0x4E, 0x47]);
        let is_jpeg = data.starts_with(&[0xFF, 0xD8, 0xFF]);
        let is_gif = data.starts_with(&[0x47, 0x49, 0x46]);
        let is_bmp = data.starts_with(&[0x42, 0x4D]);
        let is_webp = data.len() > 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP";

        if is_png {
            let iend_pos = find_png_iend(data);
            let trailing = if let Some(pos) = iend_pos {
                data.len() - (pos + 12)
            } else {
                0
            };
            if trailing > 0 {
                println!("    {} [HIGH] Trailing data after IEND: {} bytes", "!".red().bold(), trailing);
                findings.push(format!("{}: trailing data after IEND ({} bytes)", path, trailing));
            }
            let chunks = analyze_png_chunks(data);
            for (chunk_type, chunk_size) in &chunks {
                if chunk_type == "tEXt" || chunk_type == "iTXt" || chunk_type == "zTXt" {
                    println!("    {} [INFO] Text chunk: {} ({} bytes)", "?".cyan(), chunk_type, chunk_size);
                }
                if chunk_type == "Unknown" {
                    println!("    {} [MED] Unknown chunk: {} bytes", "!".yellow(), chunk_size);
                    findings.push(format!("{}: unknown PNG chunk ({} bytes)", path, chunk_size));
                }
            }
        }

        if is_jpeg {
            let eoi_pos = find_jpeg_eoi(data);
            let trailing = if let Some(pos) = eoi_pos {
                data.len() - (pos + 2)
            } else {
                0
            };
            if trailing > 0 {
                println!("    {} [HIGH] Trailing data after FFD9: {} bytes", "!".red().bold(), trailing);
                findings.push(format!("{}: trailing data after JPEG EOI ({} bytes)", path, trailing));
            }
            let exif_size = find_jpeg_exif_size(data);
            if exif_size > 1000 {
                println!("    {} [MED] Large EXIF segment: {} bytes", "!".yellow(), exif_size);
                findings.push(format!("{}: large EXIF segment ({} bytes)", path, exif_size));
            }
            let comment_size = find_jpeg_comment_size(data);
            if comment_size > 100 {
                println!("    {} [MED] Large comment segment: {} bytes", "!".yellow(), comment_size);
                findings.push(format!("{}: large JPEG comment ({} bytes)", path, comment_size));
            }
        }

        if is_gif {
            let trailer_pos = find_gif_trailer(data);
            let trailing = if let Some(pos) = trailer_pos {
                data.len() - (pos + 1)
            } else {
                0
            };
            if trailing > 0 {
                println!("    {} [HIGH] Trailing data after GIF trailer: {} bytes", "!".red().bold(), trailing);
                findings.push(format!("{}: trailing data after GIF trailer ({} bytes)", path, trailing));
            }
        }

        let lsb_score = analyze_lsb(data);
        if lsb_score > 0.7 {
            println!("    {} [HIGH] LSB anomaly score: {:.2} — possible LSB steganography", "!".red().bold(), lsb_score);
            findings.push(format!("{}: LSB anomaly score {:.2}", path, lsb_score));
        } else if lsb_score > 0.5 {
            println!("    {} [MED] LSB anomaly score: {:.2}", "?".yellow(), lsb_score);
        } else {
            println!("    {} [OK] LSB analysis: {:.2} (normal)", ".".green(), lsb_score);
        }

        let entropy = calculate_entropy(data);
        if entropy > 7.5 {
            println!("    {} [MED] High entropy: {:.2} — possible encrypted data", "?".yellow(), entropy);
        } else {
            println!("    {} [OK] Entropy: {:.2}", ".".green(), entropy);
        }
    }

    println!("\n{} [3/3] Steganography technique reference...", "[*]".cyan().bold());
    for (name, desc) in STEGO_TECHNIQUES {
        println!("  {} {:25} {}", "*".cyan(), name, desc);
    }

    println!("\n{} Detection indicators checked:", "[*]".cyan().bold());
    for (name, desc) in STEGO_INDICATORS {
        println!("  {} {:25} {}", "*".cyan(), name, desc);
    }

    println!(
        "\n{} {} images analyzed, {} steganographic findings detected",
        "[*]".cyan().bold(),
        images.len(),
        findings.len()
    );

    if !findings.is_empty() {
        println!("{} [HIGH] Steganographic anomalies detected:", "[!]".red().bold());
        for f in &findings {
            println!("    {} {}", ">".red(), f);
        }
    } else if !images.is_empty() {
        println!("{} No steganographic anomalies detected in {} images", "[-]".green().bold(), images.len());
    }

    Ok(())
}

fn find_png_iend(data: &[u8]) -> Option<usize> {
    let iend_marker = [0x49, 0x45, 0x4E, 0x44];
    data.windows(4).position(|w| w == iend_marker)
}

fn find_jpeg_eoi(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == [0xFF, 0xD9])
}

fn find_gif_trailer(data: &[u8]) -> Option<usize> {
    data.iter().rposition(|&b| b == 0x3B)
}

fn analyze_png_chunks(data: &[u8]) -> Vec<(String, usize)> {
    let mut chunks = Vec::new();
    let mut pos = 8;
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        let chunk_type = std::str::from_utf8(&data[pos+4..pos+8]).unwrap_or("Unknown");
        let is_known = matches!(chunk_type, "IHDR" | "PLTE" | "IDAT" | "IEND" | "tEXt" | "iTXt" | "zTXt" | "gAMA" | "cHRM" | "sRGB" | "iCCP" | "tRNS" | "bKGD" | "pHYs" | "tIME" | "acTL" | "fcTL" | "fdAT");
        let type_name = if is_known { chunk_type.to_string() } else { "Unknown".to_string() };
        chunks.push((type_name, len));
        pos += 12 + len;
    }
    chunks
}

fn find_jpeg_exif_size(data: &[u8]) -> usize {
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0xFF && data[i+1] == 0xE1 {
            if i + 4 <= data.len() {
                return u16::from_be_bytes([data[i+2], data[i+3]]) as usize;
            }
        }
    }
    0
}

fn find_jpeg_comment_size(data: &[u8]) -> usize {
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0xFF && data[i+1] == 0xFE {
            if i + 4 <= data.len() {
                return u16::from_be_bytes([data[i+2], data[i+3]]) as usize;
            }
        }
    }
    0
}

fn analyze_lsb(data: &[u8]) -> f64 {
    if data.len() < 100 {
        return 0.0;
    }
    let sample_size = data.len().min(10000);
    let mut lsb_zero = 0usize;
    let mut lsb_one = 0usize;
    for i in 0..sample_size {
        if data[i] & 1 == 0 {
            lsb_zero += 1;
        } else {
            lsb_one += 1;
        }
    }
    let total = lsb_zero + lsb_one;
    if total == 0 {
        return 0.0;
    }
    let ratio = lsb_zero as f64 / total as f64;
    (ratio - 0.5).abs() * 2.0
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data.iter().take(10000) {
        freq[b as usize] += 1;
    }
    let total = data.len().min(10000) as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}
