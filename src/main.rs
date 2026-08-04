#![allow(dead_code, clippy::too_many_arguments)]

mod cli;
mod modules;

use clap::Parser;
use cli::{
    AclAction, ActuatorAction, AgentAction, AiAction, AmqpAction, ApiAction, ArgoCDAction,
    AwsAction, AzureAction, BleAction, BruteAction, CacheAction, CicdAction, Cli, ClickAction,
    CloudAction, CmdiAction, CoapAction, Commands, ContainerAction, CookieAction, CorsAction,
    CrlfAction, CspAction, CsrfAction, DebugAction, DeserAction, DnsenumAction, DomAction,
    ElasticAction, EtcdAction, ExchangeAction, ExfilAction, ExploitAction, FingerAction,
    FtpAction, GitAction, GcpAction, GhaAction, GitlabciAction, GraphqlAttackAction, GrpcAction,
    H2Action, HostAction, HppAction, IdorAction, IocAction, IpmiAction, IstioAction,
    JndiAction, JenkinsAction, JwtAction, K8sAction, KerbAction, LdapiAction, LfiAction,
    LlmAction, MagiclinkAction, MassAction, MemcacheAction, MfaAction, MongoAction, MqttAction,
    NfsAction, NosqliAction, NtlmAction, NtpAction, OauthAction, OidcAction, OpenapiAction,
    OtAction, OwaAction, PadoracleAction, PasskeyAction, PayloadAction, PostmsgAction,
    ProtoAction, RaceAction, RatelimitAction, RceAction, RdpAction, RebindAction,
    RedirectAction, RedisxAction, RtspAction, SamlAction, SecretAction, SessionAction,
    SharepointAction, ShellAction, SipAction, SmbAction, SmtpAction, SmuggleAction, SnmpAction,
    SprayAction, SqliAction, SseAction, SshAction, SsrfAction, SsrfChainAction, SstiAction,
    StompAction, SubdomAction, SupplyAction, SsoAction, SwAction, TakeoverAction, TelnetAction,
    TftpAction, TfstateAction, TlsAction, UnicodeAction, UpnpAction, VectordbAction, VncAction,
    WafAction, WasmAction, Web3Action, WebauthnAction, WebdavAction, WebrtcAction, WfuzzAction,
    WhoisAction, WinrmAction, WsAction, WsdlAction, X11Action, XsleakAction, XssAction,
    XxeAction, ZookeeperAction,
};
use colored::Colorize;

fn banner() {
    println!(
        r#"
____  _     _____ ____   ____ _____   ____ _____ ____  ___ _  _______ 
|  _ \| |   | ____|  _ \ / ___| ____| / ___|_   _|  _ \|_ _| |/ / ____|
| |_) | |   |  _| | | | | |  _|  _|   \___ \ | | | |_) || || ' /|  _|  
|  __/| |___| |___| |_| | |_| | |___   ___) || | |  _ < | || . \| |___ 
|_|   |_____|_____|____/ \____|_____| |____/ |_| |_| \_\___|_|\_\_____|
"#
    );
}

fn main() -> anyhow::Result<()> {
    let builder = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024);
    let handle = builder.spawn(|| {
        let args = Cli::parse();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(Box::pin(async_main(args)))
    })?;
    handle.join().unwrap();
    Ok(())
}

async fn async_main(args: Cli) -> anyhow::Result<()> {
    match args.command {
        Commands::Jwt { action } => match action {
            JwtAction::Decode { token } => {
                banner();
                println!("{} JWT Decode", "[*]".cyan().bold());
                println!("{}", "─".repeat(60).dimmed());

                match modules::jwt::decode::decode(&token) {
                    Ok(parts) => {
                        print!("{}", modules::jwt::decode::format_decoded(&parts));
                    }
                    Err(e) => {
                        println!("{} Failed to decode: {}", "[-]".red().bold(), e);
                    }
                }
            }

            JwtAction::Check { token } => {
                banner();
                println!("{} JWT Vulnerability Check", "[*]".cyan().bold());
                println!("{}", "─".repeat(60).dimmed());

                match modules::jwt::check::check(&token) {
                    Ok(results) => {
                        print!("{}", modules::jwt::check::format_results(&results));
                    }
                    Err(e) => {
                        println!("{} Failed to check: {}", "[-]".red().bold(), e);
                    }
                }
            }

            JwtAction::Crack {
                token,
                wordlist,
                threads,
            } => {
                banner();
                println!("{} JWT Brute-Force", "[*]".cyan().bold());
                println!("{}", "─".repeat(60).dimmed());

                match modules::jwt::crack::crack(&token, &wordlist, threads.unwrap_or(0)) {
                    Ok(Some(secret)) => {
                        println!(
                            "\n{} SECRET FOUND: {}",
                            "[+]".green().bold(),
                            secret.white().bold()
                        );
                        println!();
                        println!(
                            "{} You can now forge tokens with this secret:",
                            "[*]".cyan().bold()
                        );
                        println!(
                            "    pledgestrike jwt forge --secret \"{}\" --payload '{{\"user\":\"admin\",\"role\":\"admin\"}}'",
                            secret
                        );
                    }
                    Ok(None) => {
                        println!("\n{} Secret not found in wordlist.", "[-]".red().bold());
                    }
                    Err(e) => {
                        println!("{} Error: {}", "[-]".red().bold(), e);
                    }
                }
            }

            JwtAction::Forge {
                secret,
                payload,
                payload_file,
                alg,
            } => {
                banner();
                println!("{} JWT Forge", "[*]".cyan().bold());
                println!("{}", "─".repeat(60).dimmed());

                let payload_str = if let Some(file) = &payload_file {
                    match std::fs::read_to_string(file) {
                        Ok(content) => content,
                        Err(e) => {
                            println!("{} Failed to read payload file: {}", "[-]".red().bold(), e);
                            return Ok(());
                        }
                    }
                } else if let Some(p) = &payload {
                    p.clone()
                } else {
                    println!(
                        "{} Either --payload or --payload-file must be provided",
                        "[-]".red().bold()
                    );
                    return Ok(());
                };

                match modules::jwt::forge::forge(&secret, &payload_str, &alg) {
                    Ok(token) => {
                        modules::jwt::forge::print_forge_result(
                            &token,
                            &secret,
                            &alg,
                            &payload_str,
                        );
                    }
                    Err(e) => {
                        println!("{} Failed to forge: {}", "[-]".red().bold(), e);
                    }
                }
            }
        },

        Commands::Ssrf { action } => match action {
            SsrfAction::Probe {
                target,
                port,
                external_ip,
                cloud,
                smuggle,
                custom,
                timeout,
            } => {
                banner();
                println!("{} SSRF Probe", "[*]".cyan().bold());
                println!("{}", "═".repeat(60).cyan());

                if let Err(e) = modules::ssrf::probe::probe(
                    &target,
                    port,
                    external_ip,
                    &cloud,
                    smuggle,
                    custom.as_deref(),
                    timeout,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            SsrfAction::Listen { port } => {
                banner();
                if let Err(e) = modules::ssrf::probe::listen_only(port).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            SsrfAction::Payloads {
                cloud,
                external_ip,
                smuggle,
            } => {
                banner();
                if let Err(e) =
                    modules::ssrf::probe::payloads_only(&external_ip, &cloud, smuggle).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Shell { action } => match action {
            ShellAction::Listen {
                port,
                bind,
                encrypt,
                key,
                log_file,
            } => {
                banner();

                let log = if let Some(path) = &log_file {
                    Some(std::fs::File::create(path)?)
                } else {
                    None
                };

                let manager = modules::shell::listener::SessionManager::new(log);

                if let Err(e) = manager.listen(&bind, port, encrypt, key.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            ShellAction::Generate {
                shell_type,
                ip,
                port,
                base64,
            } => {
                banner();
                println!(
                    "{}",
                    modules::shell::generate::generate(&shell_type, &ip, port, base64)
                );
            }
        },

        Commands::Api { action } => match action {
            ApiAction::Enum {
                url,
                wordlist,
                methods,
                token,
                api_key,
                headers,
                timeout,
                status_filter,
                rate,
            } => {
                banner();
                if let Err(e) = modules::api::enumerate::enumerate(
                    &url,
                    &wordlist,
                    &methods,
                    token.as_deref(),
                    api_key.as_deref(),
                    headers.as_deref(),
                    timeout,
                    status_filter.as_deref(),
                    rate,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            ApiAction::Fuzz {
                url,
                wordlist,
                token,
                value,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::api::fuzz::fuzz(&url, &wordlist, token.as_deref(), &value, timeout)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            ApiAction::GraphQL {
                url,
                token,
                suggest,
                wordlist,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::api::graphql::graphql(
                    &url,
                    token.as_deref(),
                    suggest,
                    wordlist.as_deref(),
                    timeout,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            ApiAction::Auth {
                url,
                token,
                idor,
                no_auth,
                jwt_none,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::api::auth::auth(
                    &url,
                    token.as_deref(),
                    idor,
                    no_auth,
                    jwt_none,
                    timeout,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ratelimit { action } => match action {
            RatelimitAction::Burst {
                url,
                count,
                rate,
                workers,
                token,
                method,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ratelimit::burst(
                    &url,
                    count,
                    rate,
                    workers,
                    token.as_deref(),
                    &method,
                    timeout,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            RatelimitAction::Distributed {
                url,
                count,
                sources,
                rate,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ratelimit::distributed(
                    &url,
                    count,
                    sources,
                    rate,
                    token.as_deref(),
                    timeout,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            RatelimitAction::Report {
                url,
                endpoints,
                count,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::ratelimit::report(&url, &endpoints, count, token.as_deref(), timeout)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Tls { action } => match action {
            TlsAction::Scan { host, verbose } => {
                banner();
                match modules::tls::scan_host(&host, verbose).await {
                    Ok(result) => modules::tls::print_scan_result(&result),
                    Err(e) => println!("{} Error: {}", "[-]".red().bold(), e),
                }
            }

            TlsAction::Batch {
                file,
                output,
                workers,
            } => {
                banner();
                if let Err(e) = modules::tls::batch_scan(&file, output.as_deref(), workers).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            TlsAction::Report {
                input,
                format,
                output,
            } => {
                banner();
                if let Err(e) =
                    modules::tls::generate_report(&input, &format, output.as_deref()).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ioc { action } => match action {
            IocAction::Extract {
                file,
                types,
                format,
                output,
            } => {
                banner();
                if let Err(e) =
                    modules::ioc::extract(&file, &types, &format, output.as_deref()).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            IocAction::Hunt {
                file,
                pattern,
                context,
            } => {
                banner();
                if let Err(e) = modules::ioc::hunt(&file, &pattern, context).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }

            IocAction::Stats { file, min } => {
                banner();
                if let Err(e) = modules::ioc::stats(&file, min).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Sqli { action } => match action {
            SqliAction::Error {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::sqli::error_scan(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SqliAction::Blind {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::sqli::blind_scan(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SqliAction::Time {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::sqli::time_scan(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SqliAction::Dump {
                url,
                param,
                token,
                timeout,
                table,
            } => {
                banner();
                if let Err(e) =
                    modules::sqli::dump(&url, &param, token.as_deref(), timeout, &table).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Xss { action } => match action {
            XssAction::Reflect {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::xss::reflect(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            XssAction::Store {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::xss::store(&url, &param, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            XssAction::Dom {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::xss::dom(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            XssAction::Blind {
                url,
                param,
                callback_url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::xss::blind(&url, &param, &callback_url, token.as_deref(), timeout)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Cmdi { action } => match action {
            CmdiAction::Os {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::cmdi::os_inject(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CmdiAction::Filter {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::cmdi::filter_bypass(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CmdiAction::Time {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::cmdi::time_based(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CmdiAction::Oob {
                url,
                param,
                callback_host,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::cmdi::oob(&url, &param, &callback_host, token.as_deref(), timeout)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Xxe { action } => match action {
            XxeAction::File {
                url,
                token,
                timeout,
                file,
            } => {
                banner();
                if let Err(e) =
                    modules::xxe::file_read(&url, token.as_deref(), timeout, &file).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            XxeAction::Ssrf {
                url,
                token,
                timeout,
                target_url,
            } => {
                banner();
                if let Err(e) =
                    modules::xxe::ssrf(&url, token.as_deref(), timeout, &target_url).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            XxeAction::Blind {
                url,
                token,
                timeout,
                callback_host,
            } => {
                banner();
                if let Err(e) =
                    modules::xxe::blind(&url, token.as_deref(), timeout, &callback_host).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            XxeAction::Oob {
                url,
                token,
                timeout,
                callback_host,
                file,
            } => {
                banner();
                if let Err(e) =
                    modules::xxe::oob(&url, token.as_deref(), timeout, &callback_host, &file).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Lfi { action } => match action {
            LfiAction::Read {
                url,
                param,
                token,
                timeout,
                file,
            } => {
                banner();
                if let Err(e) =
                    modules::lfi::read(&url, &param, token.as_deref(), timeout, &file).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LfiAction::Include {
                url,
                param,
                token,
                timeout,
                remote_url,
            } => {
                banner();
                if let Err(e) =
                    modules::lfi::include(&url, &param, token.as_deref(), timeout, &remote_url)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LfiAction::Wrapper {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::lfi::wrapper(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LfiAction::Log {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::lfi::log_poison(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::SsrfChain { action } => match action {
            SsrfChainAction::Metadata {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::ssrf_chain::metadata(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SsrfChainAction::Gopher {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::ssrf_chain::gopher(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SsrfChainAction::Blind {
                url,
                param,
                callback_host,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ssrf_chain::blind(
                    &url,
                    &param,
                    &callback_host,
                    token.as_deref(),
                    timeout,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SsrfChainAction::Scan {
                url,
                param,
                token,
                timeout,
                ports,
            } => {
                banner();
                if let Err(e) =
                    modules::ssrf_chain::scan(&url, &param, token.as_deref(), timeout, &ports).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SsrfChainAction::CloudV2 {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::ssrf_chain::cloud_v2(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Cors { action } => match action {
            CorsAction::Origin { url, timeout } => {
                banner();
                if let Err(e) = modules::cors::origin(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CorsAction::Creds { url, timeout } => {
                banner();
                if let Err(e) = modules::cors::creds(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CorsAction::Wildcard { url, timeout } => {
                banner();
                if let Err(e) = modules::cors::wildcard(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CorsAction::Null { url, timeout } => {
                banner();
                if let Err(e) = modules::cors::null_origin(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Crlf { action } => match action {
            CrlfAction::Header {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::crlf::header(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CrlfAction::Body {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::crlf::body(&url, &param, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CrlfAction::Split {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::crlf::split(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CrlfAction::Log {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::crlf::log(&url, &param, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Redirect { action } => match action {
            RedirectAction::Scan {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::redirect::scan(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RedirectAction::Bypass {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::redirect::bypass(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RedirectAction::Chain {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::redirect::chain(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Cache { action } => match action {
            CacheAction::Poison {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::cache::poison(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CacheAction::Deceive {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::cache::deceive(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CacheAction::Key {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::cache::key(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Smuggle { action } => match action {
            SmuggleAction::Clte {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::smuggle::clte(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmuggleAction::Tecl {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::smuggle::tecl(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmuggleAction::Cl0 {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::smuggle::cl0(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmuggleAction::Detect {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::smuggle::detect(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmuggleAction::Desync {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::smuggle::desync(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ws { action } => match action {
            WsAction::Fuzz {
                url,
                token,
                timeout,
                message,
            } => {
                banner();
                if let Err(e) = modules::ws::fuzz(&url, token.as_deref(), timeout, &message).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WsAction::Inject {
                url,
                token,
                timeout,
                payload,
            } => {
                banner();
                if let Err(e) = modules::ws::inject(&url, token.as_deref(), timeout, &payload).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WsAction::Cswssh {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ws::cswssh(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WsAction::Auth {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ws::auth(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::GraphqlAttack { action } => match action {
            GraphqlAttackAction::Introspect {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::graphql_attack::introspect(&url, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GraphqlAttackAction::Batch {
                url,
                token,
                timeout,
                count,
            } => {
                banner();
                if let Err(e) =
                    modules::graphql_attack::batch(&url, token.as_deref(), timeout, count).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GraphqlAttackAction::Suggest {
                url,
                token,
                timeout,
                wordlist,
            } => {
                banner();
                if let Err(e) = modules::graphql_attack::suggest(
                    &url,
                    token.as_deref(),
                    timeout,
                    wordlist.as_deref(),
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GraphqlAttackAction::Depth {
                url,
                token,
                timeout,
                max_depth,
            } => {
                banner();
                if let Err(e) =
                    modules::graphql_attack::depth(&url, token.as_deref(), timeout, max_depth).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GraphqlAttackAction::Fuzz {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::graphql_attack::fuzz(&url, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Oauth { action } => match action {
            OauthAction::Redirect {
                auth_url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::oauth::redirect(&auth_url, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OauthAction::State {
                auth_url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::oauth::state(&auth_url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OauthAction::Token {
                token_url,
                client_id,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::oauth::token(&token_url, &client_id, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OauthAction::Scope {
                token_url,
                client_id,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::oauth::scope(&token_url, &client_id, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OauthAction::Ato {
                auth_url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::oauth::ato(&auth_url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ssti { action } => match action {
            SstiAction::Detect {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ssti::detect(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SstiAction::Jinja {
                url,
                param,
                token,
                timeout,
                cmd,
            } => {
                banner();
                if let Err(e) =
                    modules::ssti::jinja(&url, &param, token.as_deref(), timeout, &cmd).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SstiAction::Twig {
                url,
                param,
                token,
                timeout,
                cmd,
            } => {
                banner();
                if let Err(e) =
                    modules::ssti::twig(&url, &param, token.as_deref(), timeout, &cmd).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SstiAction::Freemarker {
                url,
                param,
                token,
                timeout,
                cmd,
            } => {
                banner();
                if let Err(e) =
                    modules::ssti::freemarker(&url, &param, token.as_deref(), timeout, &cmd).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Proto { action } => match action {
            ProtoAction::Scan {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::proto::scan(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ProtoAction::Gadget {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::proto::gadget(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ProtoAction::Exploit {
                url,
                token,
                timeout,
                cmd,
            } => {
                banner();
                if let Err(e) = modules::proto::exploit(&url, token.as_deref(), timeout, &cmd).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Race { action } => match action {
            RaceAction::Race {
                url,
                method,
                body,
                token,
                timeout,
                workers,
                count,
            } => {
                banner();
                if let Err(e) = modules::race::race(
                    &url,
                    &method,
                    body.as_deref(),
                    token.as_deref(),
                    timeout,
                    workers,
                    count,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RaceAction::Toctou {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::race::toctou(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RaceAction::Balance {
                url,
                account,
                token,
                timeout,
                workers,
                amount,
            } => {
                banner();
                if let Err(e) = modules::race::balance(
                    &url,
                    &account,
                    token.as_deref(),
                    timeout,
                    workers,
                    &amount,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RaceAction::Coupon {
                url,
                coupon,
                token,
                timeout,
                workers,
            } => {
                banner();
                if let Err(e) =
                    modules::race::coupon(&url, &coupon, token.as_deref(), timeout, workers).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Host { action } => match action {
            HostAction::Password {
                url,
                token,
                timeout,
                email,
            } => {
                banner();
                if let Err(e) =
                    modules::host::password(&url, token.as_deref(), timeout, &email).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            HostAction::Cache {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::host::cache(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            HostAction::Access {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::host::access(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            HostAction::Ssrf {
                url,
                token,
                timeout,
                target,
            } => {
                banner();
                if let Err(e) = modules::host::ssrf(&url, token.as_deref(), timeout, &target).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Acl { action } => match action {
            AclAction::Idor {
                url,
                token,
                timeout,
                start_id,
                count,
            } => {
                banner();
                if let Err(e) =
                    modules::acl::idor(&url, token.as_deref(), timeout, start_id, count).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AclAction::Bfla {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::acl::bfla(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AclAction::Privilege {
                url,
                token,
                timeout,
                low_token,
            } => {
                banner();
                if let Err(e) =
                    modules::acl::privilege(&url, token.as_deref(), timeout, &low_token).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AclAction::Path {
                url,
                token,
                timeout,
                wordlist,
            } => {
                banner();
                if let Err(e) =
                    modules::acl::path(&url, token.as_deref(), timeout, wordlist.as_deref()).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Takeover { action } => match action {
            TakeoverAction::Scan {
                domains_file,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::takeover::scan(&domains_file, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            TakeoverAction::Verify {
                domain,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::takeover::verify(&domain, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            TakeoverAction::Fingerprint {
                domain,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::takeover::fingerprint(&domain, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Cloud { action } => match action {
            CloudAction::S3 {
                bucket,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::cloud::s3(&bucket, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CloudAction::Iam { token, timeout } => {
                banner();
                if let Err(e) = modules::cloud::iam(token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CloudAction::Lambda {
                function_url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::cloud::lambda(&function_url, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CloudAction::Metadata {
                target_url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::cloud::metadata(&target_url, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::K8s { action } => match action {
            K8sAction::Pods {
                api_server,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::k8s::pods(&api_server, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            K8sAction::Rbac {
                api_server,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::k8s::rbac(&api_server, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            K8sAction::Secrets {
                api_server,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::k8s::secrets(&api_server, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            K8sAction::Escape {
                api_server,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::k8s::escape(&api_server, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Rebind { action } => match action {
            RebindAction::Attack {
                target,
                token,
                timeout,
                interval,
                count,
            } => {
                banner();
                if let Err(e) =
                    modules::rebind::attack(&target, token.as_deref(), timeout, interval, count)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RebindAction::Listen {
                port,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::rebind::listen(port, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RebindAction::Bypass {
                target,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::rebind::bypass(&target, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Spray { action } => match action {
            SprayAction::Spray {
                url,
                users_file,
                password,
                timeout,
                delay,
            } => {
                banner();
                if let Err(e) =
                    modules::spray::spray(&url, &users_file, &password, timeout, delay).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SprayAction::Lockout {
                url,
                user,
                timeout,
                count,
            } => {
                banner();
                if let Err(e) = modules::spray::lockout(&url, &user, timeout, count).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SprayAction::Policy { url, timeout } => {
                banner();
                if let Err(e) = modules::spray::policy(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SprayAction::Round {
                url,
                users_file,
                timeout,
                delay,
            } => {
                banner();
                if let Err(e) = modules::spray::round(&url, &users_file, timeout, delay).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Brute { action } => match action {
            BruteAction::Http {
                url,
                users_file,
                pass_file,
                timeout,
                workers,
            } => {
                banner();
                if let Err(e) =
                    modules::brute::http(&url, &users_file, &pass_file, timeout, workers).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            BruteAction::Ssh {
                host,
                port,
                users_file,
                pass_file,
                timeout,
                workers,
            } => {
                banner();
                if let Err(e) =
                    modules::brute::ssh(&host, port, &users_file, &pass_file, timeout, workers)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            BruteAction::Ftp {
                host,
                port,
                users_file,
                pass_file,
                timeout,
                workers,
            } => {
                banner();
                if let Err(e) =
                    modules::brute::ftp(&host, port, &users_file, &pass_file, timeout, workers)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            BruteAction::Form {
                url,
                users_file,
                pass_file,
                timeout,
                workers,
                user_field,
                pass_field,
                fail_text,
            } => {
                banner();
                if let Err(e) = modules::brute::form(
                    &url,
                    &users_file,
                    &pass_file,
                    timeout,
                    workers,
                    &user_field,
                    &pass_field,
                    &fail_text,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Payload { action } => match action {
            PayloadAction::Xss { context } => {
                banner();
                if let Err(e) = modules::payload::xss(&context).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PayloadAction::Sqli { context } => {
                banner();
                if let Err(e) = modules::payload::sqli(&context).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PayloadAction::Cmdi { context } => {
                banner();
                if let Err(e) = modules::payload::cmdi(&context).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PayloadAction::Encode { input, encoding } => {
                banner();
                if let Err(e) = modules::payload::encode(&input, &encoding).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Exfil { action } => match action {
            ExfilAction::Dns {
                domain,
                data,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::exfil::dns(&domain, &data, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExfilAction::Icmp {
                host,
                data,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::exfil::icmp(&host, &data, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExfilAction::Http { url, data, timeout } => {
                banner();
                if let Err(e) = modules::exfil::http(&url, &data, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExfilAction::Stego { url, data, timeout } => {
                banner();
                if let Err(e) = modules::exfil::stego(&url, &data, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Wfuzz { action } => match action {
            WfuzzAction::Param {
                url,
                wordlist,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::wfuzz::param(&url, wordlist.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WfuzzAction::Header {
                url,
                wordlist,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::wfuzz::header(&url, wordlist.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WfuzzAction::Body {
                url,
                wordlist,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::wfuzz::body(&url, wordlist.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WfuzzAction::Cookie {
                url,
                wordlist,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::wfuzz::cookie(&url, wordlist.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Deser { action } => match action {
            DeserAction::Detect {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::deser::detect(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DeserAction::Java {
                url,
                token,
                timeout,
                cmd,
            } => {
                banner();
                if let Err(e) = modules::deser::java(&url, token.as_deref(), timeout, &cmd).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DeserAction::Net {
                url,
                token,
                timeout,
                cmd,
            } => {
                banner();
                if let Err(e) = modules::deser::net(&url, token.as_deref(), timeout, &cmd).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DeserAction::Php {
                url,
                token,
                timeout,
                cmd,
            } => {
                banner();
                if let Err(e) = modules::deser::php(&url, token.as_deref(), timeout, &cmd).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Exploit { action } => match action {
            ExploitAction::Search { query } => {
                banner();
                if let Err(e) = modules::exploit::search(&query).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExploitAction::Lookup { cve } => {
                banner();
                if let Err(e) = modules::exploit::lookup(&cve).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExploitAction::Recent {
                start,
                end,
                severity,
            } => {
                banner();
                if let Err(e) = modules::exploit::recent(&start, &end, severity.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExploitAction::Run {
                cve,
                target,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::exploit::run(&cve, &target, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExploitAction::Verify {
                cve,
                target,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::exploit::verify(&cve, &target, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExploitAction::Chain {
                cves,
                target,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::exploit::chain(&cves, &target, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Llm { action } => match action {
            LlmAction::Inject {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::llm::inject(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LlmAction::Jailbreak {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::llm::jailbreak(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LlmAction::Leak {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::llm::leak(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LlmAction::Hijack {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::llm::hijack(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LlmAction::Exfil {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::llm::exfil(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LlmAction::Bypass {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::llm::bypass(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Agent { action } => match action {
            AgentAction::Tool {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::agent::tool(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AgentAction::Rag {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::agent::rag(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AgentAction::Memory {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::agent::memory(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AgentAction::Plugin {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::agent::plugin(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Ai { action } => match action {
            AiAction::Extract {
                url,
                queries,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::ai::extract(&url, queries, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AiAction::Hyper {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::ai::hyper(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AiAction::Adversarial {
                url,
                input_type,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) =
                    modules::ai::adversarial(&url, &input_type, timeout, token.as_deref()).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Vectordb { action } => match action {
            VectordbAction::Extract {
                url,
                limit,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) =
                    modules::vectordb::extract(&url, limit, timeout, token.as_deref()).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            VectordbAction::Enum {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::vectordb::enumerate(&url, timeout, token.as_deref()).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            VectordbAction::Probe { url, timeout } => {
                banner();
                if let Err(e) = modules::vectordb::probe(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Aws { action } => match action {
            AwsAction::Privesc { token, timeout } => {
                banner();
                if let Err(e) = modules::aws::privesc(token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AwsAction::LambdaInject { url, token, timeout } => {
                banner();
                if let Err(e) = modules::aws::lambda_inject(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Gcp { action } => match action {
            GcpAction::Abuse { token, timeout } => {
                banner();
                if let Err(e) = modules::gcp::abuse(token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Azure { action } => match action {
            AzureAction::App {
                tenant,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::azure::app(&tenant, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Tfstate { action } => match action {
            TfstateAction::Exploit {
                bucket,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::tfstate::exploit(&bucket, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Istio { action } => match action {
            IstioAction::Enum {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::istio::enumerate(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            IstioAction::Probe { url, timeout } => {
                banner();
                if let Err(e) = modules::istio::probe(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Argocd { action } => match action {
            ArgoCDAction::Enum {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::argocd::enumerate(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ArgoCDAction::Probe { url, timeout } => {
                banner();
                if let Err(e) = modules::argocd::probe(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Dom { action } => match action {
            DomAction::Clobber {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::dom::clobber(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Xsleak { action } => match action {
            XsleakAction::Detect {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::xsleak::detect(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Oidc { action } => match action {
            OidcAction::Confuse {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::oidc::confuse(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Passkey { action } => match action {
            PasskeyAction::Abuse {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::passkey::abuse(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Sso { action } => match action {
            SsoAction::Hijack {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::sso::hijack(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Magiclink { action } => match action {
            MagiclinkAction::Abuse {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::magiclink::abuse(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Gha { action } => match action {
            GhaAction::Inject {
                repo,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::gha::inject(&repo, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Gitlabci { action } => match action {
            GitlabciAction::Inject {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::gitlabci::inject(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Jenkins { action } => match action {
            JenkinsAction::Rce {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::jenkins::rce(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Mfa { action } => match action {
            MfaAction::Fatigue {
                url,
                user,
                count,
                delay,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::mfa::fatigue(&url, &user, count, delay, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MfaAction::Race {
                url,
                user,
                otp,
                count,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::mfa::race(&url, &user, &otp, count, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MfaAction::Otp {
                url,
                user,
                timeout,
                count,
            } => {
                banner();
                if let Err(e) = modules::mfa::otp(&url, &user, timeout, count).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MfaAction::Fallback { url, user, timeout } => {
                banner();
                if let Err(e) = modules::mfa::fallback(&url, &user, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Saml { action } => match action {
            SamlAction::Xsw {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::saml::xsw(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SamlAction::Response {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::saml::response(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SamlAction::Cert { url, timeout } => {
                banner();
                if let Err(e) = modules::saml::cert(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SamlAction::Assertion {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::saml::assertion(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Webauthn { action } => match action {
            WebauthnAction::Origin { url, timeout } => {
                banner();
                if let Err(e) = modules::webauthn::origin(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebauthnAction::Resident { url, timeout } => {
                banner();
                if let Err(e) = modules::webauthn::resident(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebauthnAction::Relay { url, timeout } => {
                banner();
                if let Err(e) = modules::webauthn::relay(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebauthnAction::Downgrade { url, timeout } => {
                banner();
                if let Err(e) = modules::webauthn::downgrade(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Csp { action } => match action {
            CspAction::Analyze { url, timeout } => {
                banner();
                if let Err(e) = modules::csp::analyze(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CspAction::Bypass {
                url,
                timeout,
                callback,
            } => {
                banner();
                if let Err(e) = modules::csp::bypass(&url, timeout, &callback).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CspAction::Inline {
                url,
                timeout,
                callback,
            } => {
                banner();
                if let Err(e) = modules::csp::inline(&url, timeout, &callback).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CspAction::Exfil {
                url,
                timeout,
                callback,
            } => {
                banner();
                if let Err(e) = modules::csp::exfil(&url, timeout, &callback).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::H2 { action } => match action {
            H2Action::Rapidreset {
                url,
                count,
                rate,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::h2::rapidreset(&url, count, rate, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            H2Action::Stream {
                url,
                count,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::h2::stream(&url, count, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            H2Action::Header { url, timeout } => {
                banner();
                if let Err(e) = modules::h2::header(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            H2Action::Priority { url, timeout } => {
                banner();
                if let Err(e) = modules::h2::priority(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Jndi { action } => match action {
            JndiAction::Ldap {
                url,
                callback,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::jndi::ldap(&url, &callback, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            JndiAction::Rmi {
                url,
                callback,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::jndi::rmi(&url, &callback, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            JndiAction::Dns {
                url,
                callback,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::jndi::dns(&url, &callback, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            JndiAction::Gadget {
                url,
                callback,
                timeout,
                cmd,
            } => {
                banner();
                if let Err(e) = modules::jndi::gadget(&url, &callback, timeout, &cmd).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Container { action } => match action {
            ContainerAction::Docker { url, timeout } => {
                banner();
                if let Err(e) = modules::container::docker(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ContainerAction::Kubelet { url, timeout } => {
                banner();
                if let Err(e) = modules::container::kubelet(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ContainerAction::Cap { url, timeout } => {
                banner();
                if let Err(e) = modules::container::cap(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ContainerAction::Mount { url, timeout } => {
                banner();
                if let Err(e) = modules::container::mount(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Cicd { action } => match action {
            CicdAction::Inject {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::cicd::inject(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CicdAction::Poison {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::cicd::poison(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CicdAction::Runner {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::cicd::runner(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CicdAction::Webhook { url, timeout } => {
                banner();
                if let Err(e) = modules::cicd::webhook(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Supply { action } => match action {
            SupplyAction::Typosquat {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::supply::typosquat(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SupplyAction::Confusion {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::supply::confusion(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SupplyAction::Poison {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::supply::poison(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SupplyAction::Audit {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::supply::audit(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Subdom { action } => match action {
            SubdomAction::Brute {
                domain,
                timeout,
                wordlist,
            } => {
                banner();
                if let Err(e) = modules::subdom::brute(&domain, timeout, wordlist.as_deref()).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SubdomAction::Ct { domain, timeout } => {
                banner();
                if let Err(e) = modules::subdom::ct(&domain, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SubdomAction::Passive { domain, timeout } => {
                banner();
                if let Err(e) = modules::subdom::passive(&domain, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SubdomAction::Permutate { domain, timeout } => {
                banner();
                if let Err(e) = modules::subdom::permutate(&domain, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Secret { action } => match action {
            SecretAction::Js { url, timeout } => {
                banner();
                if let Err(e) = modules::secret::js(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SecretAction::Repo {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::secret::repo(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SecretAction::Response {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::secret::response(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SecretAction::Docker {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::secret::docker(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Web3 { action } => match action {
            Web3Action::Reentrancy {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::web3::reentrancy(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            Web3Action::Overflow {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::web3::overflow(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            Web3Action::Access {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::web3::access(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            Web3Action::Delegatecall {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::web3::delegatecall(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
        Commands::Webrtc { action } => match action {
            WebrtcAction::Leak { url, timeout } => {
                banner();
                if let Err(e) = modules::webrtc::leak(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebrtcAction::Stun { url, timeout } => {
                banner();
                if let Err(e) = modules::webrtc::stun(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebrtcAction::Relay { url, timeout } => {
                banner();
                if let Err(e) = modules::webrtc::relay(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebrtcAction::Fingerprint { url, timeout } => {
                banner();
                if let Err(e) = modules::webrtc::fingerprint(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Git { action } => match action {
            GitAction::Expose { url, timeout } => {
                banner();
                if let Err(e) = modules::git::expose(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GitAction::Dump { url, timeout } => {
                banner();
                if let Err(e) = modules::git::dump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GitAction::Hook {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::git::hook(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GitAction::Actions {
                url,
                timeout,
                token,
            } => {
                banner();
                if let Err(e) = modules::git::actions(&url, timeout, token.as_deref()).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Nosqli { action } => match action {
            NosqliAction::Mongo {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::nosqli::mongo(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NosqliAction::Redis {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::nosqli::redis(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NosqliAction::Cassandra {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::nosqli::cassandra(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NosqliAction::Blind {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::nosqli::blind(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Grpc { action } => match action {
            GrpcAction::Reflect { url, timeout } => {
                banner();
                if let Err(e) = modules::grpc::reflect(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GrpcAction::Method { url, timeout } => {
                banner();
                if let Err(e) = modules::grpc::method(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GrpcAction::Meta { url, timeout } => {
                banner();
                if let Err(e) = modules::grpc::meta(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            GrpcAction::Stream {
                url,
                count,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::grpc::stream(&url, count, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Kerb { action } => match action {
            KerbAction::Roast { url, timeout } => {
                banner();
                if let Err(e) = modules::kerb::roast(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            KerbAction::Asrep { url, timeout } => {
                banner();
                if let Err(e) = modules::kerb::asrep(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            KerbAction::Diamond { url, timeout } => {
                banner();
                if let Err(e) = modules::kerb::diamond(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            KerbAction::S4u { url, timeout } => {
                banner();
                if let Err(e) = modules::kerb::s4u(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ldapi { action } => match action {
            LdapiAction::Filter {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::ldapi::filter(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LdapiAction::Blind {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ldapi::blind(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LdapiAction::Enum {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ldapi::enum_ldap(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            LdapiAction::Ad {
                url,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::ldapi::ad(&url, token.as_deref(), timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Postmsg { action } => match action {
            PostmsgAction::Origin { url, timeout } => {
                banner();
                if let Err(e) = modules::postmsg::origin(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PostmsgAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::postmsg::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PostmsgAction::Fuzz { url, timeout } => {
                banner();
                if let Err(e) = modules::postmsg::fuzz(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PostmsgAction::Chain { url, timeout } => {
                banner();
                if let Err(e) = modules::postmsg::chain(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Sw { action } => match action {
            SwAction::Register { url, timeout } => {
                banner();
                if let Err(e) = modules::sw::register(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SwAction::Hijack { url, timeout } => {
                banner();
                if let Err(e) = modules::sw::hijack(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SwAction::Persist { url, timeout } => {
                banner();
                if let Err(e) = modules::sw::persist(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SwAction::Fetch { url, timeout } => {
                banner();
                if let Err(e) = modules::sw::fetch(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Wasm { action } => match action {
            WasmAction::Analyze { url, timeout } => {
                banner();
                if let Err(e) = modules::wasm::analyze(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WasmAction::Memory { url, timeout } => {
                banner();
                if let Err(e) = modules::wasm::memory(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WasmAction::Import { url, timeout } => {
                banner();
                if let Err(e) = modules::wasm::import(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WasmAction::Reverse { url, timeout } => {
                banner();
                if let Err(e) = modules::wasm::reverse(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Mqtt { action } => match action {
            MqttAction::Connect { url, timeout } => {
                banner();
                if let Err(e) = modules::mqtt::connect(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MqttAction::Topic { url, timeout } => {
                banner();
                if let Err(e) = modules::mqtt::topic(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MqttAction::Retain { url, timeout } => {
                banner();
                if let Err(e) = modules::mqtt::retain(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MqttAction::Will { url, timeout } => {
                banner();
                if let Err(e) = modules::mqtt::will(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ot { action } => match action {
            OtAction::Modbus { url, timeout } => {
                banner();
                if let Err(e) = modules::ot::modbus(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OtAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::ot::enum_ot(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OtAction::Write { url, timeout } => {
                banner();
                if let Err(e) = modules::ot::write_test(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OtAction::Hmi { url, timeout } => {
                banner();
                if let Err(e) = modules::ot::hmi(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Padoracle { action } => match action {
            PadoracleAction::Detect {
                url,
                param,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::padoracle::detect(&url, &param, token.as_deref(), timeout).await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PadoracleAction::Decrypt {
                url,
                param,
                ciphertext,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::padoracle::decrypt(
                    &url,
                    &param,
                    &ciphertext,
                    token.as_deref(),
                    timeout,
                )
                .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PadoracleAction::Encrypt {
                url,
                param,
                plaintext,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::padoracle::encrypt(&url, &param, &plaintext, token.as_deref(), timeout)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            PadoracleAction::Bit {
                url,
                param,
                ciphertext,
                token,
                timeout,
            } => {
                banner();
                if let Err(e) =
                    modules::padoracle::bit(&url, &param, &ciphertext, token.as_deref(), timeout)
                        .await
                {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Sse { action } => match action {
            SseAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::sse::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SseAction::Exhaust {
                url,
                count,
                timeout,
            } => {
                banner();
                if let Err(e) = modules::sse::exhaust(&url, count, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SseAction::Exfil { url, timeout } => {
                banner();
                if let Err(e) = modules::sse::exfil(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SseAction::Replay { url, timeout } => {
                banner();
                if let Err(e) = modules::sse::replay(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ble { action } => match action {
            BleAction::Scan { url, timeout } => {
                banner();
                if let Err(e) = modules::ble::scan(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            BleAction::Gatt { url, timeout } => {
                banner();
                if let Err(e) = modules::ble::gatt(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            BleAction::Write { url, timeout } => {
                banner();
                if let Err(e) = modules::ble::write_test(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            BleAction::Mitm { url, timeout } => {
                banner();
                if let Err(e) = modules::ble::mitm(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ntp { action } => match action {
            NtpAction::Monlist { url, timeout } => {
                banner();
                if let Err(e) = modules::ntp::monlist(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NtpAction::Amplify { url, timeout } => {
                banner();
                if let Err(e) = modules::ntp::amplify(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NtpAction::Time { url, timeout } => {
                banner();
                if let Err(e) = modules::ntp::time(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NtpAction::Peek { url, timeout } => {
                banner();
                if let Err(e) = modules::ntp::peek(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Webdav { action } => match action {
            WebdavAction::Methods { url, timeout } => {
                banner();
                if let Err(e) = modules::webdav::methods(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebdavAction::Propfind { url, timeout } => {
                banner();
                if let Err(e) = modules::webdav::propfind(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebdavAction::Upload { url, timeout } => {
                banner();
                if let Err(e) = modules::webdav::upload(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WebdavAction::Copy { url, timeout } => {
                banner();
                if let Err(e) = modules::webdav::copy(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Dnsenum { action } => match action {
            DnsenumAction::Axfr { url, timeout } => {
                banner();
                if let Err(e) = modules::dnsenum::axfr(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DnsenumAction::Records { url, timeout } => {
                banner();
                if let Err(e) = modules::dnsenum::records(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DnsenumAction::Nsec { url, timeout } => {
                banner();
                if let Err(e) = modules::dnsenum::nsec(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DnsenumAction::Snoop { url, timeout } => {
                banner();
                if let Err(e) = modules::dnsenum::snoop(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Csrf { action } => match action {
            CsrfAction::Token { url, timeout } => {
                banner();
                if let Err(e) = modules::csrf::token(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CsrfAction::Samesite { url, timeout } => {
                banner();
                if let Err(e) = modules::csrf::samesite(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CsrfAction::Json { url, timeout } => {
                banner();
                if let Err(e) = modules::csrf::json(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CsrfAction::Method { url, timeout } => {
                banner();
                if let Err(e) = modules::csrf::method(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Click { action } => match action {
            ClickAction::Frame { url, timeout } => {
                banner();
                if let Err(e) = modules::click::frame(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ClickAction::Overlay { url, timeout } => {
                banner();
                if let Err(e) = modules::click::overlay(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ClickAction::Pointer { url, timeout } => {
                banner();
                if let Err(e) = modules::click::pointer(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ClickAction::Cursor { url, timeout } => {
                banner();
                if let Err(e) = modules::click::cursor(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Hpp { action } => match action {
            HppAction::Detect { url, timeout } => {
                banner();
                if let Err(e) = modules::hpp::detect(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            HppAction::Bypass { url, timeout } => {
                banner();
                if let Err(e) = modules::hpp::bypass(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            HppAction::Auth { url, timeout } => {
                banner();
                if let Err(e) = modules::hpp::auth(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            HppAction::Logic { url, timeout } => {
                banner();
                if let Err(e) = modules::hpp::logic(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Smtp { action } => match action {
            SmtpAction::Relay { url, timeout } => {
                banner();
                if let Err(e) = modules::smtp::relay(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmtpAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::smtp::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmtpAction::Spf { url, timeout } => {
                banner();
                if let Err(e) = modules::smtp::spf(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmtpAction::Command { url, timeout } => {
                banner();
                if let Err(e) = modules::smtp::command(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ftp { action } => match action {
            FtpAction::Anon { url, timeout } => {
                banner();
                if let Err(e) = modules::ftp::anon(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            FtpAction::Bounce { url, timeout } => {
                banner();
                if let Err(e) = modules::ftp::bounce(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            FtpAction::Traverse { url, timeout } => {
                banner();
                if let Err(e) = modules::ftp::traverse(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            FtpAction::Backdoor { url, timeout } => {
                banner();
                if let Err(e) = modules::ftp::backdoor(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Smb { action } => match action {
            SmbAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::smb::enum_smb(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmbAction::Null { url, timeout } => {
                banner();
                if let Err(e) = modules::smb::null(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmbAction::Eternal { url, timeout } => {
                banner();
                if let Err(e) = modules::smb::eternal(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SmbAction::Relay { url, timeout } => {
                banner();
                if let Err(e) = modules::smb::relay(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Rdp { action } => match action {
            RdpAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::rdp::enum_rdp(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RdpAction::Bluekeep { url, timeout } => {
                banner();
                if let Err(e) = modules::rdp::bluekeep(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RdpAction::Cred { url, timeout } => {
                banner();
                if let Err(e) = modules::rdp::cred(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RdpAction::Nla { url, timeout } => {
                banner();
                if let Err(e) = modules::rdp::nla(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ssh { action } => match action {
            SshAction::Audit { url, timeout } => {
                banner();
                if let Err(e) = modules::ssh::audit(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SshAction::Cipher { url, timeout } => {
                banner();
                if let Err(e) = modules::ssh::cipher(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SshAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::ssh::enum_ssh(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SshAction::Agent { url, timeout } => {
                banner();
                if let Err(e) = modules::ssh::agent(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Snmp { action } => match action {
            SnmpAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::snmp::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SnmpAction::Dump { url, timeout } => {
                banner();
                if let Err(e) = modules::snmp::dump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SnmpAction::Write { url, timeout } => {
                banner();
                if let Err(e) = modules::snmp::write(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SnmpAction::Amplify { url, timeout } => {
                banner();
                if let Err(e) = modules::snmp::amplify(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Redisx { action } => match action {
            RedisxAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::redisx::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RedisxAction::Rce { url, timeout } => {
                banner();
                if let Err(e) = modules::redisx::rce(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RedisxAction::Lua { url, timeout } => {
                banner();
                if let Err(e) = modules::redisx::lua(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RedisxAction::Exfil { url, timeout } => {
                banner();
                if let Err(e) = modules::redisx::exfil(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Elastic { action } => match action {
            ElasticAction::Expose { url, timeout } => {
                banner();
                if let Err(e) = modules::elastic::expose(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ElasticAction::Dump { url, timeout } => {
                banner();
                if let Err(e) = modules::elastic::dump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ElasticAction::Script { url, timeout } => {
                banner();
                if let Err(e) = modules::elastic::script(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ElasticAction::Reindex { url, timeout } => {
                banner();
                if let Err(e) = modules::elastic::reindex(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Amqp { action } => match action {
            AmqpAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::amqp::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AmqpAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::amqp::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AmqpAction::Flood { url, timeout } => {
                banner();
                if let Err(e) = modules::amqp::flood(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            AmqpAction::Mgmt { url, timeout } => {
                banner();
                if let Err(e) = modules::amqp::mgmt(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ipmi { action } => match action {
            IpmiAction::Cipher0 { url, timeout } => {
                banner();
                if let Err(e) = modules::ipmi::cipher0(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            IpmiAction::Default { url, timeout } => {
                banner();
                if let Err(e) = modules::ipmi::default(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            IpmiAction::Dump { url, timeout } => {
                banner();
                if let Err(e) = modules::ipmi::dump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            IpmiAction::Bmc { url, timeout } => {
                banner();
                if let Err(e) = modules::ipmi::bmc(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Coap { action } => match action {
            CoapAction::Discover { url, timeout } => {
                banner();
                if let Err(e) = modules::coap::discover(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CoapAction::Amplify { url, timeout } => {
                banner();
                if let Err(e) = modules::coap::amplify(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CoapAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::coap::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CoapAction::Cache { url, timeout } => {
                banner();
                if let Err(e) = modules::coap::cache(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Memcache { action } => match action {
            MemcacheAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::memcache::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MemcacheAction::Stats { url, timeout } => {
                banner();
                if let Err(e) = modules::memcache::stats(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MemcacheAction::Dump { url, timeout } => {
                banner();
                if let Err(e) = modules::memcache::dump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MemcacheAction::Slab { url, timeout } => {
                banner();
                if let Err(e) = modules::memcache::slab(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Mongo { action } => match action {
            MongoAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::mongo::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MongoAction::Dump { url, timeout } => {
                banner();
                if let Err(e) = modules::mongo::dump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MongoAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::mongo::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MongoAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::mongo::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Vnc { action } => match action {
            VncAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::vnc::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            VncAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::vnc::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            VncAction::Bypass { url, timeout } => {
                banner();
                if let Err(e) = modules::vnc::bypass(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            VncAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::vnc::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Telnet { action } => match action {
            TelnetAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::telnet::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            TelnetAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::telnet::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            TelnetAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::telnet::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            TelnetAction::Banner { url, timeout } => {
                banner();
                if let Err(e) = modules::telnet::banner(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Sip { action } => match action {
            SipAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::sip::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SipAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::sip::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SipAction::Register { url, timeout } => {
                banner();
                if let Err(e) = modules::sip::register(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SipAction::Invite { url, timeout } => {
                banner();
                if let Err(e) = modules::sip::invite(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Rtsp { action } => match action {
            RtspAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::rtsp::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RtspAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::rtsp::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RtspAction::Stream { url, timeout } => {
                banner();
                if let Err(e) = modules::rtsp::stream(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RtspAction::Cred { url, timeout } => {
                banner();
                if let Err(e) = modules::rtsp::cred(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Nfs { action } => match action {
            NfsAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::nfs::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NfsAction::Mount { url, timeout } => {
                banner();
                if let Err(e) = modules::nfs::mount(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NfsAction::Export { url, timeout } => {
                banner();
                if let Err(e) = modules::nfs::export(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NfsAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::nfs::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::X11 { action } => match action {
            X11Action::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::x11::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            X11Action::Keylog { url, timeout } => {
                banner();
                if let Err(e) = modules::x11::keylog(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            X11Action::Screenshot { url, timeout } => {
                banner();
                if let Err(e) = modules::x11::screenshot(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            X11Action::Bypass { url, timeout } => {
                banner();
                if let Err(e) = modules::x11::bypass(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Stomp { action } => match action {
            StompAction::Connect { url, timeout } => {
                banner();
                if let Err(e) = modules::stomp::connect(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            StompAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::stomp::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            StompAction::Flood { url, timeout } => {
                banner();
                if let Err(e) = modules::stomp::flood(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            StompAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::stomp::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Tftp { action } => match action {
            TftpAction::Read { url, timeout } => {
                banner();
                if let Err(e) = modules::tftp::read(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            TftpAction::Write { url, timeout } => {
                banner();
                if let Err(e) = modules::tftp::write(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            TftpAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::tftp::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            TftpAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::tftp::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Whois { action } => match action {
            WhoisAction::Lookup { url, timeout } => {
                banner();
                if let Err(e) = modules::whois::lookup(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WhoisAction::Reverse { url, timeout } => {
                banner();
                if let Err(e) = modules::whois::reverse(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WhoisAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::whois::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WhoisAction::Abuse { url, timeout } => {
                banner();
                if let Err(e) = modules::whois::abuse(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Finger { action } => match action {
            FingerAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::finger::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            FingerAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::finger::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            FingerAction::Redirect { url, timeout } => {
                banner();
                if let Err(e) = modules::finger::redirect(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            FingerAction::Bomb { url, timeout } => {
                banner();
                if let Err(e) = modules::finger::bomb(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Zookeeper { action } => match action {
            ZookeeperAction::Env { url, timeout } => {
                banner();
                if let Err(e) = modules::zookeeper::env(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ZookeeperAction::Dump { url, timeout } => {
                banner();
                if let Err(e) = modules::zookeeper::dump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ZookeeperAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::zookeeper::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ZookeeperAction::Srvr { url, timeout } => {
                banner();
                if let Err(e) = modules::zookeeper::srvr(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Etcd { action } => match action {
            EtcdAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::etcd::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            EtcdAction::Dump { url, timeout } => {
                banner();
                if let Err(e) = modules::etcd::dump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            EtcdAction::Keys { url, timeout } => {
                banner();
                if let Err(e) = modules::etcd::keys(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            EtcdAction::Auth { url, timeout } => {
                banner();
                if let Err(e) = modules::etcd::auth(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Upnp { action } => match action {
            UpnpAction::Discover { url, timeout } => {
                banner();
                if let Err(e) = modules::upnp::discover(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            UpnpAction::Expose { url, timeout } => {
                banner();
                if let Err(e) = modules::upnp::expose(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            UpnpAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::upnp::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            UpnpAction::Flood { url, timeout } => {
                banner();
                if let Err(e) = modules::upnp::flood(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Idor { action } => match action {
            IdorAction::Test { url, timeout } => {
                banner();
                if let Err(e) = modules::idor::test(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            IdorAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::idor::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            IdorAction::Predict { url, timeout } => {
                banner();
                if let Err(e) = modules::idor::predict(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            IdorAction::Chain { url, timeout } => {
                banner();
                if let Err(e) = modules::idor::chain(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Mass { action } => match action {
            MassAction::Check { url, timeout } => {
                banner();
                if let Err(e) = modules::mass::check(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MassAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::mass::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MassAction::Escalate { url, timeout } => {
                banner();
                if let Err(e) = modules::mass::escalate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            MassAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::mass::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Cookie { action } => match action {
            CookieAction::Fixation { url, timeout } => {
                banner();
                if let Err(e) = modules::cookie::fixation(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CookieAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::cookie::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CookieAction::Tamper { url, timeout } => {
                banner();
                if let Err(e) = modules::cookie::tamper(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            CookieAction::Overflow { url, timeout } => {
                banner();
                if let Err(e) = modules::cookie::overflow(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Session { action } => match action {
            SessionAction::Fixation { url, timeout } => {
                banner();
                if let Err(e) = modules::session::fixation(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SessionAction::Predict { url, timeout } => {
                banner();
                if let Err(e) = modules::session::predict(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SessionAction::Hijack { url, timeout } => {
                banner();
                if let Err(e) = modules::session::hijack(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SessionAction::Puzzle { url, timeout } => {
                banner();
                if let Err(e) = modules::session::puzzle(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Rce { action } => match action {
            RceAction::Detect { url, timeout } => {
                banner();
                if let Err(e) = modules::rce::detect(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RceAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::rce::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RceAction::Chain { url, timeout } => {
                banner();
                if let Err(e) = modules::rce::chain(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            RceAction::Oob { url, timeout } => {
                banner();
                if let Err(e) = modules::rce::oob(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Actuator { action } => match action {
            ActuatorAction::Env { url, timeout } => {
                banner();
                if let Err(e) = modules::actuator::env(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ActuatorAction::Heapdump { url, timeout } => {
                banner();
                if let Err(e) = modules::actuator::heapdump(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ActuatorAction::Jolokia { url, timeout } => {
                banner();
                if let Err(e) = modules::actuator::jolokia(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ActuatorAction::Shutdown { url, timeout } => {
                banner();
                if let Err(e) = modules::actuator::shutdown(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Debug { action } => match action {
            DebugAction::Scan { url, timeout } => {
                banner();
                if let Err(e) = modules::debug::scan(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DebugAction::Trace { url, timeout } => {
                banner();
                if let Err(e) = modules::debug::trace(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DebugAction::Stack { url, timeout } => {
                banner();
                if let Err(e) = modules::debug::stack(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            DebugAction::Source { url, timeout } => {
                banner();
                if let Err(e) = modules::debug::source(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Openapi { action } => match action {
            OpenapiAction::Spec { url, timeout } => {
                banner();
                if let Err(e) = modules::openapi::spec(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OpenapiAction::Fuzz { url, timeout } => {
                banner();
                if let Err(e) = modules::openapi::fuzz(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OpenapiAction::Auth { url, timeout } => {
                banner();
                if let Err(e) = modules::openapi::auth(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OpenapiAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::openapi::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Unicode { action } => match action {
            UnicodeAction::Homoglyph { url, timeout } => {
                banner();
                if let Err(e) = modules::unicode::homoglyph(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            UnicodeAction::Overlong { url, timeout } => {
                banner();
                if let Err(e) = modules::unicode::overlong(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            UnicodeAction::Bidi { url, timeout } => {
                banner();
                if let Err(e) = modules::unicode::bidi(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            UnicodeAction::Normalize { url, timeout } => {
                banner();
                if let Err(e) = modules::unicode::normalize(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Wsdl { action } => match action {
            WsdlAction::Parse { url, timeout } => {
                banner();
                if let Err(e) = modules::wsdl::parse(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WsdlAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::wsdl::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WsdlAction::Xxe { url, timeout } => {
                banner();
                if let Err(e) = modules::wsdl::xxe(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WsdlAction::Fuzz { url, timeout } => {
                banner();
                if let Err(e) = modules::wsdl::fuzz(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Ntlm { action } => match action {
            NtlmAction::Relay { url, timeout } => {
                banner();
                if let Err(e) = modules::ntlm::relay(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NtlmAction::Pass { url, timeout } => {
                banner();
                if let Err(e) = modules::ntlm::pass(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NtlmAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::ntlm::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            NtlmAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::ntlm::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Winrm { action } => match action {
            WinrmAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::winrm::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WinrmAction::Exec { url, timeout } => {
                banner();
                if let Err(e) = modules::winrm::exec(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WinrmAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::winrm::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            WinrmAction::Lateral { url, timeout } => {
                banner();
                if let Err(e) = modules::winrm::lateral(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Exchange { action } => match action {
            ExchangeAction::Proxylogon { url, timeout } => {
                banner();
                if let Err(e) = modules::exchange::proxylogon(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExchangeAction::Proxyshell { url, timeout } => {
                banner();
                if let Err(e) = modules::exchange::proxyshell(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExchangeAction::Proxynotshell { url, timeout } => {
                banner();
                if let Err(e) = modules::exchange::proxynotshell(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            ExchangeAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::exchange::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Owa { action } => match action {
            OwaAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::owa::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OwaAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::owa::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OwaAction::Spray { url, timeout } => {
                banner();
                if let Err(e) = modules::owa::spray(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            OwaAction::Rule { url, timeout } => {
                banner();
                if let Err(e) = modules::owa::rule(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Sharepoint { action } => match action {
            SharepointAction::Enum { url, timeout } => {
                banner();
                if let Err(e) = modules::sharepoint::enumerate(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SharepointAction::Brute { url, timeout } => {
                banner();
                if let Err(e) = modules::sharepoint::brute(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SharepointAction::Access { url, timeout } => {
                banner();
                if let Err(e) = modules::sharepoint::access(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
            SharepointAction::Inject { url, timeout } => {
                banner();
                if let Err(e) = modules::sharepoint::inject(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },

        Commands::Waf { action } => match action {
            WafAction::Detect { url, timeout } => {
                banner();
                if let Err(e) = modules::waf::detect(&url, timeout).await {
                    println!("{} Error: {}", "[-]".red().bold(), e);
                }
            }
        },
    }

    Ok(())
}
