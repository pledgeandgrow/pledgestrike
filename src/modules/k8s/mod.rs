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

pub async fn pods(
    api_server: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Kubernetes Pod Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} API Server: {}", "[*]".cyan().bold(), api_server);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let endpoints = [
        ("All pods", "/api/v1/pods"),
        ("Default namespace pods", "/api/v1/namespaces/default/pods"),
        ("All namespaces", "/api/v1/namespaces"),
        ("Nodes", "/api/v1/nodes"),
        ("Services", "/api/v1/services"),
        ("Deployments", "/apis/apps/v1/deployments"),
        ("DaemonSets", "/apis/apps/v1/daemonsets"),
        ("StatefulSets", "/apis/apps/v1/statefulsets"),
        ("CronJobs", "/apis/batch/v1/cronjobs"),
        ("Ingresses", "/apis/networking.k8s.io/v1/ingresses"),
    ];

    for (name, path) in &endpoints {
        let url = format!("{}{}", api_server.trim_end_matches('/'), path);
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let status_str = if accessible { "ACCESSIBLE".red().bold().to_string() }
                    else if status == 401 { "unauthorized".to_string() }
                    else if status == 403 { "forbidden".to_string() }
                    else { format!("status {}", status) };
                println!("  {} {:30} status={} {}", "*".cyan(), name, status, status_str);

                if accessible {
                    let count = body.matches("\"name\"").count();
                    println!("    {} Found {} name references", "*".cyan(), count);
                    if body.contains("clusterIP") || body.contains("externalIP") {
                        println!("    {} Contains network configuration!", ">".red().bold());
                    }
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Pod enumeration complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn rbac(
    api_server: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Kubernetes RBAC Analysis", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} API Server: {}", "[*]".cyan().bold(), api_server);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let endpoints = [
        ("ClusterRoles", "/apis/rbac.authorization.k8s.io/v1/clusterroles"),
        ("ClusterRoleBindings", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"),
        ("Roles", "/apis/rbac.authorization.k8s.io/v1/roles"),
        ("RoleBindings", "/apis/rbac.authorization.k8s.io/v1/rolebindings"),
        ("SelfSubjectAccessReview", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"),
        ("SelfSubjectRulesReview", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"),
    ];

    for (name, path) in &endpoints {
        let url = format!("{}{}", api_server.trim_end_matches('/'), path);
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let status_str = if accessible { "ACCESSIBLE".red().bold().to_string() }
                    else { format!("status {}", status) };
                println!("  {} {:35} status={} {}", "*".cyan(), name, status, status_str);

                if accessible {
                    if body.contains("cluster-admin") {
                        println!("    {} [HIGH] cluster-admin role found!", ">".red().bold());
                    }
                    if body.contains("wildcard") || body.contains("\"*\"") {
                        println!("    {} [HIGH] Wildcard permissions found!", ">".red().bold());
                    }
                    if body.contains("secrets") {
                        println!("    {} [WARN] Secret access granted", ">".yellow().bold());
                    }
                    if body.contains("pods/exec") {
                        println!("    {} [WARN] Pod exec granted", ">".yellow().bold());
                    }
                }
            }
            Err(_) => {
                println!("  {} {:35} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} RBAC analysis complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn secrets(
    api_server: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Kubernetes Secret Extraction", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} API Server: {}", "[*]".cyan().bold(), api_server);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let endpoints = [
        ("All secrets", "/api/v1/secrets"),
        ("Default namespace secrets", "/api/v1/namespaces/default/secrets"),
        ("Kube-system secrets", "/api/v1/namespaces/kube-system/secrets"),
        ("Service accounts", "/api/v1/serviceaccounts"),
        ("ConfigMaps", "/api/v1/configmaps"),
    ];

    for (name, path) in &endpoints {
        let url = format!("{}{}", api_server.trim_end_matches('/'), path);
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let status_str = if accessible { "EXPOSED".red().bold().to_string() }
                    else { format!("status {}", status) };
                println!("  {} {:35} status={} {}", "*".cyan(), name, status, status_str);

                if accessible {
                    let secret_count = body.matches("\"name\"").count();
                    println!("    {} Found {} items", "*".cyan(), secret_count);

                    if body.contains("token") {
                        println!("    {} [HIGH] Service account tokens found!", ">".red().bold());
                    }
                    if body.contains("dockerconfigjson") || body.contains(".dockerconfigjson") {
                        println!("    {} [HIGH] Docker registry credentials found!", ">".red().bold());
                    }
                    if body.contains("tls.crt") || body.contains("tls.key") {
                        println!("    {} [HIGH] TLS certificates found!", ">".red().bold());
                    }
                    if body.contains("password") || body.contains("apikey") || body.contains("api_key") {
                        println!("    {} [HIGH] Credentials found in secrets!", ">".red().bold());
                    }
                }
            }
            Err(_) => {
                println!("  {} {:35} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Secret extraction complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn escape(
    api_server: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Kubernetes Pod Escape Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} API Server: {}", "[*]".cyan().bold(), api_server);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    let checks = [
        ("Host PID access", "/api/v1/pods?fieldSelector=spec.hostPID=true"),
        ("Host network access", "/api/v1/pods?fieldSelector=spec.hostNetwork=true"),
        ("Privileged pods", "/api/v1/pods?fieldSelector=spec.containers.securityContext.privileged=true"),
        ("Host path mounts", "/api/v1/pods?fieldSelector=spec.volumes.hostPath.path=/"),
        ("Service account token", "/api/v1/namespaces/default/serviceaccounts/default"),
        ("Exec permissions", "/api/v1/namespaces/default/pods?fieldSelector=status.phase=Running"),
    ];

    for (name, path) in &checks {
        let url = format!("{}{}", api_server.trim_end_matches('/'), path);
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200;
                let status_str = if accessible { "FOUND".red().bold().to_string() }
                    else { format!("status {}", status) };
                println!("  {} {:30} status={} {}", "*".cyan(), name, status, status_str);

                if accessible {
                    if body.contains("hostPID") {
                        println!("    {} [HIGH] Pod with hostPID found — potential escape!", ">".red().bold());
                    }
                    if body.contains("hostNetwork") {
                        println!("    {} [HIGH] Pod with hostNetwork found — network escape!", ">".red().bold());
                    }
                    if body.contains("privileged") {
                        println!("    {} [HIGH] Privileged pod found — full host access!", ">".red().bold());
                    }
                    if body.contains("hostPath") {
                        println!("    {} [HIGH] Host path mount found — filesystem escape!", ">".red().bold());
                    }
                    if body.contains("token") {
                        println!("    {} [HIGH] Service account token accessible!", ">".red().bold());
                    }
                }
            }
            Err(_) => {
                println!("  {} {:30} error", "*".cyan(), name);
            }
        }
    }

    println!("\n{} Pod escape test complete.", "[*]".cyan().bold());
    Ok(())
}
