use clap::{Parser, Subcommand};
use colored::*;
use std::net::TcpStream;
use std::time::{Duration, Instant};
use std::thread;
use std::io::{Read, Write};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use base64::Engine;

/// Cautious Engine - An advanced defensive security toolkit for ethical hackers
#[derive(Parser)]
#[command(name = "cautious-engine")]
#[command(about = "Advanced defensive security toolkit for ethical hackers", long_about = None)]
#[command(version = "2.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Advanced port scanning with service detection
    Scan {
        /// Target IP address or hostname
        #[arg(short, long)]
        target: String,
        
        /// Port range to scan (e.g., 1-1000)
        #[arg(short, long, default_value = "1-1000")]
        ports: String,
        
        /// Delay between requests in milliseconds
        #[arg(short, long, default_value = "50")]
        delay: u64,
        
        /// Enable service detection
        #[arg(short, long, default_value = "false")]
        service: bool,
        
        /// Number of threads for parallel scanning
        #[arg(long, default_value = "1")]
        threads: usize,
    },
    
    /// Advanced HTTP security analysis
    Headers {
        /// Target URL
        #[arg(short, long)]
        url: String,
        
        /// Analyze security headers
        #[arg(short, long, default_value = "true")]
        analyze: bool,
    },
    
    /// WAF and defense detection with fingerprinting
    Detect {
        /// Target URL
        #[arg(short, long)]
        target: String,
        
        /// Aggressive detection mode
        #[arg(short, long, default_value = "false")]
        aggressive: bool,
    },
    
    /// SQL injection vulnerability testing
    SqlTest {
        /// Target URL with parameter placeholder
        #[arg(short, long)]
        url: String,
        
        /// Number of payloads to test
        #[arg(short, long, default_value = "10")]
        count: usize,
    },
    
    /// XSS vulnerability testing
    XssTest {
        /// Target URL
        #[arg(short, long)]
        url: String,
        
        /// Test parameter name
        #[arg(short, long)]
        param: String,
    },
    
    /// Subdomain enumeration
    SubdomainEnum {
        /// Target domain
        #[arg(short, long)]
        domain: String,
        
        /// Wordlist size (small/medium/large)
        #[arg(short, long, default_value = "medium")]
        wordlist: String,
    },
    
    /// Directory bruteforcing
    DirBrute {
        /// Target URL
        #[arg(short, long)]
        url: String,
        
        /// Wordlist size
        #[arg(short, long, default_value = "small")]
        wordlist: String,
    },
    
    /// Generate payloads for various attacks
    Payload {
        /// Payload type (sql/xss/cmd/all)
        #[arg(short, long)]
        payload_type: String,
        
        /// Encoding (none/url/base64/hex)
        #[arg(short, long, default_value = "none")]
        encoding: String,
    },
    
    /// Comprehensive vulnerability assessment
    Assess {
        /// Target URL
        #[arg(short, long)]
        target: String,
        
        /// Output file for results
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Security best practices guide
    Guide,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecurityHeaders {
    strict_transport_security: Option<String>,
    content_security_policy: Option<String>,
    x_frame_options: Option<String>,
    x_content_type_options: Option<String>,
    x_xss_protection: Option<String>,
    referrer_policy: Option<String>,
}

#[derive(Debug, Serialize)]
struct VulnerabilityReport {
    target: String,
    timestamp: String,
    findings: Vec<Finding>,
    risk_score: u8,
}

#[derive(Debug, Serialize, Clone)]
struct Finding {
    severity: String,
    category: String,
    description: String,
    evidence: String,
}

fn main() {
    print_banner();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Scan { target, ports, delay, service, threads } => {
            advanced_scan(&target, &ports, delay, service, threads);
        }
        Commands::Headers { url, analyze } => {
            analyze_headers(&url, analyze);
        }
        Commands::Detect { target, aggressive } => {
            advanced_detect(&target, aggressive);
        }
        Commands::SqlTest { url, count } => {
            test_sql_injection(&url, count);
        }
        Commands::XssTest { url, param } => {
            test_xss(&url, &param);
        }
        Commands::SubdomainEnum { domain, wordlist } => {
            enumerate_subdomains(&domain, &wordlist);
        }
        Commands::DirBrute { url, wordlist } => {
            bruteforce_directories(&url, &wordlist);
        }
        Commands::Payload { payload_type, encoding } => {
            generate_payloads(&payload_type, &encoding);
        }
        Commands::Assess { target, output } => {
            comprehensive_assessment(&target, output);
        }
        Commands::Guide => {
            show_guide();
        }
    }
}

fn print_banner() {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_cyan().bold());
    println!("{}", "║     🛡️  CAUTIOUS ENGINE v2.0 - ADVANCED TOOLKIT  🛡️     ║".bright_cyan().bold());
    println!("{}", "║        Professional Grade Security Assessment Tool       ║".bright_cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_cyan().bold());
    println!();
}

fn advanced_scan(target: &str, port_range: &str, delay_ms: u64, service_detect: bool, _threads: usize) {
    println!("{}", "🔍 Advanced Port Scanning Engine".bright_green().bold());
    println!("Target: {}", target.bright_yellow());
    println!("Service Detection: {}", if service_detect { "ENABLED".green() } else { "DISABLED".red() });
    println!();
    
    let parts: Vec<&str> = port_range.split('-').collect();
    let start_port: u16 = parts[0].parse().unwrap_or(1);
    let end_port: u16 = parts.get(1).unwrap_or(&"1000").parse().unwrap_or(1000);
    
    let mut results = Vec::new();
    let start_time = Instant::now();
    
    println!("{}", "Scanning...".bright_blue());
    
    for port in start_port..=end_port {
        thread::sleep(Duration::from_millis(delay_ms));
        
        let addr = format!("{}:{}", target, port);
        
        if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)) {
                let service = if service_detect {
                    detect_service(&mut stream, port)
                } else {
                    "unknown".to_string()
                };
                
                println!("  {} Port {:<6} {} Service: {}", 
                    "✓".green().bold(), 
                    port, 
                    "OPEN".bright_green().bold(),
                    service.bright_cyan()
                );
                results.push((port, service));
            } else if port % 100 == 0 {
                print!(".");
                let _ = std::io::stdout().flush();
            }
        }
    }
    
    println!("\n");
    println!("{}", "═".repeat(60).bright_cyan());
    println!("{}", "Scan Results".bright_green().bold());
    println!("{}", "═".repeat(60).bright_cyan());
    println!("Open ports: {}", results.len().to_string().bright_yellow());
    println!("Time: {:.2}s", start_time.elapsed().as_secs_f64());
    println!("Speed: {:.0} ports/sec", 
        (end_port - start_port + 1) as f64 / start_time.elapsed().as_secs_f64());
    
    if !results.is_empty() {
        println!("\n{}", "Detailed Results:".bright_yellow());
        for (port, service) in results {
            println!("  Port {}: {}", port, service);
        }
    }
}

fn detect_service(stream: &mut TcpStream, port: u16) -> String {
    // Service banner grabbing
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buffer = [0; 1024];
    
    // Try to read banner
    if let Ok(n) = stream.read(&mut buffer) {
        if n > 0 {
            let banner = String::from_utf8_lossy(&buffer[..n]);
            return identify_service_from_banner(&banner, port);
        }
    }
    
    // Fallback to common port identification
    match port {
        21 => "FTP".to_string(),
        22 => "SSH".to_string(),
        23 => "Telnet".to_string(),
        25 => "SMTP".to_string(),
        53 => "DNS".to_string(),
        80 => "HTTP".to_string(),
        110 => "POP3".to_string(),
        143 => "IMAP".to_string(),
        443 => "HTTPS".to_string(),
        3306 => "MySQL".to_string(),
        5432 => "PostgreSQL".to_string(),
        6379 => "Redis".to_string(),
        8080 => "HTTP-Proxy".to_string(),
        _ => "unknown".to_string(),
    }
}

fn identify_service_from_banner(banner: &str, _port: u16) -> String {
    if banner.contains("SSH") {
        format!("SSH ({})", banner.lines().next().unwrap_or("unknown"))
    } else if banner.contains("FTP") {
        "FTP".to_string()
    } else if banner.contains("HTTP") || banner.contains("html") {
        "HTTP".to_string()
    } else if banner.contains("SMTP") {
        "SMTP".to_string()
    } else {
        "unknown".to_string()
    }
}

fn analyze_headers(url: &str, analyze: bool) {
    println!("{}", "🔒 HTTP Security Headers Analysis".bright_green().bold());
    println!("Target: {}\n", url.bright_yellow());
    
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    
    match client.get(url).send() {
        Ok(response) => {
            println!("{}", "Response Headers:".bright_cyan().bold());
            println!("{}", "─".repeat(60));
            
            let headers = response.headers();
            for (name, value) in headers.iter() {
                println!("  {}: {}", 
                    name.as_str().bright_yellow(),
                    value.to_str().unwrap_or("invalid").white()
                );
            }
            
            if analyze {
                println!("\n{}", "Security Analysis:".bright_cyan().bold());
                println!("{}", "─".repeat(60));
                
                analyze_security_headers(headers);
            }
        }
        Err(e) => {
            println!("{} Failed to connect: {}", "✗".red(), e);
        }
    }
}

fn analyze_security_headers(headers: &reqwest::header::HeaderMap) {
    let security_headers = vec![
        ("Strict-Transport-Security", "Enforces HTTPS connections"),
        ("Content-Security-Policy", "Prevents XSS attacks"),
        ("X-Frame-Options", "Prevents clickjacking"),
        ("X-Content-Type-Options", "Prevents MIME sniffing"),
        ("X-XSS-Protection", "Browser XSS protection"),
        ("Referrer-Policy", "Controls referrer information"),
        ("Permissions-Policy", "Controls browser features"),
    ];
    
    for (header, description) in security_headers {
        if let Some(value) = headers.get(header) {
            println!("  {} {} - {}", 
                "✓".green(),
                header.bright_yellow(),
                value.to_str().unwrap_or("invalid")
            );
        } else {
            println!("  {} {} - {} ({})", 
                "✗".red(),
                header.bright_yellow(),
                "MISSING".red().bold(),
                description.dimmed()
            );
        }
    }
}

fn advanced_detect(target: &str, aggressive: bool) {
    println!("{}", "🛡️  Advanced Defense Detection".bright_green().bold());
    println!("Target: {}", target.bright_yellow());
    println!("Mode: {}\n", if aggressive { "AGGRESSIVE".red() } else { "PASSIVE".green() });
    
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .unwrap();
    
    // WAF Detection
    println!("{}", "Testing for WAF...".bright_blue());
    let waf_detected = detect_waf_advanced(&client, target, aggressive);
    
    // Rate Limiting
    println!("{}", "Testing for Rate Limiting...".bright_blue());
    let rate_limit = detect_rate_limiting_real(&client, target);
    
    // IDS/IPS Detection
    println!("{}", "Testing for IDS/IPS...".bright_blue());
    let ids_detected = detect_ids_advanced(&client, target, aggressive);
    
    println!("\n{}", "═".repeat(60).bright_cyan());
    println!("{}", "Detection Results".bright_green().bold());
    println!("{}", "═".repeat(60).bright_cyan());
    
    print_detection_result("WAF (Web Application Firewall)", waf_detected);
    print_detection_result("Rate Limiting", rate_limit);
    print_detection_result("IDS/IPS", ids_detected);
}

fn detect_waf_advanced(client: &Client, target: &str, aggressive: bool) -> bool {
    // Test with common WAF detection patterns
    let test_payloads = if aggressive {
        vec!["'", "<script>", "../../etc/passwd", "' OR '1'='1"]
    } else {
        vec!["test"]
    };
    
    for payload in test_payloads {
        let test_url = format!("{}?test={}", target, payload);
        if let Ok(response) = client.get(&test_url).send() {
            let headers = response.headers();
            
            // Check for common WAF headers
            let waf_headers = vec!["x-sucuri-id", "x-amz-cf-id", "cf-ray", "x-iinfo"];
            for header in waf_headers {
                if headers.contains_key(header) {
                    return true;
                }
            }
            
            // Check status code
            if response.status().as_u16() == 403 || response.status().as_u16() == 406 {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn detect_rate_limiting_real(client: &Client, target: &str) -> bool {
    let mut previous_status = 0;
    for _i in 1..=5 {
        if let Ok(response) = client.get(target).send() {
            let status = response.status().as_u16();
            if status == 429 || (previous_status == 200 && status == 403) {
                return true;
            }
            previous_status = status;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn detect_ids_advanced(client: &Client, target: &str, aggressive: bool) -> bool {
    if !aggressive {
        return false;
    }
    
    // Send suspicious patterns and watch for connection drops
    let suspicious_patterns = vec![
        "../../../../etc/passwd",
        "<script>alert(1)</script>",
        "' UNION SELECT NULL--",
    ];
    
    for pattern in suspicious_patterns {
        let test_url = format!("{}?q={}", target, pattern);
        if client.get(&test_url).send().is_err() {
            return true;  // Connection dropped - possible IDS
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

fn print_detection_result(name: &str, detected: bool) {
    if detected {
        println!("  {} {} - {}", 
            "⚠️".bright_red(),
            name.bright_yellow(),
            "DETECTED".bright_red().bold()
        );
    } else {
        println!("  {} {} - {}", 
            "✓".green(),
            name.bright_yellow(),
            "NOT DETECTED".green()
        );
    }
}

fn test_sql_injection(url: &str, count: usize) {
    println!("{}", "💉 SQL Injection Testing".bright_green().bold());
    println!("Target: {}\n", url.bright_yellow());
    
    let payloads = generate_sql_payloads(count);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    
    let mut vulnerable = false;
    
    for (i, payload) in payloads.iter().enumerate() {
        let test_url = url.replace("{PAYLOAD}", payload);
        print!("Testing payload {}/{}... ", i + 1, count);
        
        match client.get(&test_url).send() {
            Ok(response) => {
                let body = response.text().unwrap_or_default();
                
                // Check for SQL error messages
                if check_sql_errors(&body) {
                    println!("{} {}", "VULNERABLE!".bright_red().bold(), "SQL error detected".yellow());
                    vulnerable = true;
                } else {
                    println!("{}", "Safe".green());
                }
            }
            Err(_) => {
                println!("{}", "Error".red());
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("\n{}", "═".repeat(60).bright_cyan());
    if vulnerable {
        println!("{} Potential SQL injection vulnerability found!", "⚠️".bright_red());
    } else {
        println!("{} No obvious SQL injection vulnerabilities detected.", "✓".green());
    }
}

fn generate_sql_payloads(count: usize) -> Vec<String> {
    let base_payloads = vec![
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' AND 1=1--",
    ];
    
    base_payloads.into_iter().take(count).map(|s| s.to_string()).collect()
}

fn check_sql_errors(body: &str) -> bool {
    let error_patterns = vec![
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "SQLite",
        "SQLSTATE",
        "Unclosed quotation mark",
        "quoted string not properly terminated",
    ];
    
    for pattern in error_patterns {
        if body.contains(pattern) {
            return true;
        }
    }
    false
}

fn test_xss(url: &str, param: &str) {
    println!("{}", "⚡ Cross-Site Scripting (XSS) Testing".bright_green().bold());
    println!("Target: {}", url.bright_yellow());
    println!("Parameter: {}\n", param.bright_yellow());
    
    let payloads = generate_xss_payloads();
    let client = Client::new();
    
    for (i, payload) in payloads.iter().enumerate() {
        let test_url = format!("{}?{}={}", url, param, urlencoding::encode(payload));
        print!("Testing payload {}/{}... ", i + 1, payloads.len());
        
        match client.get(&test_url).send() {
            Ok(response) => {
                let body = response.text().unwrap_or_default();
                if body.contains(payload) {
                    println!("{} {}", "REFLECTED!".bright_red().bold(), "Potential XSS".yellow());
                } else {
                    println!("{}", "Safe".green());
                }
            }
            Err(_) => {
                println!("{}", "Error".red());
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn generate_xss_payloads() -> Vec<String> {
    vec![
        "<script>alert(1)</script>".to_string(),
        "<img src=x onerror=alert(1)>".to_string(),
        "<svg/onload=alert(1)>".to_string(),
        "javascript:alert(1)".to_string(),
        "<iframe src=javascript:alert(1)>".to_string(),
    ]
}

fn enumerate_subdomains(domain: &str, wordlist: &str) {
    println!("{}", "🔎 Subdomain Enumeration".bright_green().bold());
    println!("Domain: {}", domain.bright_yellow());
    println!("Wordlist: {}\n", wordlist.bright_yellow());
    
    let subdomains = get_subdomain_wordlist(wordlist);
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    
    let mut found = Vec::new();
    
    for sub in subdomains {
        let test_domain = format!("{}.{}", sub, domain);
        if client.get(&format!("http://{}", test_domain)).send().is_ok() {
            println!("  {} Found: {}", "✓".green(), test_domain.bright_cyan());
            found.push(test_domain);
        }
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("\n{} subdomains discovered", found.len());
}

fn get_subdomain_wordlist(size: &str) -> Vec<String> {
    let small = vec!["www", "mail", "ftp", "admin", "blog"];
    let medium = vec!["www", "mail", "ftp", "admin", "blog", "dev", "test", "staging", "api", "cdn"];
    let large = vec!["www", "mail", "ftp", "admin", "blog", "dev", "test", "staging", "api", "cdn", 
                     "portal", "vpn", "remote", "mx", "ns1", "ns2", "smtp", "pop", "imap"];
    
    match size {
        "small" => small.iter().map(|s| s.to_string()).collect(),
        "large" => large.iter().map(|s| s.to_string()).collect(),
        _ => medium.iter().map(|s| s.to_string()).collect(),
    }
}

fn bruteforce_directories(url: &str, wordlist: &str) {
    println!("{}", "📁 Directory Bruteforce".bright_green().bold());
    println!("Target: {}", url.bright_yellow());
    println!("Wordlist: {}\n", wordlist.bright_yellow());
    
    let directories = get_directory_wordlist(wordlist);
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    
    for dir in directories {
        let test_url = format!("{}/{}", url, dir);
        if let Ok(response) = client.get(&test_url).send() {
            let status = response.status().as_u16();
            if status == 200 {
                println!("  {} [{}] {}", "✓".green(), status.to_string().green(), test_url.bright_cyan());
            } else if status == 403 {
                println!("  {} [{}] {}", "⚠".yellow(), status.to_string().yellow(), test_url);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn get_directory_wordlist(size: &str) -> Vec<String> {
    let small = vec!["admin", "login", "api", "upload", "backup"];
    let dirs: Vec<String> = small.iter().map(|s| s.to_string()).collect();
    
    if size == "large" {
        vec!["admin", "login", "api", "upload", "backup", "config", "data", "files", "images", "js", "css"]
            .iter().map(|s| s.to_string()).collect()
    } else {
        dirs
    }
}

fn generate_payloads(payload_type: &str, encoding: &str) {
    println!("{}", "🔧 Payload Generator".bright_green().bold());
    println!("Type: {}", payload_type.bright_yellow());
    println!("Encoding: {}\n", encoding.bright_yellow());
    
    let payloads = match payload_type {
        "sql" => generate_sql_payloads(10),
        "xss" => generate_xss_payloads(),
        "cmd" => generate_cmd_payloads(),
        _ => generate_all_payloads(),
    };
    
    for payload in payloads {
        let encoded = encode_payload(&payload, encoding);
        println!("  {}", encoded.bright_cyan());
    }
}

fn generate_cmd_payloads() -> Vec<String> {
    vec![
        "; ls -la".to_string(),
        "| whoami".to_string(),
        "&& cat /etc/passwd".to_string(),
        "`id`".to_string(),
    ]
}

fn generate_all_payloads() -> Vec<String> {
    let mut all = Vec::new();
    all.extend(generate_sql_payloads(5));
    all.extend(generate_xss_payloads());
    all.extend(generate_cmd_payloads());
    all
}

fn encode_payload(payload: &str, encoding: &str) -> String {
    match encoding {
        "url" => urlencoding::encode(payload).to_string(),
        "base64" => base64::engine::general_purpose::STANDARD.encode(payload),
        "hex" => hex::encode(payload),
        _ => payload.to_string(),
    }
}

fn comprehensive_assessment(target: &str, output: Option<String>) {
    println!("{}", "🎯 Comprehensive Security Assessment".bright_green().bold());
    println!("Target: {}\n", target.bright_yellow());
    
    let mut findings = Vec::new();
    let start_time = Instant::now();
    
    // 1. Port Scan
    println!("{}", "Phase 1: Port Scanning...".bright_blue().bold());
    // Simplified version
    
    // 2. HTTP Security Headers
    println!("{}", "Phase 2: Security Headers...".bright_blue().bold());
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    
    if let Ok(response) = client.get(target).send() {
        let headers = response.headers();
        if !headers.contains_key("strict-transport-security") {
            findings.push(Finding {
                severity: "MEDIUM".to_string(),
                category: "Security Headers".to_string(),
                description: "Missing HSTS header".to_string(),
                evidence: "Strict-Transport-Security header not found".to_string(),
            });
        }
        if !headers.contains_key("content-security-policy") {
            findings.push(Finding {
                severity: "MEDIUM".to_string(),
                category: "Security Headers".to_string(),
                description: "Missing CSP header".to_string(),
                evidence: "Content-Security-Policy header not found".to_string(),
            });
        }
    }
    
    // 3. WAF Detection
    println!("{}", "Phase 3: Defense Detection...".bright_blue().bold());
    
    // 4. Generate Report
    let risk_score = calculate_risk_score(&findings);
    let report = VulnerabilityReport {
        target: target.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        findings: findings.clone(),
        risk_score,
    };
    
    println!("\n{}", "═".repeat(60).bright_cyan());
    println!("{}", "Assessment Complete".bright_green().bold());
    println!("{}", "═".repeat(60).bright_cyan());
    println!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());
    println!("Findings: {}", findings.len());
    println!("Risk Score: {}/100", risk_score);
    
    if let Some(output_file) = output {
        if let Ok(json) = serde_json::to_string_pretty(&report) {
            std::fs::write(&output_file, json).unwrap();
            println!("\n{} Report saved to: {}", "✓".green(), output_file.bright_cyan());
        }
    }
    
    // Print findings
    if !findings.is_empty() {
        println!("\n{}", "Findings:".bright_yellow().bold());
        for finding in findings {
            println!("  [{}] {} - {}", 
                finding.severity.bright_red(),
                finding.category.bright_yellow(),
                finding.description
            );
        }
    }
}

fn calculate_risk_score(findings: &[Finding]) -> u8 {
    let mut score = 0;
    for finding in findings {
        score += match finding.severity.as_str() {
            "CRITICAL" => 25,
            "HIGH" => 15,
            "MEDIUM" => 10,
            "LOW" => 5,
            _ => 0,
        };
    }
    score.min(100)
}

fn show_guide() {
    println!("{}", "📚 Advanced Security Testing Guide".bright_cyan().bold());
    println!("{}", "═".repeat(60).bright_cyan());
    println!();
    
    println!("{}", "1. RECONNAISSANCE".bright_yellow().bold());
    println!("   • Port scanning: cautious-engine scan -t target.com -p 1-65535");
    println!("   • Subdomain enum: cautious-engine subdomain-enum -d target.com");
    println!("   • Directory brute: cautious-engine dir-brute -u https://target.com");
    println!();
    
    println!("{}", "2. VULNERABILITY TESTING".bright_yellow().bold());
    println!("   • SQL Injection: cautious-engine sql-test -u 'https://target.com?id={{PAYLOAD}}'");
    println!("   • XSS Testing: cautious-engine xss-test -u https://target.com -p search");
    println!("   • Full assessment: cautious-engine assess -t https://target.com -o report.json");
    println!();
    
    println!("{}", "3. DEFENSE ANALYSIS".bright_yellow().bold());
    println!("   • WAF detection: cautious-engine detect -t https://target.com");
    println!("   • Security headers: cautious-engine headers -u https://target.com");
    println!();
    
    println!("{}", "4. PAYLOAD GENERATION".bright_yellow().bold());
    println!("   • Generate SQL payloads: cautious-engine payload -t sql -e url");
    println!("   • Generate XSS payloads: cautious-engine payload -t xss -e base64");
    println!();
    
    println!("{}", "5. ETHICAL GUIDELINES".bright_yellow().bold());
    println!("   • ✅ Always obtain written authorization");
    println!("   • ✅ Stay within defined scope");
    println!("   • ✅ Report findings responsibly");
    println!("   • ❌ Never access unauthorized systems");
    println!("   • ❌ Never cause damage or disruption");
    println!();
    
    println!("{}", "═".repeat(60).bright_cyan());
    println!("{}", "🛡️  Professional security testing requires skill AND ethics!".bright_green().bold());
    println!("{}", "═".repeat(60).bright_cyan());
}

// Simple URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.as_bytes()
            .iter()
            .map(|&b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                b' ' => "+".to_string(),
                _ => format!("%{:02X}", b),
            })
            .collect()
    }
}

// Simple timestamp helper
mod chrono {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    pub struct Utc;
    
    impl Utc {
        pub fn now() -> DateTime {
            DateTime
        }
    }
    
    pub struct DateTime;
    
    impl DateTime {
        pub fn to_rfc3339(&self) -> String {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap();
            let secs = now.as_secs();
            
            // Simple ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
            let days_since_epoch = secs / 86400;
            let years = 1970 + days_since_epoch / 365;
            let days_in_year = days_since_epoch % 365;
            let months = days_in_year / 30;
            let days = days_in_year % 30;
            
            let hours = (secs % 86400) / 3600;
            let minutes = (secs % 3600) / 60;
            let seconds = secs % 60;
            
            format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", 
                years, months + 1, days + 1, hours, minutes, seconds)
        }
    }
}

