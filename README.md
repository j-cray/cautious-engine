# 🛡️ cautious-engine v2.0

An **advanced defensive security toolkit** for ethical hackers and penetration testers. Built in Rust for maximum performance, safety, and reliability.

![Security](https://img.shields.io/badge/Security-Advanced%20Toolkit-red?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Rust-orange?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🎯 What is cautious-engine?

**Cautious Engine v2.0** is a professional-grade defensive security toolkit with real, working implementations of advanced penetration testing capabilities. Unlike basic scanning tools, it provides comprehensive vulnerability assessment, payload generation, and defensive mechanism detection.

### 🌟 Advanced Features

#### 🔍 **Port Scanning & Service Detection**
- Advanced port scanning with banner grabbing
- Automatic service identification
- Multi-threaded scanning support
- Configurable delay for stealth

#### 🛡️ **Defense Detection & Analysis**
- **Real WAF detection** using signature analysis
- IDS/IPS detection with aggressive mode
- Rate limiting identification
- HTTP security headers analysis
- Comprehensive defense fingerprinting

#### 💉 **Vulnerability Testing**
- **SQL Injection testing** with real payloads
- **XSS vulnerability scanning** with reflection detection
- Directory bruteforcing
- Subdomain enumeration
- Comprehensive vulnerability assessment

#### 🔧 **Payload Generation**
- SQL injection payloads
- XSS attack vectors
- Command injection payloads
- Multiple encoding options (URL, Base64, Hex)

#### 📊 **Assessment & Reporting**
- Comprehensive security assessments
- JSON export for results
- Risk scoring system
- Detailed vulnerability findings

## 🚀 Installation

### Prerequisites
- Rust 1.70 or higher
- Cargo (comes with Rust)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/j-cray/cautious-engine
cd cautious-engine

# Build the project (release mode for performance)
cargo build --release

# Run the tool
./target/release/cautious-engine --help
```

## 📖 Usage

### 🔍 Advanced Port Scanning

Scan ports with service detection:

```bash
# Scan common ports with service detection
cargo run -- scan -t scanme.nmap.org -p 1-1000 -s true

# Fast scan with minimal delay
cargo run -- scan -t 192.168.1.1 -p 80-443 -d 10

# Comprehensive scan
cargo run -- scan -t target.com -p 1-65535 -d 50 --service
```

**Features:**
- Banner grabbing for service identification
- Automatic protocol detection
- Progress indicators
- Speed metrics

### 🛡️ WAF & Defense Detection

Detect security mechanisms before testing:

```bash
# Passive detection
cargo run -- detect -t https://example.com

# Aggressive detection (sends test payloads)
cargo run -- detect -t https://example.com --aggressive
```

**Detects:**
- Web Application Firewalls (Cloudflare, AWS WAF, Sucuri, etc.)
- Intrusion Detection/Prevention Systems
- Rate limiting mechanisms
- CAPTCHA protection

### 🔒 Security Headers Analysis

Analyze HTTP security posture:

```bash
cargo run -- headers -u https://example.com --analyze
```

**Analyzes:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

### 💉 SQL Injection Testing

Test for SQL injection vulnerabilities:

```bash
# Replace {PAYLOAD} with injection point
cargo run -- sql-test -u 'https://target.com/page?id={PAYLOAD}' --count 10
```

**Features:**
- 10+ SQL injection payloads
- Error-based detection
- Automatic vulnerability identification

### ⚡ XSS Vulnerability Testing

Test for cross-site scripting:

```bash
cargo run -- xss-test -u https://target.com/search -p query
```

**Features:**
- Multiple XSS payloads
- Reflection detection
- Various attack vectors

### 🔎 Subdomain Enumeration

Discover subdomains:

```bash
# Small wordlist
cargo run -- subdomain-enum -d example.com --wordlist small

# Large wordlist
cargo run -- subdomain-enum -d example.com --wordlist large
```

### 📁 Directory Bruteforcing

Find hidden directories:

```bash
cargo run -- dir-brute -u https://example.com --wordlist medium
```

### 🔧 Payload Generation

Generate attack payloads with encoding:

```bash
# SQL payloads with URL encoding
cargo run -- payload --payload-type sql --encoding url

# XSS payloads with Base64 encoding
cargo run -- payload --payload-type xss --encoding base64

# All payloads
cargo run -- payload --payload-type all --encoding none
```

### 🎯 Comprehensive Assessment

Run full security assessment:

```bash
cargo run -- assess -t https://target.com -o assessment-report.json
```

**Generates:**
- Vulnerability report
- Risk scoring (0-100)
- JSON export
- Categorized findings

## 🎬 Example Sessions

### Port Scanning with Service Detection

```bash
$ cargo run -- scan -t scanme.nmap.org -p 20-100 -s true

╔══════════════════════════════════════════════════════════╗
║     🛡️  CAUTIOUS ENGINE v2.0 - ADVANCED TOOLKIT  🛡️     ║
║        Professional Grade Security Assessment Tool       ║
╚══════════════════════════════════════════════════════════╝

🔍 Advanced Port Scanning Engine
Target: scanme.nmap.org
Service Detection: ENABLED

Scanning...
  ✓ Port 22     OPEN Service: SSH
  ✓ Port 80     OPEN Service: HTTP
..........

════════════════════════════════════════════════════════════
Scan Results
════════════════════════════════════════════════════════════
Open ports: 2
Time: 4.23s
Speed: 19 ports/sec

Detailed Results:
  Port 22: SSH
  Port 80: HTTP
```

### WAF Detection

```bash
$ cargo run -- detect -t https://example.com --aggressive

╔══════════════════════════════════════════════════════════╗
║     🛡️  CAUTIOUS ENGINE v2.0 - ADVANCED TOOLKIT  🛡️     ║
║        Professional Grade Security Assessment Tool       ║
╚══════════════════════════════════════════════════════════╝

🛡️  Advanced Defense Detection
Target: https://example.com
Mode: AGGRESSIVE

Testing for WAF...
Testing for Rate Limiting...
Testing for IDS/IPS...

════════════════════════════════════════════════════════════
Detection Results
════════════════════════════════════════════════════════════
  ⚠️  WAF (Web Application Firewall) - DETECTED
  ✓  Rate Limiting - NOT DETECTED
  ⚠️  IDS/IPS - DETECTED
```

### Payload Generation

```bash
$ cargo run -- payload --payload-type sql --encoding url

╔══════════════════════════════════════════════════════════╗
║     🛡️  CAUTIOUS ENGINE v2.0 - ADVANCED TOOLKIT  🛡️     ║
║        Professional Grade Security Assessment Tool       ║
╚══════════════════════════════════════════════════════════╝

🔧 Payload Generator
Type: sql
Encoding: url

  %27+OR+%271%27%3D%271
  %27+OR+%271%27%3D%271+--
  %27+OR+%271%27%3D%271+/*
  admin%27+--
  admin%27+%23
  %27+UNION+SELECT+NULL--
  ...
```

## 🛠️ Command Reference

### All Commands

```bash
cargo run -- <COMMAND> [OPTIONS]
```

**Available Commands:**

| Command | Description |
|---------|-------------|
| `scan` | Advanced port scanning with service detection |
| `headers` | HTTP security headers analysis |
| `detect` | WAF and defense detection with fingerprinting |
| `sql-test` | SQL injection vulnerability testing |
| `xss-test` | XSS vulnerability testing |
| `subdomain-enum` | Subdomain enumeration |
| `dir-brute` | Directory bruteforcing |
| `payload` | Generate payloads with encoding |
| `assess` | Comprehensive vulnerability assessment |
| `guide` | Security best practices guide |

### Scan Options

```bash
-t, --target <TARGET>        Target IP or hostname
-p, --ports <PORTS>          Port range [default: 1-1000]
-d, --delay <DELAY>          Delay in ms [default: 50]
-s, --service <SERVICE>      Enable service detection [default: false]
    --threads <THREADS>      Number of threads [default: 1]
```

### Detect Options

```bash
-t, --target <TARGET>            Target URL
-a, --aggressive <AGGRESSIVE>    Aggressive mode [default: false]
```

### Payload Options

```bash
--payload-type <TYPE>      Payload type (sql/xss/cmd/all)
--encoding <ENCODING>      Encoding (none/url/base64/hex) [default: none]
```

## 🔒 Security & Ethics

### ⚠️ Legal Notice

**CRITICAL:** This is a powerful offensive security tool. Misuse can be illegal.

- ✅ **ALWAYS** obtain written authorization
- ✅ **ALWAYS** stay within defined scope
- ✅ **ALWAYS** follow responsible disclosure
- ❌ **NEVER** use on unauthorized systems
- ❌ **NEVER** cause damage or disruption
- ❌ **NEVER** access unauthorized data

### Responsible Use

This tool is designed for:
- Authorized penetration testing
- Security research
- Vulnerability assessment
- Educational purposes (in controlled environments)

### Compliance

Users must comply with:
- Computer Fraud and Abuse Act (CFAA)
- Local and international laws
- Organizational policies
- Rules of engagement

## 🏗️ Architecture

### Technology Stack

- **Language**: Rust 2021 edition
- **HTTP Client**: reqwest (blocking)
- **CLI**: clap 4.5
- **Serialization**: serde + serde_json
- **Encoding**: base64, hex
- **Hashing**: sha2
- **Terminal**: colored

### Project Structure

```
cautious-engine/
├── src/
│   └── main.rs              # 900+ lines of advanced functionality
├── tests/
│   └── integration_test.rs  # Integration tests
├── Cargo.toml               # Dependencies
├── README.md                # This file
└── .gitignore              # Rust ignore patterns
```

## 🧪 Testing

Run the test suite:

```bash
cargo test
```

Test individual commands:

```bash
# Test payload generation
cargo run -- payload --payload-type sql --encoding none

# Test guide
cargo run -- guide

# Test version
cargo run -- --version
```

## 🚧 Advanced Features

### Real Implementations

Unlike basic tools, Cautious Engine v2.0 includes:

- ✅ **Real HTTP requests** using reqwest
- ✅ **Actual banner grabbing** for service detection
- ✅ **Working WAF detection** with signature analysis
- ✅ **Live SQL injection testing** with error detection
- ✅ **XSS reflection checking**
- ✅ **Rate limit detection** with multiple probes
- ✅ **JSON report generation** with serde
- ✅ **Multiple encoding schemes** (URL, Base64, Hex)

### Performance

- Written in Rust for maximum speed
- Efficient network operations
- Minimal memory footprint
- Parallel scanning support

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

This is a professional-grade tool built for the security community. It combines:

- Offensive security capabilities
- Defensive awareness
- Ethical guidelines
- Professional-grade code quality

---

**Remember: Advanced tools require advanced responsibility. Use cautiously, test ethically, hack responsibly.** 🛡️

*For authorized security testing and research purposes only.*

**Version 2.0 - Now with REAL functionality, not simulations!**
