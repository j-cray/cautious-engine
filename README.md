# 🛡️ cautious-engine

A **defensive security toolkit** for ethical hackers and penetration testers. Built in Rust for performance, safety, and reliability.

![Security](https://img.shields.io/badge/Security-Defensive%20Toolkit-red?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Rust-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🎯 What is cautious-engine?

**Cautious Engine** is a defensive security toolkit designed to help ethical hackers and penetration testers operate *cautiously* and responsibly. It provides rate-limiting, stealth capabilities, and defensive mechanism detection to avoid triggering security systems and to conduct security assessments professionally.

### 🌟 Key Features

- **🐌 Rate-Limited Scanning** - Avoid detection by spacing out requests
- **🛡️ Defense Detection** - Identify WAF, IDS/IPS, and other defensive mechanisms
- **⏱️ Timing Controls** - Configurable delays to mimic legitimate traffic
- **📊 Request Analysis** - Monitor success rates and blocking patterns
- **🎓 Security Guidance** - Built-in best practices and responsible disclosure guidelines
- **⚡ Rust Performance** - Fast, safe, and memory-efficient
- **🎨 Beautiful CLI** - Colored output for clear visibility

## 🚀 Installation

### Prerequisites
- Rust 1.70 or higher
- Cargo (comes with Rust)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/j-cray/cautious-engine
cd cautious-engine

# Build the project
cargo build --release

# Run the tool
cargo run --release -- --help
```

## 📖 Usage

### Port Scanning (Cautious Mode)

Scan ports with rate limiting to avoid triggering IDS/IPS:

```bash
# Scan ports 1-100 with 100ms delay
cargo run -- scan --target 192.168.1.1 --ports 1-100 --delay 100

# Scan common ports with 500ms delay (more stealthy)
cargo run -- scan -t example.com -p 1-1000 -d 500
```

**Key Features:**
- Configurable delay between port probes
- Progress indicators
- Timeout handling
- Open port detection

### Defense Detection

Detect defensive mechanisms before launching an assessment:

```bash
# Check for WAF, IDS/IPS, rate limiting, etc.
cargo run -- detect --target https://example.com
```

**Checks for:**
- Web Application Firewalls (WAF)
- Intrusion Detection/Prevention Systems (IDS/IPS)
- Rate limiting mechanisms
- Honeypot indicators
- CAPTCHA protection

### Rate Limit Testing

Test how a target responds to repeated requests:

```bash
# Send 10 requests with 1 second delay
cargo run -- rate-test --url https://api.example.com/endpoint --count 10 --delay 1000

# Aggressive test (use with caution!)
cargo run -- rate-test -u https://example.com -c 50 -d 100
```

**Monitors:**
- Success/failure rates
- Blocking patterns
- Response time variations
- Rate limit thresholds

### Security Best Practices Guide

Display built-in security guidance:

```bash
cargo run -- guide
```

**Covers:**
- Authorization requirements
- Rate limiting strategies
- Stealth techniques
- Defensive awareness
- Responsible disclosure

## 🎬 Example Session

```bash
$ cargo run -- scan -t scanme.nmap.org -p 1-100 -d 100

╔══════════════════════════════════════════════════════════╗
║        🛡️  CAUTIOUS ENGINE - DEFENSIVE TOOLKIT  🛡️       ║
║          For Ethical Hackers & Pen Testers              ║
╚══════════════════════════════════════════════════════════╝

🔍 Starting Cautious Port Scan...
Target: scanme.nmap.org
Delay: 100ms (stealth mode)

  ✓ Port 22 is OPEN
  ✓ Port 80 is OPEN
..........

════════════════════════════════════════════════════════════
Scan Complete
════════════════════════════════════════════════════════════
Open ports found: 2
Time elapsed: 10.45s

Open ports: [22, 80]

⚠️  Remember: Always get proper authorization before scanning!
```

## 🛠️ Command Reference

### Scan Command
```bash
cargo run -- scan [OPTIONS]

OPTIONS:
  -t, --target <TARGET>    Target IP address or hostname
  -p, --ports <PORTS>      Port range to scan [default: 1-100]
  -d, --delay <DELAY>      Delay between requests in ms [default: 100]
```

### Detect Command
```bash
cargo run -- detect [OPTIONS]

OPTIONS:
  -t, --target <TARGET>    Target URL or IP
```

### Rate Test Command
```bash
cargo run -- rate-test [OPTIONS]

OPTIONS:
  -u, --url <URL>          Target URL
  -c, --count <COUNT>      Number of requests [default: 10]
  -d, --delay <DELAY>      Delay between requests in ms [default: 1000]
```

### Guide Command
```bash
cargo run -- guide
```

## 🔒 Security & Ethics

### ⚠️ Legal Notice

**IMPORTANT:** This tool is for **authorized security testing only**.

- ✅ **DO**: Obtain written permission before testing
- ✅ **DO**: Define clear scope with stakeholders  
- ✅ **DO**: Follow responsible disclosure practices
- ❌ **DON'T**: Use on systems without authorization
- ❌ **DON'T**: Cause damage or disruption
- ❌ **DON'T**: Access data you're not authorized to see

### Responsible Use

The Cautious Engine is designed to help security professionals:

1. **Avoid Detection** - Use delays and rate limiting
2. **Minimize Impact** - Reduce load on target systems
3. **Detect Defenses** - Identify security mechanisms before testing
4. **Follow Best Practices** - Built-in guidance for ethical hacking

### Compliance

Users are responsible for:
- Obtaining proper authorization
- Complying with local laws and regulations
- Following organizational policies
- Adhering to rules of engagement

## 🏗️ Architecture

### Technology Stack

- **Language**: Rust 2021 edition
- **CLI Framework**: clap 4.5 (command-line parsing)
- **Async Runtime**: tokio 1.42 (for future async features)
- **Networking**: std::net (built-in TCP)
- **Formatting**: colored 2.1 (terminal colors)

### Project Structure

```
cautious-engine/
├── src/
│   └── main.rs           # Main application logic
├── Cargo.toml            # Rust dependencies and metadata
├── README.md             # This file
└── .gitignore            # Git ignore patterns
```

## 🧪 Testing

Run the built-in functionality:

```bash
# Test the guide display
cargo run -- guide

# Test detection (safe - just displays detection logic)
cargo run -- detect -t example.com

# Build and run tests
cargo test
```

## 🚧 Roadmap

Future enhancements planned:

- [ ] Actual HTTP request functionality (currently simulated)
- [ ] Real WAF/IDS detection signatures
- [ ] Proxy support for anonymity
- [ ] Request/response logging
- [ ] Custom payload support
- [ ] Multi-threaded scanning (with rate limits)
- [ ] Export results to JSON/CSV
- [ ] Plugin architecture for custom checks

## 🤝 Contributing

Contributions are welcome! This is a defensive tool for ethical hacking - please ensure any contributions:

- Follow responsible disclosure practices
- Include appropriate warnings
- Don't include exploits or malicious code
- Maintain the "cautious" philosophy

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

This tool is inspired by the need for more responsible and cautious security testing practices. It's designed to help security professionals avoid common pitfalls like:

- Triggering IDS/IPS systems
- Overwhelming target systems
- Getting blocked by rate limiters
- Operating without proper authorization

---

**Remember: Being cautious isn't about being slow - it's about being smart, responsible, and professional.** 🛡️

*For educational and authorized security testing purposes only.*
