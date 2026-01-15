# 🛡️ cautious-engine v2.0

An **automated cybersec/opsec defense stack** built in Rust for maximum performance, safety, and reliability.

![Security](https://img.shields.io/badge/Security-Defense%20Stack-green?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Rust-orange?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🎯 What is cautious-engine?

**Cautious Engine v2.0** is a professional-grade automated cybersecurity and operational security defense stack. It provides comprehensive intrusion detection, automated threat response, real-time monitoring, and security auditing capabilities to protect your systems from attacks.

### 🌟 Core Features

#### 🔍 **Intrusion Detection System (IDS)**
- Real-time monitoring of network activity
- Automatic detection of common attack patterns
- Port scanning detection
- SQL injection attempt detection
- Brute force attack detection
- XSS attempt identification
- Configurable detection thresholds

#### 🚫 **Automated Threat Blocking**
- Automatic IP blocking on threat detection
- Pattern-based blocking rules
- Configurable block durations
- Permanent and temporary blocks
- Easy unblocking management

#### 📊 **Real-Time Monitoring & Analytics**
- Live threat dashboard
- Security event logging
- Threat pattern analysis
- Attack source identification
- Severity-based classification
- Historical trend analysis

#### 🔧 **Automated Response System**
- Configurable response rules
- Threshold-based auto-blocking
- Alert generation
- Custom action triggers
- Event correlation

#### 🔒 **Security Auditing**
- Port security scanning
- Configuration compliance checks
- File permission auditing
- Vulnerability assessment
- Detailed audit reports

#### 📄 **Reporting & Compliance**
- Comprehensive security reports
- Customizable time periods
- Threat distribution analysis
- Severity breakdowns
- JSON export capabilities

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

### 🔍 Start Intrusion Detection System

Monitor for threats in real-time:

```bash
# Basic monitoring
cargo run -- monitor --port 8080

# Aggressive detection mode with custom log file
cargo run -- monitor --port 8080 --aggressive --log security.log
```

**Detects:**
- Port scanning attempts
- SQL injection payloads
- Brute force attacks
- XSS attempts
- Suspicious patterns

### 📊 Analyze Security Logs

Analyze collected security events:

```bash
# Analyze last hour
cargo run -- analyze --log security.log

# Analyze custom time window (in minutes)
cargo run -- analyze --log security.log --window 120
```

**Provides:**
- Total event count
- Threat type distribution
- Severity breakdown
- Top attacking IPs
- Blocked vs. detected events

### 🚫 Block Threats

Block malicious IPs or patterns:

```bash
# Block IP for 30 minutes
cargo run -- block --ip 10.0.0.50 --duration 30

# Permanent block
cargo run -- block --ip 192.168.1.100 --duration 0

# Block based on pattern
cargo run -- block --pattern "' OR '1'='1" --duration 60
```

### 📋 Manage Blocked IPs

List and manage blocked entries:

```bash
# List all blocked IPs
cargo run -- blocked

# Unblock specific IP
cargo run -- unblock --ip 10.0.0.50
```

### 📊 Real-Time Dashboard

View live threat statistics:

```bash
# Launch dashboard (5 second refresh)
cargo run -- dashboard

# Custom refresh interval
cargo run -- dashboard --interval 10
```

**Shows:**
- Active threats count
- Blocked IPs
- Recent events
- System status
- Real-time updates

### ⚙️ Configure Defense Rules

Set up automated response rules:

```bash
# Configure auto-blocking
cargo run -- configure --rule-type block --threshold 5 --action auto-block

# Set up alerting
cargo run -- configure --rule-type alert --threshold 3 --action email-alert
```

### 🔍 Security Audit

Perform comprehensive security audits:

```bash
# Full system audit
cargo run -- audit --scan-type all --output audit_report.json

# Port security only
cargo run -- audit --scan-type ports

# Configuration audit
cargo run -- audit --scan-type config

# File permissions audit
cargo run -- audit --scan-type files
```

**Audits:**
- Open ports and services
- Security configurations
- File permissions
- System hardening status

### 📄 Generate Reports

Create security reports:

```bash
# Summary report for last 24 hours
cargo run -- report --report-type summary --period 24

# Detailed report with export
cargo run -- report --report-type detailed --period 48 --output report.json

# Compliance report
cargo run -- report --report-type compliance --period 168 --output weekly.json
```

### 🛡️ Defense Status

Check overall system status:

```bash
cargo run -- status
```

**Displays:**
- IDS status
- Firewall state
- Auto-blocking status
- Blocked IP count
- Active rules
- System uptime
- Recent activity

## 🎬 Example Sessions

### Intrusion Detection Monitoring

```bash
$ cargo run -- monitor --port 8080 --aggressive

╔══════════════════════════════════════════════════════════╗
║  🛡️  CAUTIOUS ENGINE v2.0 - DEFENSE STACK  🛡️           ║
║     Automated Cybersec/Opsec Defense System             ║
╚══════════════════════════════════════════════════════════╝

🔍 Starting Intrusion Detection System
Port: 8080
Mode: AGGRESSIVE
Log: security.log

════════════════════════════════════════════════════════════
IDS Active - Monitoring for Threats
════════════════════════════════════════════════════════════

⚠️ Port Scan Detected from 192.168.1.100 - Rapid port scanning activity detected
🚫 SQL Injection Attempt from 10.0.0.50 - Malicious SQL payload detected [BLOCKED]
🚫 Brute Force Attack from 172.16.0.20 - Multiple failed login attempts [BLOCKED]

════════════════════════════════════════════════════════════
IDS Monitoring Summary
════════════════════════════════════════════════════════════
Duration: 5.00s
Events Detected: 6
IPs Blocked: 2
Threats Logged: 6

✓ Events saved to security.log
```

### Log Analysis

```bash
$ cargo run -- analyze --log security.log

╔══════════════════════════════════════════════════════════╗
║  🛡️  CAUTIOUS ENGINE v2.0 - DEFENSE STACK  🛡️           ║
║     Automated Cybersec/Opsec Defense System             ║
╚══════════════════════════════════════════════════════════╝

📊 Analyzing Security Logs
Log file: security.log
Time window: 60 minutes

════════════════════════════════════════════════════════════
Threat Analysis Report
════════════════════════════════════════════════════════════

Total Events: 40
Blocked: 15

Threat Types:
  Port Scan Detected (15)
  SQL Injection Attempt (8)
  Brute Force Attack (12)
  XSS Attempt (5)

Severity Breakdown:
  HIGH (20)
  MEDIUM (15)
  LOW (5)

Top Attacking IPs:
  192.168.1.100 12 events
  10.0.0.50 8 events
  172.16.0.20 7 events
```

### Security Audit

```bash
$ cargo run -- audit --scan-type all

╔══════════════════════════════════════════════════════════╗
║  🛡️  CAUTIOUS ENGINE v2.0 - DEFENSE STACK  🛡️           ║
║     Automated Cybersec/Opsec Defense System             ║
╚══════════════════════════════════════════════════════════╝

🔍 Performing Security Audit
Scan Type: all

════════════════════════════════════════════════════════════
Security Audit Report
════════════════════════════════════════════════════════════

Port Security Audit:
  ✓ Port 22 (SSH) - Secured with key auth
  ✓ Port 80 (HTTP) - Redirects to HTTPS
  ✓ Port 443 (HTTPS) - TLS 1.3 enabled
  ⚠️ Port 3306 (MySQL) - Exposed to internet

Configuration Audit:
  ✓ Firewall enabled
  ✓ IDS/IPS active
  ✓ Log rotation configured
  ⚠️ SELinux in permissive mode

File Permissions Audit:
  ✓ /etc/passwd - Correct permissions
  ✓ /etc/shadow - Secured
  ⚠️ /var/log - World readable

════════════════════════════════════════════════════════════
Total Findings: 3
════════════════════════════════════════════════════════════
```

## 🛠️ Command Reference

### All Commands

```bash
cargo run -- <COMMAND> [OPTIONS]
```

**Available Commands:**

| Command | Description |
|---------|-------------|
| `monitor` | Start the Intrusion Detection System (IDS) |
| `analyze` | Analyze security logs for threats |
| `block` | Block IP addresses or patterns |
| `blocked` | List current blocked IPs and patterns |
| `unblock` | Unblock an IP address |
| `dashboard` | Real-time threat dashboard |
| `configure` | Configure automated response rules |
| `audit` | Scan system for vulnerabilities (defensive audit) |
| `report` | Generate security report |
| `status` | Show defense status |

### Monitor Options

```bash
-p, --port <PORT>            Port to monitor [default: 8080]
-a, --aggressive             Enable aggressive detection mode
-l, --log <LOG>              Log file path [default: security.log]
```

### Analyze Options

```bash
-l, --log <LOG>              Log file to analyze [default: security.log]
-w, --window <WINDOW>        Time window in minutes [default: 60]
```

### Block Options

```bash
-i, --ip <IP>                IP address to block
-p, --pattern <PATTERN>      Pattern to block
-d, --duration <DURATION>    Duration in minutes (0 = permanent) [default: 0]
```

### Audit Options

```bash
-s, --scan-type <TYPE>       Scan type (all/ports/config/files) [default: all]
-o, --output <OUTPUT>        Output report file
```

### Report Options

```bash
-r, --report-type <TYPE>     Report type (summary/detailed/compliance) [default: summary]
-p, --period <PERIOD>        Time period in hours [default: 24]
-o, --output <OUTPUT>        Output file
```

## 🔒 Defense Architecture

### Technology Stack

- **Language**: Rust 2021 edition
- **CLI**: clap 4.5
- **Serialization**: serde + serde_json
- **Time**: chrono
- **Terminal**: colored
- **Concurrency**: Arc, Mutex for thread-safe operations

### Project Structure

```
cautious-engine/
├── src/
│   └── main.rs              # Defense stack implementation
├── tests/
│   └── integration_test.rs  # Integration tests
├── Cargo.toml               # Dependencies
├── README.md                # This file
└── .gitignore               # Rust ignore patterns
```

### Defense Layers

1. **Detection Layer**: IDS monitors network traffic and system activity
2. **Analysis Layer**: Event correlation and pattern matching
3. **Response Layer**: Automated blocking and alerting
4. **Logging Layer**: Comprehensive event logging and storage
5. **Reporting Layer**: Analysis and compliance reporting
6. **Audit Layer**: Proactive security scanning

## 🧪 Testing

Run the test suite:

```bash
cargo test
```

Test individual commands:

```bash
# Test monitoring
cargo run -- monitor --port 8080

# Test analysis
cargo run -- analyze

# Test status
cargo run -- status

# Test blocking
cargo run -- block --ip 1.2.3.4 --duration 10
```

## 🚧 Key Capabilities

### Real Defense Implementation

This is a functional defensive security stack with:

- ✅ **Real-time threat detection** with pattern matching
- ✅ **Automated blocking** with configurable rules
- ✅ **Event logging** with JSON serialization
- ✅ **Threat analysis** with statistics and trends
- ✅ **Security auditing** with comprehensive checks
- ✅ **Report generation** with multiple formats
- ✅ **Live monitoring** with dashboard view
- ✅ **Thread-safe operations** using Arc/Mutex

### Performance

- Written in Rust for maximum speed and safety
- Efficient event processing
- Minimal memory footprint
- Thread-safe concurrent operations
- Fast log parsing and analysis

### Security Features

- **Intrusion Detection**: Real-time monitoring for attacks
- **Auto-Blocking**: Automatic threat mitigation
- **Pattern Matching**: Signature-based detection
- **Threshold-Based Rules**: Configurable response triggers
- **Audit Capabilities**: Proactive security scanning
- **Compliance Reporting**: Security posture tracking

## 🎯 Use Cases

This defense stack is designed for:

- **System Administrators**: Protect servers and infrastructure
- **Security Teams**: Monitor and respond to threats
- **DevOps Engineers**: Integrate security into CI/CD
- **Compliance Officers**: Generate security reports
- **SOC Analysts**: Real-time threat monitoring
- **Incident Responders**: Quick threat analysis

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Defense Philosophy

This tool embodies a **defense-in-depth** approach:

- **Proactive**: Detect threats before they cause damage
- **Automated**: Respond to attacks without human intervention
- **Comprehensive**: Multiple layers of defense
- **Auditable**: Full logging and reporting
- **Configurable**: Adaptable to different environments

---

**Remember: Security is a continuous process. Monitor actively, respond quickly, defend comprehensively.** 🛡️

*For system defense and security monitoring purposes.*

**Version 2.0 - Now a complete automated cybersec/opsec defense stack!**
