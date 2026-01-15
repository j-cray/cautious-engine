# 🛡️ cautious-engine v2.0

An **automated cybersec/opsec defense stack** built in Rust for maximum performance, safety, and reliability. **Fully cross-platform** (Windows, Linux, macOS) with daemon mode for automated, always-running protection and AI-powered threat analysis.

![Security](https://img.shields.io/badge/Security-Defense%20Stack-green?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Rust-orange?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=for-the-badge)

## 🎯 What is cautious-engine?

**Cautious Engine v2.0** is a professional-grade automated cybersecurity and operational security defense stack. It provides comprehensive intrusion detection, automated threat response, real-time monitoring, security auditing, **daemon mode for continuous operation**, and **AI-powered threat analysis** to protect your systems 24/7 from attacks.

### 🌟 Core Features

#### 🤖 **Daemon Mode - Always Running** ⭐ NEW
- Run as a background service for continuous protection
- Automated threat detection and response
- No manual intervention required
- Cross-platform process management
- Graceful shutdown handling
- PID file management

#### 🧠 **AI-Powered Analysis** ⭐ NEW
- Machine learning-based anomaly detection
- Threat prediction and forecasting
- Pattern recognition using statistical analysis
- AI integration recommendations for advanced deployment
- Support for external AI services (OpenAI, Azure, AWS)

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

### 🤖 Daemon Mode - Automated Always-Running Service ⭐ NEW

Run the engine as a background service for continuous automated protection:

```bash
# Start daemon with aggressive detection (recommended for production)
cargo run -- daemon --port 8080 --aggressive --log security.log

# Start daemon in normal mode
cargo run -- daemon --port 8080

# Custom PID file location
cargo run -- daemon --port 8080 --pid-file /var/run/cautious-engine.pid
```

**Features:**
- Runs continuously in the background
- Automatic threat detection and blocking
- Auto-saves logs periodically
- Graceful shutdown on SIGTERM/SIGINT
- Cross-platform compatible (Windows/Linux/macOS)
- PID file for process management
- No manual intervention required

**Production Use:**
```bash
# Linux/macOS - run in background
nohup ./target/release/cautious-engine daemon --aggressive &

# Windows - use Task Scheduler or NSSM for service installation
```

### 🧠 AI-Powered Threat Analysis ⭐ NEW

Analyze threats using AI and machine learning:

```bash
# Full AI analysis with anomaly detection and prediction
cargo run -- ai-analyze --log security.log

# Just anomaly detection
cargo run -- ai-analyze --log security.log --prediction false

# Just threat prediction
cargo run -- ai-analyze --log security.log --anomaly-detection false
```

**Capabilities:**
- Statistical anomaly detection
- Behavioral analysis
- Threat prediction and forecasting
- Pattern recognition
- AI integration recommendations
- Support for ML frameworks (TensorFlow, PyTorch, scikit-learn)

**AI Integration Suggestions:**
- Machine learning models (Random Forest, LSTM, SVM)
- Natural language processing for payload analysis
- Reinforcement learning for adaptive defense
- External AI services (OpenAI, Azure ML, AWS SageMaker)

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

### Daemon Mode - Automated Service

```bash
$ cargo run -- daemon --port 8080 --aggressive

╔══════════════════════════════════════════════════════════╗
║  🛡️  CAUTIOUS ENGINE v2.0 - DEFENSE STACK  🛡️           ║
║     Automated Cybersec/Opsec Defense System             ║
╚══════════════════════════════════════════════════════════╝

🤖 Starting Daemon Mode - Automated Defense Service
Port: 8080
Mode: AGGRESSIVE
Log: security.log
PID File: cautious-engine.pid

✓ Daemon started with PID: 12345

════════════════════════════════════════════════════════════
Daemon Active - Continuous Monitoring
Running indefinitely until stopped
════════════════════════════════════════════════════════════

⚠️ Port Scan Detected from 192.168.3.21 - Rapid port scanning activity
🚫 SQL Injection Attempt from 10.7.21.77 - Malicious SQL payload [BLOCKED]
💾 Auto-saved 25 events to log

📊 Daemon Status - Uptime: 60s | Events: 25 | Blocked: 8

# Runs continuously until Ctrl+C or service stop
```

### AI-Powered Analysis

```bash
$ cargo run -- ai-analyze --log security.log

╔══════════════════════════════════════════════════════════╗
║  🛡️  CAUTIOUS ENGINE v2.0 - DEFENSE STACK  🛡️           ║
║     Automated Cybersec/Opsec Defense System             ║
╚══════════════════════════════════════════════════════════╝

🤖 AI-Powered Threat Analysis
Log file: security.log
Anomaly Detection: ENABLED
Threat Prediction: ENABLED

════════════════════════════════════════════════════════════
AI Analysis Report
════════════════════════════════════════════════════════════

📊 Dataset Overview:
  Total Events: 150
  Analysis Window: Last 150 events

🔍 Anomaly Detection (ML-Based):
  Average events per IP: 3.75
  Anomaly threshold: 7.50

  ⚠️ Anomaly detected: 192.168.1.100 (12 events - 220% above normal)
  ⚠️ Anomaly detected: 10.0.0.50 (9 events - 140% above normal)

🔮 Threat Prediction (Next 24 Hours):
    • Port Scan - 45 events (85% confidence)
    • SQL Injection - 20 events (85% confidence)
    • Brute Force - 30 events (85% confidence)

💡 AI Integration Recommendations:
  1. Machine Learning: TensorFlow, PyTorch, Random Forest
  2. NLP: Payload analysis, threat classification
  3. Reinforcement Learning: Adaptive defense policies
  4. External AI: OpenAI GPT, Azure ML, AWS SageMaker

✓ AI analysis complete
```

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
| `daemon` | ⭐ Run as automated background service (always running) |
| `ai-analyze` | ⭐ AI-powered threat analysis and prediction |
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

### Daemon Options (Automated Service)

```bash
-p, --port <PORT>            Port to monitor [default: 8080]
-a, --aggressive             Enable aggressive detection [default: true]
-l, --log <LOG>              Log file path [default: security.log]
    --pid-file <PID_FILE>    PID file location [default: cautious-engine.pid]
```

### AI-Analyze Options

```bash
-l, --log <LOG>                    Log file to analyze [default: security.log]
    --anomaly-detection <BOOL>     Enable anomaly detection [default: true]
    --prediction <BOOL>            Enable threat prediction [default: true]
```

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

### Cross-Platform Compatibility ⭐

Cautious Engine is **fully cross-platform** and works seamlessly on:

- ✅ **Linux** (Ubuntu, Debian, Fedora, RHEL, Arch, etc.)
- ✅ **macOS** (Intel and Apple Silicon)
- ✅ **Windows** (10, 11, Server)

**Platform-Specific Features:**
- Cross-platform signal handling for daemon mode
- Native process management (PID files)
- Compatible file paths and separators
- Works with system services (systemd, launchd, Windows Service)

**No platform-specific dependencies** - pure Rust ensures consistent behavior across all operating systems.

### Technology Stack

- **Language**: Rust 2021 edition
- **CLI**: clap 4.5
- **Serialization**: serde + serde_json
- **Time**: chrono (with clock feature)
- **Terminal**: colored
- **Signals**: signal-hook (cross-platform)
- **Concurrency**: Arc, Mutex, AtomicBool for thread-safe operations

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
2. **AI Layer**: Machine learning-based anomaly detection and prediction ⭐
3. **Analysis Layer**: Event correlation and pattern matching
4. **Response Layer**: Automated blocking and alerting
5. **Daemon Layer**: Continuous background operation ⭐
6. **Logging Layer**: Comprehensive event logging and storage
7. **Reporting Layer**: Analysis and compliance reporting
8. **Audit Layer**: Proactive security scanning

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

- **System Administrators**: Protect servers and infrastructure 24/7
- **Security Teams**: Monitor and respond to threats automatically
- **DevOps Engineers**: Integrate security into CI/CD pipelines
- **Compliance Officers**: Generate security reports and audits
- **SOC Analysts**: Real-time threat monitoring with AI insights
- **Incident Responders**: Quick threat analysis and prediction
- **Managed Security Service Providers (MSSPs)**: Deploy as always-running service

## 🤖 AI Integration Guide

Cautious Engine provides a foundation for AI/ML integration with current statistical analysis and recommendations for advanced deployment:

### Current AI Features
- ✅ Statistical anomaly detection
- ✅ Behavioral pattern analysis
- ✅ Threat prediction based on historical data
- ✅ AI integration recommendations

### Recommended AI/ML Enhancements

**Phase 1: Traditional ML (Current Phase)**
- Implement scikit-learn for classification (SVM, Random Forest)
- K-means clustering for attack grouping
- Statistical outlier detection (IQR, Z-score)

**Phase 2: Deep Learning**
- TensorFlow/PyTorch for advanced threat detection
- LSTM networks for time-series attack prediction
- Autoencoders for anomaly detection
- CNN for traffic pattern visualization

**Phase 3: NLP Integration**
- Analyze attack payloads using transformer models
- BERT/GPT for intelligent log analysis
- Entity extraction from security events
- Automated threat classification

**Phase 4: Reinforcement Learning**
- Self-learning defense policies
- Adaptive blocking strategies (Q-learning, DQN)
- Automated response optimization

**Phase 5: External AI Services**
- OpenAI API for intelligent analysis
- Azure Cognitive Services for threat intelligence
- AWS SageMaker for model deployment
- Google Cloud AI for pattern recognition

### Integration Example

```rust
// Example: Integrate with Python ML models
use pyo3::prelude::*;

fn predict_threat(features: Vec<f64>) -> PyResult<String> {
    Python::with_gil(|py| {
        let model = py.import("threat_model")?.getattr("predict")?;
        let result = model.call1((features,))?;
        result.extract()
    })
}
```

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Defense Philosophy

This tool embodies a **defense-in-depth** approach:

- **Proactive**: Detect threats before they cause damage
- **Automated**: Respond to attacks without human intervention (daemon mode)
- **Intelligent**: AI-powered analysis and prediction
- **Comprehensive**: Multiple layers of defense
- **Auditable**: Full logging and reporting
- **Configurable**: Adaptable to different environments
- **Cross-Platform**: Works on Windows, Linux, and macOS

---

**Remember: Security is a continuous process. Monitor actively, respond quickly, defend comprehensively.** 🛡️

*For system defense and security monitoring purposes.*

**Version 2.0 - Automated, AI-Enhanced, Always-Running Defense Stack! 🤖🛡️**
