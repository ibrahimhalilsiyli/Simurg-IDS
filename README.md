# Simurg IDS v3.0 (Enterprise Edition)

Simurg is a modular and high-performance **Intrusion Detection System (IDS)** designed for real-time log monitoring, traffic analysis, and automated threat response. It supports multiple log formats and provides alerting in industry-standard SIEM formats.

![Simurg Banner](https://raw.githubusercontent.com/username/repo/main/banner_preview.png)

## 🚀 Key Features

- **Multi-Source Ingestion**: Real-time monitoring of local files, UDP Syslog streams, and Stdin pipes.
- **Advanced Core Rules**:
    - **Web Attacks**: SQL Injection, Cross-Site Scripting (XSS), Directory Traversal.
    - **Brute Force Detection**: Intelligent thresholding for HTTP and SSH login failures.
    - **Scanning Detection**: Identifies known tools (Nikto, Nmap, Masscan) via User-Agent and path enumeration.
    - **Statistical Deviation**: Detects unusual traffic spikes using rolling-window baselines.
- **SIEM-Ready Outputs**: Native support for **ECS JSON**, **Suricata EVE JSON**, **ArcSight CEF**, and standard text logs.
- **Automated Response**: Built-in IP banning via `iptables` (Linux) with automated unban scheduling.
- **Cross-Platform Daemon**: Background execution with watchdog recovery and service installation support.

## 🛠️ Tech Stack

- **Language**: Python 3.8+ (Zero external dependencies for core logic).
- **Architecture**: Multi-threaded producer-consumer pipeline.
- **Compliance**: MITRE ATT&CK mapping for all detection rules.

## 📦 Installation

```bash
git clone https://github.com/yourusername/Simurg-IDS.git
cd Simurg-IDS
```

### Quick Start
```bash
python simurg.py
```

## 🛡️ Detection Rules

| Rule ID | Name | Classification | MITRE ATT&CK |
|---|---|---|---|
| 100001 | Brute Force | attempted-admin | T1110 |
| 100005 | Scanner | attempted-recon | T1595 |
| 100006 | DDoS Flood | denial-of-service | T1498 |
| 100009 | SSH Brute | attempted-admin | T1110.001 |
| 100011 | Traffic Deviation | unusual-traffic | T1499 |

## 🧪 Testing

The repository includes a realistic attack simulator to verify rule accuracy:
- `python log_generator.py`: Generates simulated attack traffic to verify rule accuracy.
- `python simurg.py`: Use the built-in menu to start the monitor and simulation simultaneously in separate sessions.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Built for security researchers and system administrators.*
