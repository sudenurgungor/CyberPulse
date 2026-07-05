# 🛡️ CyberPulse - Real-Time Intrusion Detection & Prevention System (IDS/IPS)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python">
  <img src="https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask">
  <img src="https://img.shields.io/badge/PostgreSQL-Database-blue?logo=postgresql">
  <img src="https://img.shields.io/badge/Linux-Ubuntu-orange?logo=ubuntu">
  <img src="https://img.shields.io/badge/Scapy-Network%20Analysis-green">
  <img src="https://img.shields.io/badge/Status-Completed-success">
</p>

<p align="center">
  <b>Lightweight Real-Time Intrusion Detection and Prevention System for Small-Scale Networks</b>
</p>

---

# 📌 About The Project

CyberPulse is a lightweight **Real-Time Intrusion Detection and Prevention System (IDS/IPS)** developed as a graduation project.

The system monitors network traffic in real time, detects malicious activities, stores attack records in a PostgreSQL database, and automatically blocks malicious IP addresses using firewall rules.

---

# ✨ Features

✅ Real-time network traffic monitoring  
✅ SQL Injection detection  
✅ Cross-Site Scripting (XSS) detection  
✅ Port Scan detection  
✅ High Traffic anomaly detection  
✅ Brute Force login detection  
✅ Automatic IP blocking using iptables  
✅ Whitelist and Blacklist management  
✅ Interactive Web Dashboard  
✅ Attack log filtering and CSV export  
✅ Configurable detection thresholds

---

# 🏗️ System Architecture

CyberPulse was tested in a virtual lab environment consisting of multiple virtual machines.

```text
┌──────────────────┐
│   Attacker VM    │
└────────┬─────────┘
         │
         │ Attack Traffic
         ▼
┌──────────────────┐
│   CyberPulse     │
│      IDS/IPS     │
└────────┬─────────┘
         │
         │ Detected Attacks
         ▼
┌──────────────────┐
│ Flask Dashboard  │
│ PostgreSQL DB    │
└──────────────────┘
```

The IDS/IPS monitors network traffic and records detected attacks into PostgreSQL while presenting live statistics on the dashboard.

---

# 🚨 Supported Attack Types

| Attack Type | Description |
|-------------|-------------|
| SQL Injection | Detects malicious SQL payloads |
| XSS | Detects client-side script injection |
| Port Scan | Detects scanning attempts on multiple ports |
| High Traffic | Detects abnormal traffic spikes |
| Brute Force | Detects repeated failed login attempts |

---

# 🖥️ Dashboard Screenshots

## 📊 Dashboard Overview

![Dashboard](docs/images/login.png)

---

## 📈 Attack Statistics & Severity Distribution

![Statistics](docs/images/attack-statistics.png)

---

## 🚨 Recent Attacks & System Summary

![Recent Attacks](docs/images/recent-attacks.png)

---

## 🌐 IP List Management

![IP Lists](docs/images/ip-lists.png)

---

## 🚫 Blocked IP Addresses

![Blocked IPs](docs/images/blocked-ips.png)

---

## 📝 Attack Logs & CSV Export

![Logs](docs/images/attack-logs.png)

---

## ⚙️ Rule Settings - Blocking Controls

![Rule Settings](docs/images/rule-settings1.png)

---

## ⚙️ Rule Settings - Threshold Configuration

![Threshold Settings](docs/images/rule-settings2.png)

---

# 🗄️ Database

CyberPulse uses PostgreSQL to store:

- Attacks
- Blocked IP addresses
- Whitelist records
- Blacklist records

Main tables:

```text
attacks
blocked_ips
ip_lists
```

Database schema:

```text
database/schema.sql
```

---

# 📁 Project Structure

```text
CyberPulse
│
├── database
│   ├── README.txt
│   └── schema.sql
│
├── docs
│   └── images
│
├── source
│   ├── app.py
│   ├── config.py
│   ├── db.py
│   ├── main.py
│   ├── sniffer.py
│   └── templates
│       ├── blocked_ips.html
│       ├── dashboard.html
│       ├── ip_lists.html
│       ├── login.html
│       ├── logs.html
│       └── settings.html
│
├── rules_config.json
├── README.md
└── .gitignore
```

---

# ⚙️ Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/sudenurgungor/CyberPulse.git
cd CyberPulse
```

## 2️⃣ Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

## 4️⃣ Configure Database

Edit:

```text
source/config.py
```

Example:

```python
DB_HOST = "localhost"
DB_NAME = "intrusiondb"
DB_USER = "postgres"
DB_PASSWORD = "your_password"
```

---

# ▶️ Run The Project

### Start Flask Dashboard

```bash
sudo venv/bin/python source/app.py
```

### Start Packet Sniffer

```bash
sudo venv/bin/python source/main.py
```

Dashboard:

```text
http://127.0.0.1:5000
```

---

# 📊 Dashboard Modules

- 📈 Live attack statistics
- 📝 Recent attack records
- 🌐 IP whitelist and blacklist management
- 🚫 Blocked IP management
- 📋 Attack log filtering
- ⚙️ Rule settings and thresholds
- 📥 CSV export

---

# 🔧 Default Thresholds

| Rule | Value |
|------|--------|
| SQL Injection Block Threshold | 3 attempts |
| XSS Block Threshold | 3 attempts |
| High Traffic Threshold | 40 packets / 5 seconds |
| Port Scan Threshold | 5 different ports |

---

# 🚀 Future Improvements

- 🤖 Machine Learning based anomaly detection
- 📧 Email notification system
- ⏱️ Automatic unblock timer
- 👥 Role-based authentication
- 🐳 Docker deployment
- ☁️ Centralized log collection
- 📱 Responsive dashboard improvements

---

# 👩‍💻 Author

**Sude Güngör**

🎓 Software Engineering Graduate  
💻 Aspiring Software Developer

GitHub: https://github.com/sudenurgungor

---

⭐ If you like this project, don't forget to give it a star!
