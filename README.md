# 🔥 Firewall, IDS & IPS Simulator (SOC-Style)

A Python-based firewall simulator featuring **IDS, IPS, threat-intelligence blocking,
SOC analytics dashboard, role-based access control (RBAC), and Dockerized deployment**.

This project is designed to demonstrate **real-world security engineering concepts**
used in SOC environments and enterprise networks.

---

## 🚀 Features

- ✅ Rule-based firewall with priority engine
- 🚫 Default-deny security model
- 🔍 Intrusion Detection System (IDS)
- 🛡 Intrusion Prevention System (IPS with auto-blocking)
- 🌐 Threat-intelligence IP blocking
- 📊 SOC dashboard with traffic analytics
- 👥 Role-Based Access Control (Admin / Analyst)
- 🧱 Firewall rule management (Add / Edit / Delete)
- 💾 Persistent firewall rules using JSON
- 🖥 Web-based UI + CLI-ready architecture
- 🐳 Dockerized for portable deployment

---

## 🧠 Architecture Overview
Packet
↓
Threat Intelligence Check
↓
IPS Auto-Blocking
↓
Firewall Rules (Priority-Based)
↓
ALLOW / DENY Decision
↓
Logs & Metrics
↓
SOC Dashboard


This layered design follows **defense-in-depth principles** used in real firewalls.

---

## 👤 User Roles

| User     | Role     | Permissions |
|----------|----------|-------------|
| admin    | Admin    | Full access (manage rules, dashboard, firewall) |
| analyst  | Analyst  | View-only access (firewall & dashboard) |

---

## 🔐 Demo Credentials

| Username | Password   |
|--------|------------|
| admin  | admin123   |
| analyst | analyst123 |

---

## 🛠 Tech Stack

- **Python**
- **Flask**
- **Docker**
- **HTML / CSS**
- **Chart.js**
- **JSON (persistent storage)**

---
