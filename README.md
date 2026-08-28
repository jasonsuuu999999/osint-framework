# 🛡️ OSINT Intelligence & Asset Investigation Platform

A modern, full-featured, asynchronous open-source intelligence (OSINT) automated investigation and asset detection platform. Designed for cybersecurity researchers, penetration testers, and intelligence analysts, it supports multilingual input (Traditional Chinese/Simplified Chinese/English), deeply integrates with the Kali Linux native toolchain and modern open-source intelligence tools, and features interactive correlation graphs and AI-powered intelligent analysis and summarization.

---

## ✨ Core features and functions

### 1. 🎯 Automatic multi-target identification and standardization (Multi-Entity Normalizer)
- **Automatic Input Type Recognition**：Automatically identifies input as a **Domain**、**Person/Alias**、**Email** or **Phone**.
- **Simplified/Traditional Standardization and Pinyin Expansion**：Built-in OpenCC and Pypinyin automatically convert Chinese names to Pinyin and various alias variations to improve the accuracy of social media account enumeration.

### 2. 🛠️ Modular Recon Engine OSINT Tool Matrix (Modular Recon Engine)
- **Community and Identity Detection**：`Maigret`, `Sherlock`, cross-platform native HTTP detection.
- **Email and Leakage Recovery**：`Holehe`（120+ website registration detection）、MX record parsing、Gravatar avatar inspection.
- **Phone Intelligence Analysis**：`PhoneInfoga`、`libphonenumber`, carrier and geographic region calculation.
- **Domains, WAF, and Network Assets**：`theHarvester`、`Amass`、`Sublist3r`、`DNSRecon`、`Wafw00f`（WAF fingerprint）、`HTTPX`（Web protocol/title/service detection）、`WhatWeb`（Web Tech）、`Nmap`（port detection）、`crt.sh`  credential transparency log, WHOIS history.
- **Native Engine**：Even if specific CLI tools are not installed in the environment, the system's built-in pure Python native engine can still guarantee access to DNS, WHOIS, HTTP, and basic community assets.

### 3. 🤖 AI-powered intelligent intelligence data aggregation and analysis (AI Analyst)
- **Dynamic Model Adaptation**：Supports Google Gemini and OpenAI compatible interfaces, automatically adapting to the latest models supported by the account(such as `gemini-3.6-flash`, `gemini-3.6-pro`, `gpt-4o-mini`).
- **Structured Report Generation**：Automatically generates 「Target Overview and Footprint Analysis」, 「Key Related Entities」, 「False Alarm Filtering Suggestions」 and 「Next Steps for In-Depth Analysis」 based on collected asset fragments.

### 4. 🌐 WebUI Interface
- **Dark Style**：Based on Vue 3, Tailwind CSS, and Cytoscape.js.
- **Interactive Graph**：Automatic node dragging, scaling, and automatic alignment of related edges.
- **Mode Switching**：Supports「⚡ Auto」 and 「🛠️ Custom」。
- **Case History and Search**：Real-time keyword filtering in the left sidebar, and second-level switching and deletion of historical investigation cases.
- **Role-Based Access Control(RBAC)**：Built-in JWT authentication and user management backend (administrators can add accounts, adjust permissions, and change passwords).

---

## 📁 Project Structure

```text
osint-framework/
├── backend/
│   ├── app/
│   │   ├── core/           # JWT authentication, password hashing, and secure intermediaries
│   │   ├── models/         # SQLAlchemy database model (PostgreSQL + JSONB)
│   │   ├── modules/        # CLI utility caller (Safe Subprocess) and native probing
│   │   ├── nlp/            # Input normalization, simplified/traditional Chinese conversion, Gemini/OpenAI analysis modules
│   │   └── main.py         # FastAPI core applications and routing
│   ├── requirements.txt    # Python dependencies
│   └── .env.example        # Environment variable template
├── frontend/
│   └── index.html          # Vue 3 + Tailwind + Cytoscape single-page application
├── scripts/
│   └── setup.sh            # Kali / VPS one-click automated installation script
├── .gitignore
└── README.md

Install Steps
cd osint-framework
chmod +x scripts/setup.sh
./scripts/setup.sh

