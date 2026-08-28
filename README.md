# 🛡️ OSINT Intelligence & Asset Investigation Platform

一個現代化、全功能、非同步架構的公開來源情報（OSINT）自動化調查與資產探測平台。專為資安研究員、滲透測試人員與情資分析師設計，支援多語系（繁中/簡中/英文）輸入，深度整合 Kali Linux 原生工具鏈、現代開源情報工具，並具備互動式關聯圖譜與 AI 智慧分析總結。

---

## ✨ 核心特色與功能

### 1. 🎯 多目標自動識別與標準化 (Multi-Entity Normalizer)
- **多類型自動判定**：自動識別輸入為 **網域 (Domain)**、**人名/暱稱 (Person/Alias)**、**電子郵件 (Email)** 或 **電話號碼 (Phone)**。
- **繁簡雙向標準化與拼音展開**：內建 OpenCC 與 Pypinyin，自動將中文人名轉化為漢語拼音、多種別名（Alias）變體，以提升社群帳號枚舉命中率。

### 2. 🛠️ 模組化 OSINT 工具矩陣 (Modular Recon Engine)
- **社群與身分探測**：`Maigret`、`Sherlock`、跨平台原生 HTTP 探測。
- **信箱與外洩反查**：`Holehe`（120+ 網站註冊探測）、MX 記錄解析、Gravatar 頭像檢查。
- **門號情報解析**：`PhoneInfoga`、`libphonenumber`（多國 E.164 格式、運營商與地理區域運算）。
- **網域、WAF 與網路資產**：`theHarvester`、`Amass`、`Sublist3r`、`DNSRecon`、`Wafw00f`（WAF 指紋辨識）、`HTTPX`（Web 協定/標題/服務探測）、`WhatWeb`（網站技術棧）、`Nmap`（快速開放服務埠探測）、`crt.sh` 憑證透明度日誌、WHOIS 歷史。
- **100% 高可用原生備援引擎**：即使環境未安裝特定 CLI 工具，系統內建的純 Python 原生引擎仍能保底獲取 DNS、WHOIS、HTTP 與社群基本資產。

### 3. 🤖 AI 智慧情資彙整與分析 (AI Analyst)
- **動態模型適配**：支援 Google Gemini 與 OpenAI 相容介面，自動適配帳號支援的最新模型（如 `gemini-3.6-flash`, `gemini-3.6-pro`, `gpt-4o-mini`）。
- **結構化報告產出**：自動根據採集到的資產碎片生成【目標概況與足跡研判】、【關鍵關聯實體】、【誤報過濾建議】與【下一步深挖建議】。

### 4. 🌐 現代化 WebUI 介面
- **暗色情報員風格**：基於 Vue 3、Tailwind CSS 與 Cytoscape.js。
- **互動式圖譜**：節點自動拖曳、縮放、關聯邊自動排版。
- **模式切換**：支援「⚡ 一鍵全自動探測」與「🛠️ 自選指定工具」。
- **歷史案件與搜尋**：左側側邊欄即時關鍵字過濾、歷史調查案件秒級切換與刪除。
- **角色權限控管 (RBAC)**：內建 JWT 認證與使用者管理後台（管理員可新增帳號、調整權限、修改密碼）。

---

## 📁 專案目錄結構

```text
osint-framework/
├── backend/
│   ├── app/
│   │   ├── core/           # JWT 認證、密碼雜湊與安全中介
│   │   ├── models/         # SQLAlchemy 資料庫模型 (PostgreSQL + JSONB)
│   │   ├── modules/        # CLI 工具調用器 (Safe Subprocess) 與原生探測
│   │   ├── nlp/            # 輸入正規化、繁簡轉換、Gemini/OpenAI 分析模組
│   │   └── main.py         # FastAPI 核心應用程式與路由
│   ├── requirements.txt    # Python 相依套件
│   └── .env.example        # 環境變數範本
├── frontend/
│   └── index.html          # Vue 3 + Tailwind + Cytoscape 單頁應用
├── scripts/
│   └── setup.sh            # Kali / VPS 一鍵自動化安裝腳本
├── .gitignore
└── README.md

安裝步驟
cd osint-framework
chmod +x scripts/setup.sh
./scripts/setup.sh

啟動系統
source venv/bin/activate
1.直接執行
PYTHONPATH=backend python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
or
2.背景執行
nohup env PYTHONPATH=backend python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > osint_server.log 2>&1 &

訪問瀏覽器
http://localhost:8000，Default Username/Password：admin/admin123

