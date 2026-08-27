# 🛡️ OSINT Intelligence Platform

一個支援多語系（繁中/簡中/英文）、結合 Kali 內建與開源工具、具備圖譜視覺化與 AI 情報分析的 OSINT 調查系統。

## ✨ 特色功能
- **多目標識別**：支援姓名、網域、Email、電話號碼自動分類與繁簡/拼音擴展。
- **工具集整合**：整合 Maigret、Holehe、theHarvester 等開源資安與社群探測工具。
- **身分驗證與 RBAC**：JWT 認證與操作員角色權限控管。
- **關聯圖譜視覺化**：Cytoscape.js 節點關聯繪製。
- **AI 情報總結**：串接 Gemini API 自動產出調查摘要報告。

## 🚀 快速開始

### 1. 一鍵安裝依賴 (Kali / Ubuntu / Debian)
```bash
git clone https://github.com/jasonsuuu999999/osint-framework.git
cd osint-framework
chmod +x scripts/setup.sh
./scripts/setup.sh
