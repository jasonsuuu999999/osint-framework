#!/usr/bin/env bash
# ==============================================================================
# OSINT Platform - One-Click Environment Setup Script
# Supported OS: Kali Linux, Ubuntu 22.04/24.04, Debian 11/12
# ==============================================================================

set -euo pipefail

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}    🚀 OSINT Platform 環境一鍵安裝與初始化腳本       ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. 檢查 root / sudo 權限
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
    if ! command -v sudo &> /dev/null; then
        echo -e "${RED}[-] 請以 root 權限執行此腳本，或確認系統已安裝 sudo。${NC}"
        exit 1
    fi
else
    SUDO=""
fi

# 2. 識別 Linux 發行版
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=${ID:-unknown}
    OS_LIKE=${ID_LIKE:-""}
else
    echo -e "${RED}[-] 無法識別當前作業系統發行版。${NC}"
    exit 1
fi

echo -e "${GREEN}[*] 偵測到作業系統: ${OS_ID} (${PRETTY_NAME:-Linux})${NC}"

# 3. 更新套件清單並安裝核心系統依賴
echo -e "${YELLOW}[*] 正在更新系統套件並安裝系統相依項目...${NC}"
$SUDO apt-get update -y
$SUDO apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libpq-dev \
    libopencc-dev \
    git \
    curl \
    whois \
    dnsutils \
    postgresql \
    postgresql-contrib

# 4. 根據發行版安裝 OSINT 工具
echo -e "${YELLOW}[*] 正在配置 OSINT 核心探測工具...${NC}"
if [ "$OS_ID" = "kali" ]; then
    echo -e "${GREEN}[*] 偵測到 Kali Linux，透過 apt 安裝內建工具集...${NC}"
    $SUDO apt-get install -y theharvester amass dnsrecon
else
    echo -e "${YELLOW}[!] 非 Kali 系統 (如 Ubuntu/Debian)，將自動透過 Go/Git 補充資產探測工具...${NC}"
    # 若需在一般 VPS 上使用 theharvester / amass，提供 apt fallback
    $SUDO apt-get install -y theharvester || true
fi

# 5. 建立專用 Python 虛擬環境 (避免 PEP 668 衝突)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[*] 正在建立 Python 虛擬環境: ${VENV_DIR}...${NC}"
    python3 -m venv "$VENV_DIR"
else
    echo -e "${GREEN}[*] 偵測到現有的虛擬環境，跳過建立。${NC}"
fi

# 啟用虛擬環境
source "$VENV_DIR/bin/activate"

# 升級 pip
pip install --upgrade pip setuptools wheel

# 6. 安裝專案 requirements.txt
if [ -f "$PROJECT_ROOT/backend/requirements.txt" ]; then
    echo -e "${YELLOW}[*] 正在安裝後端相依套件 (requirements.txt)...${NC}"
    pip install -r "$PROJECT_ROOT/backend/requirements.txt"
else
    echo -e "${RED}[-] 找不到 backend/requirements.txt，請確認專案目錄結構。${NC}"
fi

# 7. 安裝第三方開源 OSINT CLI 工具
echo -e "${YELLOW}[*] 正在安裝/更新 Maigret 與 Holehe...${NC}"
pip install --upgrade maigret holehe

# 8. 自動初始化 PostgreSQL 本地資料庫與使用者
echo -e "${YELLOW}[*] 正在配置本地 PostgreSQL 資料庫...${NC}"
$SUDO service postgresql start || true

# 建立 osint_user 與 osint_db (若尚未存在)
$SUDO -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = 'osint_user'" | grep -q 1 || \
$SUDO -u postgres psql -c "CREATE USER osint_user WITH PASSWORD 'osint_password';"

$SUDO -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'osint_db'" | grep -q 1 || \
$SUDO -u postgres psql -c "CREATE DATABASE osint_db OWNER osint_user;"

$SUDO -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE osint_db TO osint_user;"

# 9. 檢查並產生 .env 設定檔
ENV_FILE="$PROJECT_ROOT/backend/.env"
ENV_EXAMPLE="$PROJECT_ROOT/backend/.env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        echo -e "${YELLOW}[*] 生成 backend/.env 設定檔...${NC}"
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        
        # 自動生成一組安全的隨機 APP_SECRET
        RANDOM_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        sed -i "s/your-super-secret-key-change-it-in-production/${RANDOM_SECRET}/g" "$ENV_FILE" || true
        echo -e "${GREEN}[+] 已自動為 .env 產生隨機 APP_SECRET${NC}"
    else
        echo -e "${YELLOW}[!] 建立基本 backend/.env...${NC}"
        cat <<EOF > "$ENV_FILE"
DATABASE_URL=postgresql+asyncpg://osint_user:osint_password@localhost:5432/osint_db
DEBUG=True
APP_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
GEMINI_API_KEY=
OPENAI_API_KEY=
EOF
    fi
fi

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}    ✅ OSINT Platform 安裝完成！                     ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "你可以依照以下步驟啟動系統："
echo -e ""
echo -e "  1. 啟用環境:  ${BLUE}source venv/bin/activate${NC}"
echo -e "  2. 啟動服務:  ${BLUE}uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload${NC}"
echo -e "  3. 開啟網頁:  ${BLUE}http://localhost:8000${NC}"
echo -e "  4. 預設帳密:  ${YELLOW}admin / admin123${NC}"
echo -e ""
echo -e "${YELLOW}[提示] 若需啟用 AI 分析功能，請至 backend/.env 填入 GEMINI_API_KEY。${NC}"
