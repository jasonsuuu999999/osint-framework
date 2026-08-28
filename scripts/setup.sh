#!/usr/bin/env bash
# ==============================================================================
# OSINT Platform - One-Click Environment Setup Script
# Supported OS: Kali Linux, Ubuntu 22.04/24.04, Debian 11/12
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
else
    echo -e "${RED}[-] 無法識別當前作業系統發行版。${NC}"
    exit 1
fi

echo -e "${GREEN}[*] 偵測到作業系統: ${OS_ID}${NC}"

# 3. 更新套件清單並安裝核心系統依賴
echo -e "${YELLOW}[*] 正在更新系統套件並安裝相依項目...${NC}"
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
    postgresql-contrib \
    wafw00f \
    nmap \
    whatweb

# 4. 安裝額外 Kali 工具與字典庫
echo -e "${YELLOW}[*] 正在安裝擴充資安與 OSINT 工具集 (SecLists, theHarvester, amass, sublist3r)...${NC}"
if [ "$OS_ID" = "kali" ]; then
    $SUDO apt-get install -y \
        theharvester \
        amass \
        dnsrecon \
        sublist3r \
        gobuster \
        seclists \
        httpx-toolkit || true
else
    $SUDO apt-get install -y theharvester dnsrecon sublist3r || true
fi

# 5. 建立專用 Python 虛擬環境
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[*] 正在建立 Python 虛擬環境: ${VENV_DIR}...${NC}"
    python3 -m venv "$VENV_DIR"
else
    echo -e "${GREEN}[*] 偵測到現有的虛擬環境，跳過建立。${NC}"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip setuptools wheel

# 6. 安裝專案 requirements.txt
if [ -f "$PROJECT_ROOT/backend/requirements.txt" ]; then
    echo -e "${YELLOW}[*] 正在安裝後端相依套件 (requirements.txt)...${NC}"
    pip install -r "$PROJECT_ROOT/backend/requirements.txt"
fi

# 7. 安裝第三方開源 CLI 工具
echo -e "${YELLOW}[*] 正在安裝/更新 Maigret, Holehe, Sherlock...${NC}"
pip install --upgrade maigret holehe sherlock-project || true

# 8. 配置本地 PostgreSQL 資料庫
echo -e "${YELLOW}[*] 正在配置本地 PostgreSQL 資料庫...${NC}"
$SUDO service postgresql start || true

$SUDO -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = 'osint_user'" | grep -q 1 || \
$SUDO -u postgres psql -c "CREATE USER osint_user WITH PASSWORD 'osint_password';"

$SUDO -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'osint_db'" | grep -q 1 || \
$SUDO -u postgres psql -c "CREATE DATABASE osint_db OWNER osint_user;"

$SUDO -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE osint_db TO osint_user;"

# 9. 檢查並產生 .env
ENV_FILE="$PROJECT_ROOT/backend/.env"
ENV_EXAMPLE="$PROJECT_ROOT/backend/.env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        RANDOM_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        sed -i "s/your-super-secret-key-change-it-in-production/${RANDOM_SECRET}/g" "$ENV_FILE" || true
    else
        cat <<EOF > "$ENV_FILE"
DATABASE_URL=postgresql+asyncpg://osint_user:osint_password@localhost:5432/osint_db
DEBUG=True
APP_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
GEMINI_API_KEY=
OPENAI_API_KEY=
EOF
    fi
    echo -e "${GREEN}[+] 已初始化 backend/.env${NC}"
fi

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}    ✅ OSINT Platform 安裝完成！                     ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "啟動指令："
echo -e "  1. source venv/bin/activate"
echo -e "  2. PYTHONPATH=backend python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
