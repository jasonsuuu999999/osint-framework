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
echo -e "${BLUE}    🚀 OSINT Platform One-Click Installation and Initialization Script       ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. Check root / sudo Permissions
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
    if ! command -v sudo &> /dev/null; then
        echo -e "${RED}[-] Please execute this script with root privileges, or ensure that sudo is installed on your system.${NC}"
        exit 1
    fi
else
    SUDO=""
fi

# 2. Identifying Linux Version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=${ID:-unknown}
else
    echo -e "${RED}[-] Unable to identify the current operating system version. ${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Detected operating system: ${OS_ID}${NC}"

# 3. Update the package list and install core system dependencies.
echo -e "${YELLOW}[*] Updating system packages and installing dependent projects...${NC}"
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

# 4. Install additional Kali tools and dictionaries
echo -e "${YELLOW}[*] Installing extended security and OSINT toolsets(SecLists, theHarvester, amass, sublist3r)...${NC}"
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

# 5. Create Python virtual environment
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[*] Setting up Python virtual environment: ${VENV_DIR}...${NC}"
    python3 -m venv "$VENV_DIR"
else
    echo -e "${GREEN}[*] An existing virtual environment was detected; the creation process was skipped. ${NC}"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip setuptools wheel

# 6. Install requirements.txt
if [ -f "$PROJECT_ROOT/backend/requirements.txt" ]; then
    echo -e "${YELLOW}[*] Installing backend dependency packages (requirements.txt)...${NC}"
    pip install -r "$PROJECT_ROOT/backend/requirements.txt"
fi

# 7. Install third-party open-source CLI tools
echo -e "${YELLOW}[*] Installing/updating Maigret, Holehe, Sherlock...${NC}"
pip install --upgrade maigret holehe sherlock-project || true

# 8. Configure a local PostgreSQL database
echo -e "${YELLOW}[*] Configuring the local PostgreSQL database...${NC}"
$SUDO service postgresql start || true

$SUDO -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = 'osint_user'" | grep -q 1 || \
$SUDO -u postgres psql -c "CREATE USER osint_user WITH PASSWORD 'osint_password';"

$SUDO -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'osint_db'" | grep -q 1 || \
$SUDO -u postgres psql -c "CREATE DATABASE osint_db OWNER osint_user;"

$SUDO -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE osint_db TO osint_user;"

# 9. Check and generate .env
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
    echo -e "${GREEN}[+] backend/.env has been initialized. ${NC}"
fi

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}    ✅ OSINT Platform installation complete！                     ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "Startup cmd:"
echo -e "  1. source venv/bin/activate"
echo -e "  2. PYTHONPATH=backend python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
echo -e "Or excution background:"
echo -e "  2. nohup env PYTHONPATH=backend python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > osint_server.log 2>&1 &"
