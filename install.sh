#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  DIS-CORE — Device Intelligence System                         ║
# ║  One-Line Installer · Auto-OS-Detect · IrsanAI Stack           ║
# ║  github.com/IrsanAI/dis-core                                   ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'
RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🛡️  DIS — Device Intelligence System               ║${NC}"
echo -e "${CYAN}║  IrsanAI Stack Installer v1.0                       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

detect_os() {
  if [ -d "/data/data/com.termux" ] || echo "$PREFIX" | grep -q "termux"; then
    echo "termux"
  elif [ "$(uname)" = "Darwin" ]; then echo "macos"
  elif [ "$(uname)" = "Linux" ]; then echo "linux"
  else echo "unknown"; fi
}

OS=$(detect_os)
echo -e "→ Detected OS: ${GREEN}$OS${NC}"

install_node() {
  if command -v node &>/dev/null; then
    echo -e "→ Node.js: ${GREEN}$(node --version)${NC}"; return
  fi
  echo -e "→ Installing Node.js..."
  if [ "$OS" = "termux" ]; then
    pkg update -y && pkg install -y nodejs
  elif [ "$OS" = "macos" ]; then
    brew install node
  elif [ "$OS" = "linux" ]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
  fi
}

install_git() {
  if command -v git &>/dev/null; then
    echo -e "→ Git: ${GREEN}$(git --version)${NC}"; return
  fi
  if [ "$OS" = "termux" ]; then pkg install -y git
  elif [ "$OS" = "linux" ]; then sudo apt install -y git; fi
}

echo -e "${YELLOW}[1/4] Dependencies...${NC}"; install_git; install_node
echo -e "${YELLOW}[2/4] npm install...${NC}";  npm install
echo -e "${YELLOW}[3/4] Building dashboard...${NC}"; npm run build
echo -e "${YELLOW}[4/4] Done!${NC}"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅  DIS-CORE ready!                            ║${NC}"
echo -e "${GREEN}║  Start : node server.js                         ║${NC}"
echo -e "${GREEN}║  Open  : http://localhost:3001                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo -e "→ Run: ${CYAN}node server.js${NC}"
