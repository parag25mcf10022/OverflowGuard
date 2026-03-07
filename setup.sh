#!/bin/bash
# setup.sh — One-shot environment bootstrap for OverflowGuard v5.3
set -e

echo "🛡️  Configuring OverflowGuard v5.3 Environment..."
echo ""

# ── System dependencies ───────────────────────────────────────────────────────
echo "[*] Installing system toolchains..."
sudo apt-get update -qq
sudo apt-get install -y \
    gcc g++ \
    cppcheck clang-tidy \
    golang-go \
    rustc cargo \
    openjdk-17-jdk \
    python3-pip python3-venv

# ── Rust Clippy ───────────────────────────────────────────────────────────────
if command -v rustup &> /dev/null; then
    echo "[*] Adding Rust Clippy component..."
    rustup component add clippy
fi

# ── Python virtual environment ────────────────────────────────────────────────
echo "[*] Creating Python virtual environment (.venv)..."
python3 -m venv .venv
echo "[*] Installing Python dependencies..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -r requirements.txt -q

# ── Project directories ───────────────────────────────────────────────────────
mkdir -p results

# ── Environment file ──────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    echo "[*] Created .env from .env.example — edit it to customise settings."
fi

echo ""
echo "[✔] Setup complete."
echo ""
echo "    Activate the environment:"
echo "      source .venv/bin/activate"
echo ""
echo "    Run a scan:"
echo "      python3 main.py"
echo ""
echo "    Run tests:"
echo "      python3 -m pytest tests/ -v"
