#!/bin/bash
# setup.sh — One-shot environment bootstrap for OverflowGuard v9.0
set -e

echo "🛡️  Configuring OverflowGuard v9.0 Environment..."
echo ""

# ── System dependencies ───────────────────────────────────────────────────────
echo "[*] Installing system toolchains..."
sudo apt-get update -qq
sudo apt-get install -y \
    gcc g++ \
    cppcheck clang-tidy \
    clang llvm \
    afl++ bear \
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

# ── Semgrep (multi-language SAST) ─────────────────────────────────────────────
echo "[*] Installing semgrep (multi-language SAST)..."
.venv/bin/pip install semgrep -q

# ── v9.0: tree-sitter grammars (real AST parsing for 11 languages) ────────────
echo "[*] Installing tree-sitter + language grammars (v9.0)..."
.venv/bin/pip install -q \
    tree-sitter \
    tree-sitter-c tree-sitter-cpp tree-sitter-python \
    tree-sitter-java tree-sitter-go tree-sitter-rust \
    tree-sitter-javascript tree-sitter-typescript \
    tree-sitter-php tree-sitter-ruby tree-sitter-c-sharp

# ── v9.0: Z3 SMT solver (symbolic execution with counterexamples) ─────────────
echo "[*] Installing Z3 SMT solver (v9.0)..."
.venv/bin/pip install -q z3-solver

# ── Facebook Infer (optional — manual install required) ───────────────────────
echo "[i] Facebook Infer is optional. Install from: https://fbinfer.com/docs/getting-started"

# ── Project directories ───────────────────────────────────────────────────────
mkdir -p results
mkdir -p ~/.overflowguard          # trusted ML model store (ml_filter.py)

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
echo ""
echo "    v9.0 real analysis engines are installed (tree-sitter + Z3)."
echo ""
echo "    Optional — install ML false-positive filter:"
echo "      pip install scikit-learn"
echo "    Optional — install angr concolic engine (~1 GB):"
echo "      pip install angr"
