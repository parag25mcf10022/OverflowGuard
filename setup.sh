#!/bin/bash
echo "[*] Installing AFL++ and Security Tools..."
sudo apt update
# Install AFL++ and dependencies
sudo apt install -y gcc build-essential flawfinder python3-pip afl++ 

# Install Python requirements
pip3 install requests colorama --break-system-packages

echo "[+] Setup Complete. AFL++ is ready."
