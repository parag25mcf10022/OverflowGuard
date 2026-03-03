#!/bin/bash
echo "🛡️  Configuring Polyglot Overflow Guard v5.2 Environment..."

# Update and install System Toolchains
sudo apt update
sudo apt install -y gcc g++ flawfinder python3-pip golang-go rustc cargo openjdk-17-jdk

# Install Python Security Dependencies
# Using --break-system-packages for modern Debian-based distros (Parrot/Kali)
pip3 install colorama bandit --break-system-packages

# Configure Rust Security Components
if command -v rustup &> /dev/null
	then
	echo "[*] Adding Rust Clippy component..."
	rustup component add clippy
	else
		echo "[!] rustup not found, attempting to install clippy via apt..."
		sudo apt install -y clippy
		fi
		
		# Create necessary project directories
		mkdir -p results
		mkdir -p samples
		
		echo -e "\n[✔] Environment configured successfully."
		echo "[*] You can now run the tool using: python3 main.py"
