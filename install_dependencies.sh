#!/usr/bin/env bash
"""
WebStrike Studio — Core Dependency Installer
===========================================
Automates the system setup, repository sourcing, package management,
and module tracking required to execute all orchestrated testing frameworks.

Usage:
  chmod +x install_dependencies.sh
  sudo ./install_dependencies.sh
"""

# Enforce root execution contexts for package deployments
if [ "$EUID" -ne 0 ]; then
  echo -e "\e[31m[-] Error: Please run this installation script using sudo or root privileges.\e[0m"
  exit 1
fi

echo -e "\e[34m[*] Starting WebStrike Studio Core Architecture Installation Suite...\e[0m"
echo -e "\e[34m[*] Syncing operating system package distributions...\e[0m"

# Update package mappings
apt-get update -y && apt-get upgrade -y

# 1. Install Base Packages, Python Elements, and Compilers
echo -e "\e[32m[+] Installing core runtime dependencies & interpreters...\e[0m"
apt-get install -y \
    python3 \
    python3-pip \
    python3-tk \
    golang-go \
    libpcap-dev \
    curl \
    git \
    build-essential

# 2. Deploy Python Module Layer via Pip
echo -e "\e[32m[+] Configuring required Python modules...\e[0m"
# reportlab handles the programmatic reference manual output generation
python3 -m pip install --upgrade pip
python3 -m pip install reportlab --break-system-packages --quiet

# 3. Native Apt Package Security Implementations
echo -e "\e[32m[+] Installing stable repository distribution tools...\e[0m"
apt-get install -y \
    nmap \
    sslscan \
    testssl.sh \
    dirb \
    gobuster \
    ffuf \
    nikto \
    sqlmap \
    commix \
    whatweb \
    wafw00f \
    wapiti

# 4. Compiling & Fetching Advanced Go Binaries (Katana, Naabu, Nuclei)
echo -e "\e[32m[+] Compiling project-discovery automation binaries via Go modules...\e[0m"
export GOPATH=/usr/local/share/go
export GOBIN=/usr/local/bin

# Install tool wrappers globally to system bin paths
echo "[*] Fetching naabu port scanner..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
echo "[*] Fetching nuclei vulnerability assessment framework..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo "[*] Fetching katana spider engine..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# 5. Installing Modern Content Discovery Frameworks (Feroxbuster)
if ! command -v feroxbuster &> /dev/null; then
    echo -e "\e[32m[+] Deploying Feroxbuster tracking binaries via curl script...\e[0m"
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash -s /usr/local/bin
else
    echo -e "\e[34m[*] Feroxbuster already present. Skipping installation path.\e[0m"
fi

# Verify dynamic configuration
echo -e "\e[34m------------------------------------------------------------------\e[0m"
echo -e "\e[32m[+] Deployment complete, Sandy! WebStrike Studio environment is locked.\e[0m"
echo -e "\e[34m[*] Execute 'python3 webstrike_studio.py' to run the orchestrator.\e[0m"
