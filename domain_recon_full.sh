#!/bin/bash

# Usage Check
if [ -z "$1" ]; then
    echo "Usage: ./domain_recon_full.sh example.com"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="recon_$DOMAIN"
mkdir -p $OUTPUT_DIR

echo "[+] Starting full recon on $DOMAIN"
echo "[*] Saving output in $OUTPUT_DIR"

# WHOIS
echo "[+] WHOIS Lookup..."
whois $DOMAIN > $OUTPUT_DIR/whois.txt

# DIG
echo "[+] DNS Records with dig..."
dig $DOMAIN ANY +noall +answer > $OUTPUT_DIR/dns_any.txt
dig NS $DOMAIN +short > $OUTPUT_DIR/ns.txt
dig MX $DOMAIN +short > $OUTPUT_DIR/mx.txt
dig TXT $DOMAIN +short > $OUTPUT_DIR/txt.txt

# DNSRecon
echo "[+] Running dnsrecon..."
dnsrecon -d $DOMAIN -a > $OUTPUT_DIR/dnsrecon.txt

# Sublist3r
echo "[+] Running Sublist3r..."
if [ ! -d "$HOME/tools/Sublist3r" ]; then
    echo "[!] Sublist3r not found. Cloning..."
    git clone https://github.com/aboul3la/Sublist3r.git ~/tools/Sublist3r
    pip install -r ~/tools/Sublist3r/requirements.txt
fi
python3 ~/tools/Sublist3r/sublist3r.py -d $DOMAIN -o $OUTPUT_DIR/subdomains.txt

# Loop through subdomains
while read sub; do
    if [[ ! -z "$sub" ]]; then
        echo -e "\n[***] Scanning $sub ..."

        # Nmap
        echo "[+] Nmap scan (top ports)..."
        nmap -sV --top-ports 1000 -T4 $sub -oN $OUTPUT_DIR/nmap_$sub.txt

        # WhatWeb
        echo "[+] Running WhatWeb..."
        whatweb --log-verbose=$OUTPUT_DIR/whatweb_$sub.txt $sub

        # Nikto
        echo "[+] Running Nikto..."
        nikto -host $sub -o $OUTPUT_DIR/nikto_$sub.txt

        # Nuclei (make sure nuclei is installed)
        echo "[+] Running Nuclei..."
        nuclei -u $sub -o $OUTPUT_DIR/nuclei_$sub.txt || echo "Nuclei not installed or errored."
    fi
done < $OUTPUT_DIR/subdomains.txt

echo "[✔] Recon complete. All results saved in: $OUTPUT_DIR"
