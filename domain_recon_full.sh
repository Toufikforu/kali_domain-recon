#!/bin/bash

# Usage check
if [ -z "$1" ]; then
    echo "Usage: ./domain_recon_clean.sh example.com"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="clean_recon_$DOMAIN"
mkdir -p $OUTPUT_DIR

echo "[+] Starting CLEAN recon on $DOMAIN"
echo "[*] Output will be saved in $OUTPUT_DIR"

############################
### WHOIS (Trimmed Info) ###
############################
echo "[+] Getting domain WHOIS..."
whois $DOMAIN | grep -Ei 'Domain Name|Registrar:|Creation Date|Expiry Date|Name Server|Updated Date|Registrar Abuse Contact Email|Registrant Organization|Registrant Country' \
> $OUTPUT_DIR/domain_info.txt

######################
### DNS RECORDS ###
######################
echo "[+] Collecting DNS Records..."
dig NS $DOMAIN +short > $OUTPUT_DIR/ns.txt
dig MX $DOMAIN +short > $OUTPUT_DIR/mx.txt
dig TXT $DOMAIN +short > $OUTPUT_DIR/txt.txt

######################
### Sublist3r ###
######################
echo "[+] Finding subdomains with Sublist3r..."
if [ ! -d "$HOME/tools/Sublist3r" ]; then
    echo "[!] Sublist3r not found. Cloning..."
    git clone https://github.com/aboul3la/Sublist3r.git ~/tools/Sublist3r
    pip install -r ~/tools/Sublist3r/requirements.txt
fi
python3 ~/tools/Sublist3r/sublist3r.py -d $DOMAIN -o $OUTPUT_DIR/subdomains.txt

################################
### Loop Through Subdomains ###
################################
echo "[+] Scanning discovered subdomains..."

while read sub; do
    if [[ ! -z "$sub" ]]; then
        echo "[*] Scanning $sub..."

        # Nmap (open ports summary)
        nmap -sV --top-ports 1000 -T4 $sub | grep -E "open|PORT|Service" > $OUTPUT_DIR/open_ports_$sub.txt

        # WhatWeb (fingerprint web tech only)
        whatweb --log-brief=$OUTPUT_DIR/tech_$sub.txt $sub

        # Nikto (only high priority findings)
        nikto -host $sub | grep -Ei "OSVDB|Server|X-Frame|X-XSS|X-Content|Cookies|insecure|error|admin|dir listing" > $OUTPUT_DIR/nikto_$sub.txt

        # Nuclei (filtering output)
        nuclei -u $sub -severity high,critical -o $OUTPUT_DIR/nuclei_$sub.txt || echo "Nuclei not installed or errored."
    fi
done < $OUTPUT_DIR/subdomains.txt

echo "[✔] Clean recon complete. Results in: $OUTPUT_DIR"
