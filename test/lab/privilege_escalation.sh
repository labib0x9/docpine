#!/bin/sh
# Lab Scenario 2: Privilege Escalation & Capability Elevation Attack
# Simulates: Gaining CAP_SYS_ADMIN / setuid execution and calling mount

echo "[*] Step 1: Checking current capability bitmask..."
capsh --print 2>/dev/null || cat /proc/self/status | grep Cap

echo "[*] Step 2: Attempting unauthorized mount operation..."
mkdir -p /mnt/target
mount -t tmpfs tmpfs /mnt/target 2>/dev/null || true

echo "[+] Scenario 2 complete."
