#!/bin/sh
# Lab Scenario 3: Namespace Pivot & Container Boundary Manipulation
# Simulates: Invoking setns or unshare to escape container namespace baseline

echo "[*] Step 1: Inspecting current container namespace inodes..."
ls -l /proc/self/ns/

echo "[*] Step 2: Attempting namespace unshare (network + mount)..."
unshare -n -m /bin/sh -c '
    echo "[*] Subshell running inside modified namespace"
' 2>/dev/null || true

echo "[+] Scenario 3 complete."
