#!/bin/sh
# Lab Scenario 4: Over-permissioned Container Escape Attempt
# Simulates: Inspecting /proc/kcore and attempting ptrace on host-visible PID

echo "[*] Step 1: Checking host device and memory exposures..."
head -c 64 /proc/kcore 2>/dev/null || true
ls -l /var/run/docker.sock 2>/dev/null || true

echo "[*] Step 2: Attempting process inspection via ptrace..."
strace -p 1 -c -o /tmp/trace.out 2>/dev/null || true

echo "[+] Scenario 4 complete."
