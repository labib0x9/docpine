#!/bin/sh
# Lab Scenario 5: Benign High-Volume Workload (False Positive Validation)
# Simulates: A legitimate developer build reading hundreds of source files and compiling

echo "[*] Creating temporary build workspace..."
mkdir -p /tmp/build_workload
cd /tmp/build_workload

echo "[*] Writing 100 source files..."
for i in $(seq 1 100); do
    echo "package main; func Helper$i() int { return $i }" > "file_$i.go"
done

echo "[*] Compiling workload..."
cat << 'EOF' > main.go
package main
import "fmt"
func main() { fmt.Println("Build successful") }
EOF

# Normal execution
ls -la > /dev/null
rm -rf /tmp/build_workload

echo "[+] Scenario 5 (Benign Workload) complete."
