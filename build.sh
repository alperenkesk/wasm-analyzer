#!/bin/bash
# WASM Analyzer - Build Script
# Usage: ./build.sh [path-to-burp-jar]
# If no path given, auto-detects macOS/Linux Burp installation.

set -e

BURP_JAR="${1:-}"

# Auto-detect
if [ -z "$BURP_JAR" ]; then
    for candidate in \
        "/Applications/Burp Suite Community Edition.app/Contents/Resources/app/burpsuite_community.jar" \
        "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar" \
        "$HOME/BurpSuitePro/burpsuite_pro.jar" \
        "$HOME/BurpSuiteCommunity/burpsuite_community.jar" \
        "/opt/BurpSuitePro/burpsuite_pro.jar"; do
        if [ -f "$candidate" ]; then
            BURP_JAR="$candidate"
            echo "[*] Found: $BURP_JAR"
            break
        fi
    done
fi

if [ -z "$BURP_JAR" ] || [ ! -f "$BURP_JAR" ]; then
    echo "[!] Burp jar bulunamadı."
    echo "    Kullanım: ./build.sh /path/to/burpsuite_community.jar"
    echo ""
    echo "    macOS Community için tipik konum:"
    echo "    /Applications/Burp Suite Community Edition.app/Contents/Resources/app/burpsuite_community.jar"
    exit 1
fi

echo "[*] Burp jar: $BURP_JAR"
echo "[*] Derleniyor..."
mkdir -p target/classes

find src/main/java -name "*.java" > /tmp/wasm_sources.txt

javac --release 17 \
    -cp "$BURP_JAR" \
    -d target/classes \
    @/tmp/wasm_sources.txt

echo "[*] JAR paketleniyor..."
printf 'Manifest-Version: 1.0\nBurp-Extension-Class: com.wasmanalyzer.WasmAnalyzerExtension\n\n' > /tmp/WASM_MF.txt

jar cfm wasm-analyzer.jar /tmp/WASM_MF.txt -C target/classes com/

echo ""
echo "[✓] wasm-analyzer.jar hazır ($(ls -lh wasm-analyzer.jar | awk '{print $5}'))"
echo ""
echo "Burp'e yüklemek için:"
echo "  Extensions → Add → Java → wasm-analyzer.jar seç"
