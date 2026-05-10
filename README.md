# WASM Analyzer

**A comprehensive WebAssembly analysis and security scanning tool for Burp Suite**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://opensource.org/licenses/GPL-3.0)
[![Java Version](https://img.shields.io/badge/Java-17+-green.svg)](https://www.java.com/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2023.1%2B-orange.svg)](https://portswigger.net/burp)

WASM Analyzer is a Burp Suite extension that enables security researchers and developers to analyze, disassemble, and audit WebAssembly binaries found in HTTP traffic.

## 🌟 Features

### Core Functionality
- **Automatic WASM Detection** — Detects WASM payloads via magic bytes, URL patterns, and Base64 encoding
- **Pure Java Parser** — No external dependencies; works out of the box
- **WAT Disassembly** — Converts WASM binaries to WebAssembly Text Format (WAT)
- **HTTP Traffic Interception** — Captures WASM in both request and response directions

### Security Analysis
- **Vulnerability Scanner** — 10+ WASM-specific security rules (CRITICAL, HIGH, MEDIUM, LOW)
- **Secret Detection** — Scans for credentials, API keys, tokens, and sensitive data
- **Client-Side Bypass Detection** — Identifies functions that can be exploited for auth bypass
- **Source Map Probing** — Automatically probes for `.wasm.map` files

### Integration
- **Message Editor Tab** — View WASM analysis directly in request/response tabs
- **Context Menu** — Right-click to send any WASM payload to the analyzer
- **Export Capabilities** — Save analyzed WASM binaries and WAT disassembly

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/alperenkeskin/wasm-analyzer.git
cd wasm-analyzer

# Build the JAR
mvn clean package

# The JAR will be at: target/wasm-analyzer.jar
```

### From Release

1. Download the latest `wasm-analyzer.jar` from [Releases](../../releases)
2. Open Burp Suite → **Extender** → **Add**
3. Select the downloaded JAR

## 🚀 Quick Start

### 1. Automatic Capture

When WASM traffic passes through Burp's proxy, the extension automatically:
1. Captures the WASM binary
2. Parses section structure
3. Generates WAT disassembly
4. Scans for secrets and vulnerabilities
5. Probes for source maps

Results appear in the **WASM Analyzer** tab.

### 2. Manual Analysis

Right-click on any request/response containing WASM and select **Send to WASM Analyzer**.

### 3. Message Editor

When viewing a request/response with WASM content, a **WASM** tab appears in the message editor showing:
- **Overview** — Section structure, imports, exports, extracted strings
- **WAT** — WebAssembly Text Format disassembly

## 🔍 Security Rules

The security scanner detects the following vulnerability types:

| Rule | Severity | Description |
|------|:--------:|-------------|
| `HARDCODE_SECRET` | CRITICAL | Hardcoded API keys, secrets, or credentials |
| `INJECTION_TARGET` | CRITICAL | Dynamic function calls (call_indirect) — potential injection |
| `WEAK_CRYPTO` | HIGH | Usage of MD5, RC4, DES, SHA-1 |
| `SOURCEMAP_LEAK` | HIGH | `.wasm.map` reference — source code exposure risk |
| `MEMORY_CORRUPTION` | HIGH | Unsigned memory loads without bounds checking |
| `CLIENT_BYPASS` | HIGH | Functions like `is_admin`, `has_access` — client-side auth checks |
| `INTERNAL_ENDPOINT` | MEDIUM | Hardcoded internal IPs or API endpoints |
| `DANGEROUS_IMPORT` | MEDIUM | Dangerous native function imports |
| `STACKTRACE_LEAK` | MEDIUM | Error messages revealing application structure |
| `DEBUG_SYMBOLS` | LOW | Debug or test functions exported |
| `LARGE_MEMORY` | MEDIUM | Excessive memory allocation (>256 pages) |

### Secret Scanner Rules

| Rule | Severity | Description |
|------|:--------:|-------------|
| AWS Access Key | CRITICAL | `AKIA...` pattern |
| AWS Secret Key | CRITICAL | Hardcoded AWS secret |
| Private Key | CRITICAL | PEM-encoded private key header |
| JWT Token | CRITICAL | `eyJ...` JWT format |
| GCP API Key | HIGH | `AIza...` pattern |
| GitHub Token | HIGH | `gh[pousr]_...` pattern |
| Stripe Secret | HIGH | `sk_live_...` pattern |
| Bearer Token | HIGH | `bearer ...` Authorization header |
| Generic API Key | MEDIUM | Common `api_key` patterns |
| Database URL | MEDIUM | Connection strings with credentials |

## 🏗️ Architecture

```
com.wasmanalyzer/
├── WasmAnalyzerExtension.java       # Montoya API entry point
├── detector/
│   └── WasmDetector.java            # WASM payload detection
├── parser/
│   ├── WasmParser.java              # WASM binary section parser
│   ├── WatWriter.java              # Pure-Java WAT decompiler
│   ├── WasmParseResult.java         # Parse result model
│   └── ...                          # Section, import, export models
├── scanner/
│   ├── WasmSecurityScanner.java     # Security vulnerability rules
│   └── SecretScanner.java           # Credential detection
├── handler/
│   └── WasmHttpHandler.java         # HTTP traffic interceptor
├── sourcemap/
│   └── SourceMapProber.java         # .wasm.map probing
├── ui/
│   ├── AnalyzerToolTab.java         # Main suite tab
│   ├── WasmEditorTab.java           # Message editor tab
│   └── WasmContextMenu.java         # Context menu integration
├── patcher/
│   └── WasmPatcher.java            # WASM modification
├── settings/
│   └── ExtensionSettings.java       # User configuration
└── model/
    ├── WasmCapture.java             # Captured WASM model
    └── WasmCaptureStore.java        # Capture storage
```

## 📋 Requirements

| Requirement | Version |
|-------------|---------|
| Burp Suite | 2023.1 or later |
| Java Runtime | 17 or later |
| Build Tool | Maven 3.6+ |

## 🔧 Configuration

### Source Map Probing

Enable or disable automatic `.wasm.map` probing in the Settings tab.

### Export

Save analyzed WASM as:
- `.wasm` — Binary format
- `.wat` — WebAssembly Text Format

## 📄 License

This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html) — see [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 References

- [WebAssembly Specification](https://webassembly.github.io/spec/)
- [Montoya API Documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions)
- [BApp Store Acceptance Criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria)

## 📊 Stats

![Java](https://img.shields.io/badge/Java-17-blue.svg)
![Maven](https://img.shields.io/badge/Maven-3.9-blue.svg)
![Montoya API](https://img.shields.io/badge/Montoya%20API-2023.12-orange.svg)