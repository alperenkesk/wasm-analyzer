package com.wasmanalyzer.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.wasmanalyzer.WasmAnalyzerExtension;
import com.wasmanalyzer.model.WasmCapture;

import java.util.List;
import java.util.regex.Pattern;

public class WasmIssueReporter {

    public void reportFindings(WasmCapture capture) {
        if (capture.requestResponse == null) return;

        if (capture.secrets != null && !capture.secrets.isEmpty()) {
            for (SecretScanner.SecretFinding finding : capture.secrets) {
                AuditIssue issue = buildSecretIssue(capture, finding);
                if (issue != null) {
                    WasmAnalyzerExtension.api.siteMap().add(issue);
                }
            }
        }

        if (capture.securityFindings != null && !capture.securityFindings.isEmpty()) {
            for (WasmSecurityScanner.Finding finding : capture.securityFindings) {
                AuditIssue issue = buildSecurityIssue(capture, finding);
                if (issue != null) {
                    WasmAnalyzerExtension.api.siteMap().add(issue);
                }
            }
        }
    }

    private AuditIssue buildSecretIssue(WasmCapture capture, SecretScanner.SecretFinding finding) {
        String name = "WASM: " + finding.ruleName();
        String contextHtml = buildWatContextHtml(capture.watText, finding.match());

        String detail = "<p>WASM Analyzer discovered a hardcoded secret in the WebAssembly binary served at <b>"
            + htmlEscape(capture.url) + "</b>.</p>"
            + "<h4>Match Details</h4>"
            + "<p><b>Rule:</b> " + htmlEscape(finding.ruleName()) + "</p>"
            + "<p><b>Severity:</b> " + finding.severity() + "</p>"
            + "<p><b>Matched Value:</b> <code>" + htmlEscape(finding.match()) + "</code></p>"
            + "<p><b>Context:</b> <code>" + htmlEscape(finding.context()) + "</code></p>"
            + contextHtml
            + "<h4>Vulnerability Classifications</h4>"
            + "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/798.html\">CWE-798: Use of Hard-coded Credentials</a></p>"
            + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/\">A07:2021 — Identification and Authentication Failures</a></p>"
            + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/\">A05:2021 — Security Misconfiguration</a></p>"
            + "<h4>Impact</h4>"
            + "<p>Hardcoded secrets in WASM binaries are trivially extractable. "
            + "Anyone with browser DevTools can decompile the WASM and retrieve credentials, "
            + "API keys, or tokens. This can lead to:</p>"
            + "<ul>"
            + "<li>Unauthorized access to third-party services (AWS, Stripe, GitHub, etc.)</li>"
            + "<li>Account takeover on external platforms</li>"
            + "<li>Financial fraud through paid API abuse</li>"
            + "<li>Data breaches via compromised service accounts</li>"
            + "</ul>";
        String remediation = "<p>Remove hardcoded secrets from client-side WASM binaries immediately. "
            + "Recommended approaches:</p>"
            + "<ol>"
            + "<li>Move secrets to server-side environment variables</li>"
            + "<li>Use a Backend-for-Frontend (BFF) pattern — the client requests a short-lived token from your server</li>"
            + "<li>If a secret must be client-side, use a secure vault service with short expiration and rotation</li>"
            + "<li>Rotate the exposed secret immediately</li>"
            + "</ol>";
        String background = "<p>WebAssembly binaries (.wasm) are compiled from C/C++/Rust/Go and other languages. "
            + "Unlike JavaScript, WASM was historically considered harder to reverse-engineer, "
            + "but modern tools (wasm2wat, wasm-decompile, browser DevTools) make decompilation trivial. "
            + "Any string or constant embedded at compile time is visible in the binary's data sections.</p>"
            + "<p>Attackers can right-click → Inspect in any browser, open the Sources panel, "
            + "find the .wasm file, and click \"Pretty Print\" to see the decompiled WAT with all embedded strings.</p>";
        String remediationBackground = "<p>Secrets should never be embedded in client-side code regardless of the format "
            + "(JS, WASM, source maps, etc.). The industry best practice is to serve secrets dynamically "
            + "from a backend API with proper authentication and rate limiting.</p>";

        HttpRequestResponse rr = capture.requestResponse;
        AuditIssueSeverity severity = mapSecretSeverity(finding.severity());

        return AuditIssue.auditIssue(
            name, detail, remediation, capture.url,
            severity, AuditIssueConfidence.CERTAIN,
            background, remediationBackground, severity,
            rr
        );
    }

    private AuditIssue buildSecurityIssue(WasmCapture capture, WasmSecurityScanner.Finding finding) {
        String name = "WASM: " + finding.title();
        String riskHtml = riskHtml(finding.id());
        String contextHtml = buildWatContextHtml(capture.watText, finding.evidence());

        String detail = "<p>WASM Analyzer detected a security issue in the WebAssembly binary served at <b>"
            + htmlEscape(capture.url) + "</b>.</p>"
            + "<h4>Issue Details</h4>"
            + "<p><b>ID:</b> " + finding.id() + "</p>"
            + "<p><b>Severity:</b> " + finding.severity() + "</p>"
            + "<p><b>Description:</b> " + finding.description() + "</p>"
            + "<p><b>Evidence:</b> <code>" + htmlEscape(finding.evidence()) + "</code></p>"
            + contextHtml
            + "<h4>Vulnerability Classifications</h4>"
            + classificationsHtml(finding.id())
            + "<h4>Risk Assessment</h4>"
            + riskHtml;
        String remediation = "<p>Recommended fix:</p><p>" + finding.recommendation() + "</p>";
        String background = "<p>WebAssembly binaries can contain security vulnerabilities "
            + "including hardcoded endpoints, weak cryptography, dangerous imports, "
            + "memory corruption risks, and client-side authorization bypass checks. "
            + "The WASM Analyzer extension performs static analysis to identify these risks. "
            + "Since WASM runs client-side with user-controlled execution, any security logic "
            + "in the binary can be bypassed by determined attackers.</p>";
        String remediationBackground = "<p>Review each finding in the context of your application. "
            + "Security decisions should be enforced on the server-side, not in client-side WASM code. "
            + "Ensure third-party WASM modules are sourced from trusted maintainers "
            + "and consider using Subresource Integrity (SRI) checks for loaded WASM modules.</p>";

        HttpRequestResponse rr = capture.requestResponse;
        AuditIssueSeverity severity = mapSecuritySeverity(finding.severity());

        return AuditIssue.auditIssue(
            name, detail, remediation, capture.url,
            severity, AuditIssueConfidence.FIRM,
            background, remediationBackground, severity,
            rr
        );
    }

    private String buildWatContextHtml(String wat, String evidence) {
        if (wat == null || wat.isEmpty() || evidence == null || evidence.isEmpty())
            return "";

        String[] lines = wat.split("\n", -1);
        String evidenceEsc = Pattern.quote(evidence.trim());
        Pattern p;
        try {
            p = Pattern.compile(evidenceEsc, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return "";
        }

        for (int i = 0; i < lines.length; i++) {
            if (p.matcher(lines[i]).find()) {
                int start = Math.max(0, i - 5);
                int end = Math.min(lines.length, i + 6);
                StringBuilder ctx = new StringBuilder();
                ctx.append("<h4>WAT Code Context</h4>");
                ctx.append("<pre>");
                for (int j = start; j < end; j++) {
                    String marker = (j == i) ? "&gt; " : "  ";
                    ctx.append(String.format("%s%4d: %s%n", marker, j + 1, htmlEscape(lines[j])));
                }
                ctx.append("</pre>");
                return ctx.toString();
            }
        }
        return "";
    }

    private String classificationsHtml(String findingId) {
        return switch (findingId) {
            case "HARDCODE_SECRET" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/798.html\">CWE-798: Use of Hard-coded Credentials</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/\">A07:2021 — Identification and Authentication Failures</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/\">A05:2021 — Security Misconfiguration</a></p>";
            case "WEAK_CRYPTO" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/327.html\">CWE-327: Use of a Broken or Risky Cryptographic Algorithm</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/\">A02:2021 — Cryptographic Failures</a></p>";
            case "SOURCEMAP_LEAK" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/540.html\">CWE-540: Information Exposure Through Source Code</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A01_2021-Broken_Access_Control/\">A01:2021 — Broken Access Control</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/\">A05:2021 — Security Misconfiguration</a></p>";
            case "INTERNAL_ENDPOINT" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/200.html\">CWE-200: Information Exposure</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A01_2021-Broken_Access_Control/\">A01:2021 — Broken Access Control</a></p>";
            case "DANGEROUS_IMPORT" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/1104.html\">CWE-1104: Use of Unmaintained Third Party Components</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/\">A06:2021 — Vulnerable and Outdated Components</a></p>";
            case "MEMORY_CORRUPTION" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/119.html\">CWE-119: Memory Buffer Errors</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A04_2021-Insecure_Design/\">A04:2021 — Insecure Design</a></p>";
            case "INJECTION_TARGET" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/94.html\">CWE-94: Code Injection</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A03_2021-Injection/\">A03:2021 — Injection</a></p>";
            case "CLIENT_BYPASS" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/602.html\">CWE-602: Client-Side Enforcement of Server-Side Security</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A04_2021-Insecure_Design/\">A04:2021 — Insecure Design</a></p>";
            case "STACKTRACE_LEAK" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/209.html\">CWE-209: Information Exposure Through an Error Message</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/\">A05:2021 — Security Misconfiguration</a></p>";
            case "DEBUG_SYMBOLS" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/489.html\">CWE-489: Debug File</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/\">A05:2021 — Security Misconfiguration</a></p>";
            case "LARGE_MEMORY" ->
                "<p><b>CWE:</b> <a href=\"https://cwe.mitre.org/data/definitions/770.html\">CWE-770: Allocation of Resources Without Limits or Throttling</a></p>"
                + "<p><b>OWASP Top 10 2021:</b> <a href=\"https://owasp.org/Top10/A04_2021-Insecure_Design/\">A04:2021 — Insecure Design</a></p>";
            default -> "<p><b>CWE:</b> N/A</p><p><b>OWASP Top 10 2021:</b> N/A</p>";
        };
    }

    private String riskHtml(String findingId) {
        return switch (findingId) {
            case "HARDCODE_SECRET" -> "<p>Attackers can extract hardcoded secrets by decompiling the WASM binary "
                + "using browser DevTools or wasm2wat. This can lead to account takeover, "
                + "data breach, or unauthorized API access with financial implications.</p>";
            case "WEAK_CRYPTO" -> "<p>Weak cryptographic algorithms (MD5, RC4, DES) are computationally "
                + "cheap to break. An attacker can reverse or forge cryptographically protected data. "
                + "Collision attacks on MD5/SHA1 are practical with modern hardware.</p>";
            case "SOURCEMAP_LEAK" -> "<p>Source map files (.wasm.map) recreate the original source code "
                + "with variable names and comments, exposing application logic and business rules "
                + "to anyone who requests the .map file.</p>";
            case "INTERNAL_ENDPOINT" -> "<p>Hardcoded internal IPs and endpoints reveal network topology. "
                + "Attackers can target internal services directly (SSRF-like impact) or use the "
                + "endpoint as a pivot point for deeper exploitation.</p>";
            case "DANGEROUS_IMPORT" -> "<p>Imported functions like emscripten_*, WASI syscalls, or native "
                + "bindings can cause memory corruption or arbitrary behavior if called with crafted "
                + "inputs. These are gateways to the host system.</p>";
            case "MEMORY_CORRUPTION" -> "<p>Unsigned memory loads (i32.load8_u, i64.load8_u) without "
                + "explicit bounds checking can read out-of-bounds memory. This can lead to "
                + "information disclosure or control flow hijacking in vulnerable runtimes.</p>";
            case "INJECTION_TARGET" -> "<p>Dynamic calls (call_indirect, table.set/get) can be exploited "
                + "to hijack control flow by manipulating the function table. An attacker who can "
                + "control the table index can redirect execution to arbitrary function pointers.</p>";
            case "CLIENT_BYPASS" -> "<p>Client-side authorization checks running in WASM can be patched "
                + "or bypassed trivially. An attacker can modify the binary, hook the function via "
                + "JavaScript, or replace the WASM module entirely to bypass restrictions.</p>";
            case "STACKTRACE_LEAK" -> "<p>Error messages containing file paths, line numbers, or stack "
                + "traces reveal internal application structure. This information helps attackers "
                + "understand the codebase and identify additional vulnerabilities.</p>";
            case "DEBUG_SYMBOLS" -> "<p>Debug/test exports expose internal function names and potential "
                + "attack surface. They indicate a production build that retains debugging artifacts, "
                + "suggesting poor security practices.</p>";
            case "LARGE_MEMORY" -> "<p>Excessive memory allocations can cause denial of service by "
                + "exhausting browser or system memory. Users' browsers may crash or become "
                + "unresponsive when loading the WASM module.</p>";
            default -> "<p>Review the finding in the context of your specific application to assess "
                + "the actual business impact.</p>";
        };
    }

    private AuditIssueSeverity mapSecretSeverity(SecretScanner.Severity s) {
        return switch (s) {
            case CRITICAL -> AuditIssueSeverity.HIGH;
            case HIGH     -> AuditIssueSeverity.MEDIUM;
            case MEDIUM   -> AuditIssueSeverity.LOW;
            case LOW      -> AuditIssueSeverity.INFORMATION;
        };
    }

    private AuditIssueSeverity mapSecuritySeverity(WasmSecurityScanner.Severity s) {
        return switch (s) {
            case CRITICAL -> AuditIssueSeverity.HIGH;
            case HIGH     -> AuditIssueSeverity.MEDIUM;
            case MEDIUM   -> AuditIssueSeverity.LOW;
            case LOW      -> AuditIssueSeverity.INFORMATION;
            case INFO     -> AuditIssueSeverity.INFORMATION;
        };
    }

    private String htmlEscape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
