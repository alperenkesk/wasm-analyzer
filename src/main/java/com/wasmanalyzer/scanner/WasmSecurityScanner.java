package com.wasmanalyzer.scanner;

import com.wasmanalyzer.parser.WasmParseResult;
import com.wasmanalyzer.parser.WasmImport;
import com.wasmanalyzer.parser.WasmExport;

import java.util.*;
import java.util.regex.*;

public class WasmSecurityScanner {

    public enum Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

    public record Finding(
        String id,
        String title,
        String description,
        Severity severity,
        String evidence,
        String recommendation
    ) {}

    private static final Map<String, VulnRule> RULES = new LinkedHashMap<>();

    static {
        RULES.put("HARDCODE_SECRET", new VulnRule(
            "HARDCODE_SECRET", "Hardcoded Secret/Credential",
            "Hardcoded secret or credential detected in WASM binary.",
            Severity.CRITICAL,
            List.of(
                Pattern.compile("['\"][A-Za-z0-9+/]{20,}==['\"]"),
                Pattern.compile("(api[_-]?key|secret|token)\\s*[:=]\\s*['\"][^'\"]{16,}['\"]"),
                Pattern.compile("(bearer|basic)\\s+[A-Za-z0-9+/]{20,}"),
                Pattern.compile("xox[baprs]-[0-9A-Za-z-]{10,}"),
                Pattern.compile("sk_live_|pk_live_|AKIA"),
                Pattern.compile("-----BEGIN.*PRIVATE KEY-----")
            ),
            evidence -> "String: " + evidence.substring(0, Math.min(50, evidence.length())),
            "Hardcoded secrets can be easily extracted. Use environment variables on the server side."
        ));

        RULES.put("WEAK_CRYPTO", new VulnRule(
            "WEAK_CRYPTO", "Weak Cryptographic Usage",
            "Weak or vulnerable cryptographic algorithm usage detected.",
            Severity.HIGH,
            List.of(
                Pattern.compile("\\bMD4\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bMD5\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bSHA-?1\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bRC4\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bDES\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\b3DES\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bECB\\b", Pattern.CASE_INSENSITIVE)
            ),
            evidence -> "Constant: " + evidence,
            "Weak crypto (MD5, RC4, DES) can be easily broken. Use AES-256-GCM or ChaCha20."
        ));

        RULES.put("SOURCEMAP_LEAK", new VulnRule(
            "SOURCEMAP_LEAK", "Source Map Information Leak",
            "Source map reference detected - source code exposure risk.",
            Severity.HIGH,
            List.of(
                Pattern.compile("\\.wasm\\.map", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\.map\\?"),
                Pattern.compile("/src/"),
                Pattern.compile("/lib/"),
                Pattern.compile("/dist/")
            ),
            evidence -> "Reference: " + evidence,
            "Source map files expose source code. Remove .map files in production or block access."
        ));

        RULES.put("INTERNAL_ENDPOINT", new VulnRule(
            "INTERNAL_ENDPOINT", "Internal/Hardcoded Endpoint",
            "Hardcoded internal API endpoint or IP detected.",
            Severity.MEDIUM,
            List.of(
                Pattern.compile("(10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"),
                Pattern.compile("(172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3})"),
                Pattern.compile("(192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3})"),
                Pattern.compile("(localhost|127\\.0\\.0\\.1)"),
                Pattern.compile("/api/v[0-9]+/"),
                Pattern.compile("/internal/"),
                Pattern.compile("/admin/api")
            ),
            evidence -> "Endpoint: " + evidence,
            "Internal endpoints may cause information leakage. Use runtime configuration."
        ));

        RULES.put("DANGEROUS_IMPORT", new VulnRule(
            "DANGEROUS_IMPORT", "Dangerous WASM Import",
            "Potentially dangerous native function imported.",
            Severity.MEDIUM,
            List.of(
                Pattern.compile("env\\.(abort|_abort|exit|_exit)"),
                Pattern.compile("env\\.(emscripten_\\w+)"),
                Pattern.compile("wasi\\.(fd_write|fd_read|proc_exit)"),
                Pattern.compile("env\\.(stack_save|stack_restore|stack_alloc)")
            ),
            evidence -> "Import: " + evidence,
            "These imports may cause memory corruption or crash. Analyze their usage."
        ));

        RULES.put("MEMORY_CORRUPTION", new VulnRule(
            "MEMORY_CORRUPTION", "Potential Memory Corruption",
            "Memory safety checks missing in instructions detected.",
            Severity.HIGH,
            List.of(
                Pattern.compile("memory\\.grow", Pattern.CASE_INSENSITIVE),
                Pattern.compile("memory\\.size", Pattern.CASE_INSENSITIVE),
                Pattern.compile("i32\\.load8_u\\s", Pattern.CASE_INSENSITIVE),
                Pattern.compile("i64\\.load8_u\\s", Pattern.CASE_INSENSITIVE)
            ),
            evidence -> "Instruction in WAT",
            "Unsigned memory loads used without bounds check. Buffer overflow risk."
        ));

        RULES.put("INJECTION_TARGET", new VulnRule(
            "INJECTION_TARGET", "Dynamic Function Call",
            "Dynamic function call detected - injection risk.",
            Severity.CRITICAL,
            List.of(
                Pattern.compile("call_indirect"),
                Pattern.compile("ref\\.func"),
                Pattern.compile("table\\.get"),
                Pattern.compile("table\\.set")
            ),
            evidence -> "Dynamic call pattern found",
            "call_indirect/table manipulation may lead to injection attacks. Validate table index."
        ));

        RULES.put("CLIENT_BYPASS", new VulnRule(
            "CLIENT_BYPASS", "Potential Client-Side Bypass",
            "Function that can be bypassed on the client side detected.",
            Severity.HIGH,
            List.of(
                Pattern.compile("\\bis[_-]?admin\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bhas[_-]?access\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bcan[_-]?(access|admin|write)\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bcheck[_-]?auth\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bverify[_-]?owner\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bvalidate[_-]?role\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bauthorize\\b", Pattern.CASE_INSENSITIVE)
            ),
            evidence -> "Function: " + evidence,
            "These functions may be used for client-side validation. Validate on server side too."
        ));

        RULES.put("STACKTRACE_LEAK", new VulnRule(
            "STACKTRACE_LEAK", "Error/Stack Information Leak",
            "Stack trace or internal information leak risk in error messages.",
            Severity.MEDIUM,
            List.of(
                Pattern.compile("at\\s+[a-zA-Z0-9_.]+[<:]"),
                Pattern.compile("Error:\\s*at\\s*in"),
                Pattern.compile("in\\s+file\\s+"),
                Pattern.compile("line\\s+[0-9]+"),
                Pattern.compile("throw\\s+new\\s+Error\\s*\\(")
            ),
            evidence -> "Pattern: " + evidence,
            "Stack trace information reveals application structure to attackers. Use generic error messages."
        ));

        RULES.put("DEBUG_SYMBOLS", new VulnRule(
            "DEBUG_SYMBOLS", "Debug Symbols Present",
            "Debug symbols or test functions exported.",
            Severity.LOW,
            List.of(
                Pattern.compile("^debug$", Pattern.CASE_INSENSITIVE),
                Pattern.compile("^test$", Pattern.CASE_INSENSITIVE),
                Pattern.compile("_debug$", Pattern.CASE_INSENSITIVE),
                Pattern.compile("_test$", Pattern.CASE_INSENSITIVE),
                Pattern.compile("__test$", Pattern.CASE_INSENSITIVE),
                Pattern.compile("__debug$", Pattern.CASE_INSENSITIVE),
                Pattern.compile("dump\\w*", Pattern.CASE_INSENSITIVE)
            ),
            evidence -> "Export: " + evidence,
            "Debug functions should be removed in production. Provides information to attackers."
        ));

        RULES.put("LARGE_MEMORY", new VulnRule(
            "LARGE_MEMORY", "Excessive Memory Allocation",
            "Excessive memory allocation detected.",
            Severity.MEDIUM,
            null,
            evidence -> "Memory pages: " + evidence,
            "Large memory allocations may cause DoS. Add allocation limits."
        ));
    }

    public List<Finding> scan(WasmParseResult parseResult, List<String> strings, String watText) {
        List<Finding> findings = new ArrayList<>();
        if (parseResult == null) return findings;

        checkImports(parseResult.imports, findings);
        checkExports(parseResult.exports, findings);
        checkStrings(strings, findings, parseResult);
        checkWatPatterns(watText, findings);
        checkMemory(parseResult, findings);
        checkExportCount(parseResult.exports, findings);

        findings.sort(Comparator.comparingInt((Finding f) -> f.severity().ordinal()).reversed());
        return dedupeFindings(findings);
    }

    private void checkImports(List<WasmImport> imports, List<Finding> findings) {
        for (WasmImport imp : imports) {
            String fullName = imp.module + "." + imp.name;
            
            VulnRule rule = RULES.get("DANGEROUS_IMPORT");
            if (rule != null) {
                for (Pattern p : rule.patterns) {
                    if (p.matcher(fullName).find() || p.matcher(imp.name).find()) {
                        addFinding(findings, rule, fullName);
                        break;
                    }
                }
            }
        }
    }

    private void checkExports(List<WasmExport> exports, List<Finding> findings) {
        for (WasmExport exp : exports) {
            String name = exp.name.toLowerCase();
            
            VulnRule clientRule = RULES.get("CLIENT_BYPASS");
            if (clientRule != null) {
                for (Pattern p : clientRule.patterns) {
                    if (p.matcher(exp.name).find() || p.matcher(name).find()) {
                        addFinding(findings, clientRule, exp.name);
                        break;
                    }
                }
            }

            VulnRule debugRule = RULES.get("DEBUG_SYMBOLS");
            if (debugRule != null) {
                for (Pattern p : debugRule.patterns) {
                    if (p.matcher(exp.name).find() || p.matcher(name).find()) {
                        addFinding(findings, debugRule, exp.name);
                        break;
                    }
                }
            }
        }
    }

    private void checkStrings(List<String> strings, List<Finding> findings, WasmParseResult parseResult) {
        if (strings == null) return;

        for (String s : strings) {
            if (s == null || s.length() < 4) continue;

            for (Map.Entry<String, VulnRule> entry : RULES.entrySet()) {
                String ruleId = entry.getKey();
                if (ruleId.equals("LARGE_MEMORY") || ruleId.equals("DEBUG_SYMBOLS")) continue;

                VulnRule rule = entry.getValue();
                if (rule.patterns == null) continue;

                for (Pattern p : rule.patterns) {
                    if (p.matcher(s).find()) {
                        addFinding(findings, rule, s);
                        break;
                    }
                }
            }
        }
    }

    private void checkWatPatterns(String watText, List<Finding> findings) {
        if (watText == null || watText.isEmpty()) return;

        VulnRule memRule = RULES.get("MEMORY_CORRUPTION");
        if (memRule != null) {
            boolean found = false;
            for (Pattern p : memRule.patterns) {
                if (p.matcher(watText).find()) {
                    if (!found) {
                        addFinding(findings, memRule, "memory instructions found in WAT");
                        found = true;
                    }
                    break;
                }
            }
        }

        VulnRule injRule = RULES.get("INJECTION_TARGET");
        if (injRule != null) {
            boolean found = false;
            for (Pattern p : injRule.patterns) {
                if (p.matcher(watText).find()) {
                    if (!found) {
                        addFinding(findings, injRule, "dynamic call pattern in WAT");
                        found = true;
                    }
                    break;
                }
            }
        }
    }

    private void checkMemory(WasmParseResult parseResult, List<Finding> findings) {
        if (parseResult.sections == null) return;

        for (var section : parseResult.sections) {
            if (section.name.equals("memory")) {
                String desc = section.description;
                if (desc.contains("pages")) {
                    try {
                        String num = desc.replaceAll("[^0-9]", "");
                        if (!num.isEmpty() && Integer.parseInt(num) > 256) {
                            VulnRule rule = RULES.get("LARGE_MEMORY");
                            if (rule != null) {
                                addFinding(findings, rule, num + " pages");
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }
        }
    }

    private void checkExportCount(List<WasmExport> exports, List<Finding> findings) {
        if (exports == null) return;
        int count = exports.size();
        
        if (count > 100) {
            VulnRule rule = RULES.get("DEBUG_SYMBOLS");
            if (rule != null && !hasRule(findings, "DEBUG_SYMBOLS")) {
                addFinding(findings, rule, count + " exports (excessive)");
            }
        }
    }

    private void addFinding(List<Finding> findings, VulnRule rule, String evidence) {
        boolean exists = findings.stream()
            .anyMatch(f -> f.id().equals(rule.id) && f.evidence().contains(evidence.substring(0, Math.min(20, evidence.length()))));
        if (!exists) {
            findings.add(new Finding(
                rule.id, rule.title, rule.description,
                rule.severity, rule.formatEvidence.apply(evidence),
                rule.recommendation
            ));
        }
    }

    private boolean hasRule(List<Finding> findings, String id) {
        return findings.stream().anyMatch(f -> f.id().equals(id));
    }

    private List<Finding> dedupeFindings(List<Finding> findings) {
        Map<String, Finding> unique = new LinkedHashMap<>();
        for (Finding f : findings) {
            String key = f.id() + ":" + f.evidence().substring(0, Math.min(30, f.evidence().length()));
            unique.putIfAbsent(key, f);
        }
        return new ArrayList<>(unique.values());
    }

    private record VulnRule(
        String id,
        String title,
        String description,
        Severity severity,
        List<Pattern> patterns,
        java.util.function.Function<String, String> formatEvidence,
        String recommendation
    ) {}
}