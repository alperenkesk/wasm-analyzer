package com.wasmanalyzer.scanner;

import java.util.*;
import java.util.regex.*;

public class SecretScanner {

    public enum Severity { CRITICAL, HIGH, MEDIUM, LOW }

    public record SecretFinding(
        String ruleName,
        Severity severity,
        String match,
        String context
    ) {}

    // Max combined string length to scan — prevents OOM on multi-MB Unity/Blazor wasm
    private static final int MAX_SCAN_CHARS = 2_000_000;

    private static final List<SecretRule> RULES = List.of(
        // CRITICAL
        new SecretRule("AWS Access Key",     Severity.CRITICAL, "AKIA[0-9A-Z]{16}"),
        new SecretRule("AWS Secret Key",     Severity.CRITICAL, "(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
        new SecretRule("Private Key Header", Severity.CRITICAL, "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        new SecretRule("JWT Token",          Severity.CRITICAL, "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"),

        // HIGH
        new SecretRule("GCP API Key",        Severity.HIGH, "AIza[0-9A-Za-z\\-_]{35}"),
        new SecretRule("GitHub Token",       Severity.HIGH, "gh[pousr]_[A-Za-z0-9_]{36,}"),
        new SecretRule("Stripe Secret Key",  Severity.HIGH, "sk_live_[0-9a-zA-Z]{24,}"),
        new SecretRule("Stripe Public Key",  Severity.HIGH, "pk_live_[0-9a-zA-Z]{24,}"),
        new SecretRule("Slack Token",        Severity.HIGH, "xox[baprs]-[0-9A-Za-z]{10,}"),
        new SecretRule("SendGrid API Key",   Severity.HIGH, "SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}"),
        new SecretRule("Bearer Token",       Severity.HIGH, "(?i)bearer\\s+[A-Za-z0-9\\-._~+/]{20,}"),

        // MEDIUM
        new SecretRule("Generic API Key",    Severity.MEDIUM, "(?i)(?:api[_\\-]?key|apikey)[\\s:='\"][A-Za-z0-9\\-_]{16,}"),
        new SecretRule("Generic Secret",     Severity.MEDIUM, "(?i)(?:secret|password|passwd|pwd)[\\s:='\"][^\\s'\"]{8,}"),
        new SecretRule("Basic Auth",         Severity.MEDIUM, "(?i)basic\\s+[A-Za-z0-9+/]{10,}={0,2}"),
        new SecretRule("Database URL",       Severity.MEDIUM, "(?:mysql|postgres|mongodb|redis|amqp)://[^\\s'\"]{8,}"),
        new SecretRule("Private IP",         Severity.MEDIUM, "(?:10|172\\.(?:1[6-9]|2[0-9]|3[01])|192\\.168)\\.[0-9]{1,3}\\.[0-9]{1,3}"),

        // LOW
        new SecretRule("Email Address",      Severity.LOW, "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"),
        new SecretRule("URL with creds",     Severity.LOW, "https?://[^:@\\s]+:[^@\\s]+@[^\\s]+")
    );

    /**
     * Scans extracted strings from WASM data sections.
     * Returns findings sorted by severity (CRITICAL first).
     */
    public List<SecretFinding> scan(List<String> strings) {
        if (strings == null || strings.isEmpty()) return List.of();

        // Build combined text with size cap to prevent OOM
        StringBuilder sb = new StringBuilder(Math.min(strings.size() * 64, MAX_SCAN_CHARS + 1));
        for (String s : strings) {
            if (sb.length() >= MAX_SCAN_CHARS) break;
            sb.append(s).append('\n');
        }
        String combined = sb.toString();

        List<SecretFinding> findings = new ArrayList<>();

        for (SecretRule rule : RULES) {
            try {
                Matcher m = rule.pattern.matcher(combined);
                while (m.find()) {
                    String match = m.group();
                    // Deduplicate exact match per rule
                    boolean dup = findings.stream()
                        .anyMatch(f -> f.ruleName().equals(rule.name) && f.match().equals(match));
                    if (!dup) {
                        findings.add(new SecretFinding(
                            rule.name,
                            rule.severity,
                            match,
                            extractContext(combined, m.start(), 50)
                        ));
                    }
                }
            } catch (Exception ignored) {
                // Regex errors on malformed input — skip rule
            }
        }

        findings.sort(Comparator.comparingInt(f -> f.severity().ordinal()));
        return findings;
    }

    private String extractContext(String text, int pos, int radius) {
        int start = Math.max(0, pos - radius);
        int end   = Math.min(text.length(), pos + radius);
        String ctx = text.substring(start, end).replaceAll("[\\r\\n]+", " ");
        return (start > 0 ? "…" : "") + ctx + (end < text.length() ? "…" : "");
    }

    private static class SecretRule {
        final String  name;
        final Severity severity;
        final Pattern pattern;

        SecretRule(String name, Severity severity, String regex) {
            this.name     = name;
            this.severity = severity;
            // DOTALL for multi-line data, compile once at class init
            this.pattern  = Pattern.compile(regex, Pattern.DOTALL);
        }
    }
}
