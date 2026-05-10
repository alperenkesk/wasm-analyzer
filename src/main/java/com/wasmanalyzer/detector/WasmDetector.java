package com.wasmanalyzer.detector;

import java.util.Base64;

public class WasmDetector {

    private static final byte[] WASM_MAGIC = {0x00, 0x61, 0x73, 0x6D};

    // A valid Base64 body cannot contain bytes > 0x7A or control chars below 0x09.
    // Quick heuristic: if >10% of the first 256 bytes are non-Base64-alphabet,
    // skip expensive decode attempt.
    private static final String B64_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n \"";

    public boolean isWasm(byte[] body) {
        if (body == null || body.length < 4) return false;
        return body[0] == WASM_MAGIC[0]
            && body[1] == WASM_MAGIC[1]
            && body[2] == WASM_MAGIC[2]
            && body[3] == WASM_MAGIC[3];
    }

    public boolean urlEndsWithWasm(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase();
        int idx = lower.indexOf('?');
        String path = idx >= 0 ? lower.substring(0, idx) : lower;
        return path.endsWith(".wasm");
    }

    public boolean hasWasmContentType(String contentType) {
        if (contentType == null) return false;
        return contentType.contains("application/wasm")
            || contentType.contains("application/octet-stream");
    }

    /**
     * Attempts to decode a Base64-encoded WASM payload.
     * Returns decoded bytes if magic matches, else null.
     * Skips expensive decode if the body looks like raw binary.
     */
    public byte[] tryDecodeBase64Wasm(byte[] body) {
        if (body == null || body.length < 12) return null;

        // Fast rejection: sample first 256 bytes for non-Base64 characters
        int sampleLen = Math.min(256, body.length);
        int nonB64 = 0;
        for (int i = 0; i < sampleLen; i++) {
            if (B64_ALPHABET.indexOf(body[i] & 0xFF) < 0) nonB64++;
        }
        if (nonB64 > sampleLen / 10) return null; // >10% non-Base64 → skip

        try {
            String raw = new String(body).trim();
            // Strip optional surrounding quotes (JSON-encoded wasm)
            if (raw.length() > 2 && raw.charAt(0) == '"' && raw.charAt(raw.length() - 1) == '"') {
                raw = raw.substring(1, raw.length() - 1);
            }
            byte[] decoded = tryDecode(raw);
            if (decoded != null && isWasm(decoded)) return decoded;
        } catch (Exception ignored) {}
        return null;
    }

    private byte[] tryDecode(String raw) {
        try {
            return Base64.getDecoder().decode(raw);
        } catch (Exception ignored) {}
        try {
            return Base64.getUrlDecoder().decode(raw);
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Full detection pipeline. Order matters:
     *  1. Magic bytes (fastest)
     *  2. URL ends with .wasm
     *  3. Base64-encoded wasm
     */
    public DetectionResult detect(byte[] body, String url, String contentType) {
        if (body == null && url == null) {
            return new DetectionResult(false, null, DetectionResult.Source.NONE);
        }

        if (body != null && body.length >= 4 && isWasm(body)) {
            return new DetectionResult(true, body, DetectionResult.Source.DIRECT);
        }

        if (urlEndsWithWasm(url)) {
            if (body != null && body.length >= 4) {
                return new DetectionResult(true, body, DetectionResult.Source.DIRECT);
            }
        }

        if (body != null) {
            byte[] decoded = tryDecodeBase64Wasm(body);
            if (decoded != null) {
                return new DetectionResult(true, decoded, DetectionResult.Source.BASE64);
            }
        }

        return new DetectionResult(false, null, DetectionResult.Source.NONE);
    }

    public static class DetectionResult {
        public enum Source { DIRECT, BASE64, NONE }

        public final boolean detected;
        public final byte[]  wasmBytes;
        public final Source  source;

        public DetectionResult(boolean detected, byte[] wasmBytes, Source source) {
            this.detected  = detected;
            this.wasmBytes = wasmBytes;
            this.source    = source;
        }
    }
}
