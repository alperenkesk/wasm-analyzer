package com.wasmanalyzer.model;

import com.wasmanalyzer.detector.WasmDetector;
import com.wasmanalyzer.parser.WasmParseResult;
import com.wasmanalyzer.scanner.SecretScanner;
import com.wasmanalyzer.scanner.WasmSecurityScanner;

import java.time.Instant;
import java.util.List;

public class WasmCapture {

    public enum Direction { REQUEST, RESPONSE }

    public final String id;
    public final Instant capturedAt;
    public final Direction direction;
    public final String url;
    public volatile byte[] wasmBytes;
    public final WasmDetector.DetectionResult.Source detectionSource;

    public volatile WasmParseResult parseResult;
    public volatile String watText;
    public volatile List<SecretScanner.SecretFinding> secrets;
    public volatile List<WasmSecurityScanner.Finding> securityFindings;
    public volatile boolean sourceMapFound;
    public volatile String sourceMapUrl;
    public volatile String sourceMapContent;

    public WasmCapture(String id, Direction direction, String url,
                       byte[] wasmBytes, WasmDetector.DetectionResult.Source source) {
        this.id            = id;
        this.capturedAt    = Instant.now();
        this.direction     = direction;
        this.url           = url;
        this.wasmBytes     = wasmBytes;
        this.detectionSource = source;
    }

    public String displayLabel() {
        String dir = direction == Direction.REQUEST ? "REQ" : "RES";
        String path = url != null ? url.replaceFirst("https?://[^/]+", "") : "(unknown)";
        if (path.length() > 60) path = "…" + path.substring(path.length() - 57);
        int kb = wasmBytes.length / 1024;
        return String.format("[%s] %s (%d KB)", dir, path, kb);
    }
}
