package com.wasmanalyzer.handler;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.wasmanalyzer.WasmAnalyzerExtension;
import com.wasmanalyzer.detector.WasmDetector;
import com.wasmanalyzer.model.WasmCapture;
import com.wasmanalyzer.parser.WasmParser;
import com.wasmanalyzer.patcher.WasmPatcher;
import com.wasmanalyzer.scanner.SecretScanner;
import com.wasmanalyzer.scanner.WasmIssueReporter;
import com.wasmanalyzer.scanner.WasmSecurityScanner;
import com.wasmanalyzer.sourcemap.SourceMapProber;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;

public class WasmHttpHandler implements HttpHandler {

    private final WasmDetector         detector        = new WasmDetector();
    private final WasmParser           parser          = new WasmParser();
    private final WasmPatcher          patcher         = new WasmPatcher();
    private final SecretScanner        scanner         = new SecretScanner();
    private final WasmSecurityScanner  secScanner      = new WasmSecurityScanner();
    private final SourceMapProber      sourceMapProber = new SourceMapProber();
    private final WasmIssueReporter    issueReporter   = new WasmIssueReporter();

    // Bounded queue — prevents unbounded work accumulation on fast traffic
    private final ThreadPoolExecutor bgPool = new ThreadPoolExecutor(
        2, 4, 60L, TimeUnit.SECONDS,
        new LinkedBlockingQueue<>(50),
        r -> { Thread t = new Thread(r, "wasm-bg"); t.setDaemon(true); return t; },
        new ThreadPoolExecutor.DiscardOldestPolicy()
    );

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            byte[] body = response.body().getBytes();
            if (body != null && body.length >= 4) {
                String url = response.initiatingRequest().url();
                WasmDetector.DetectionResult result = detector.detect(body, url, response.headerValue("Content-Type"));
                if (result.detected) {
                    HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
                        response.initiatingRequest(), response);
                    scheduleCapture(result, url, WasmCapture.Direction.RESPONSE, rr);
                }
            }
        } catch (Exception ignored) {}
        return ResponseReceivedAction.continueWith(response);
    }

    private void scheduleCapture(WasmDetector.DetectionResult detection,
                                 String url, WasmCapture.Direction direction,
                                 HttpRequestResponse requestResponse) {
        byte[] bytes = java.util.Arrays.copyOf(detection.wasmBytes, detection.wasmBytes.length);

        WasmCapture capture = new WasmCapture(
            UUID.randomUUID().toString(),
            direction, url, bytes, detection.source,
            requestResponse
        );
        WasmAnalyzerExtension.analyzerTab.getStore().add(capture);
        WasmAnalyzerExtension.logger.logToOutput(
            "[WASM Analyzer] Captured " + bytes.length + " bytes from " + url
            + " [" + detection.source + "]");

        bgPool.submit(() -> analyzeCapture(capture));
    }

    public void shutdown() {
        bgPool.shutdownNow();
        try {
            if (!bgPool.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                WasmAnalyzerExtension.logger.logToError("[WASM Analyzer] Background pool did not terminate in time.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void analyzeCapture(WasmCapture capture) {
        try {
            // 1. Parse sections
            capture.parseResult = parser.parse(capture.wasmBytes);

            // 2. Secret scan on extracted strings
            if (!capture.parseResult.hasError()) {
                capture.secrets = scanner.scan(capture.parseResult.allStrings());
                if (!capture.secrets.isEmpty()) {
                    WasmAnalyzerExtension.logger.logToOutput(
                        "[WASM Analyzer] " + capture.secrets.size()
                        + " secret finding(s) in " + capture.url);
                }
            }

            // 3. WAT decompile (may take seconds for large files)
            capture.watText = patcher.decompile(capture.wasmBytes);

            capture.securityFindings = secScanner.scan(
                capture.parseResult,
                capture.parseResult != null ? capture.parseResult.allStrings() : List.of(),
                capture.watText
            );

            if (!capture.securityFindings.isEmpty()) {
                WasmAnalyzerExtension.logger.logToOutput(
                    "[WASM Analyzer] " + capture.securityFindings.size()
                    + " security finding(s) in " + capture.url);
            }

            // Notify UI after parse + secrets + WAT are ready
            WasmAnalyzerExtension.analyzerTab.refreshCapture(capture);

            // 4. Passive source map probe (response only)
            if (capture.direction == WasmCapture.Direction.RESPONSE) {
                sourceMapProber.probeAsync(capture.url, (found, mapUrl, mapContent) -> {
                    capture.sourceMapFound   = found;
                    capture.sourceMapUrl     = mapUrl;
                    capture.sourceMapContent = mapContent;
                    WasmAnalyzerExtension.analyzerTab.refreshCapture(capture);
                    if (found) WasmAnalyzerExtension.logger.logToOutput(
                        "[WASM Analyzer] Source map found: " + mapUrl);
                });
            }

            // 5. Report findings as Burp audit issues
            issueReporter.reportFindings(capture);

        } catch (Exception e) {
            WasmAnalyzerExtension.logger.logToError(
                "[WASM Analyzer] Analysis error for " + capture.url + ": " + e.getMessage());
        }
    }
}
