package com.wasmanalyzer.sourcemap;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.wasmanalyzer.WasmAnalyzerExtension;
import com.wasmanalyzer.settings.ExtensionSettings;

import java.util.concurrent.*;

public class SourceMapProber {

    private final ExecutorService executor = new ThreadPoolExecutor(
        1, 2, 30L, TimeUnit.SECONDS,
        new LinkedBlockingQueue<>(20),
        r -> { Thread t = new Thread(r, "wasm-sourcemap-prober"); t.setDaemon(true); return t; },
        new ThreadPoolExecutor.DiscardPolicy()
    );

    public void probeAsync(String wasmUrl, SourceMapCallback callback) {
        if (!ExtensionSettings.getInstance().isAutoProbeSourceMap()) {
            callback.onResult(false, null, null);
            return;
        }
        String mapUrl = buildMapUrl(wasmUrl);
        if (mapUrl == null) { callback.onResult(false, null, null); return; }

        try {
            executor.submit(() -> doProbe(mapUrl, callback));
        } catch (RejectedExecutionException e) {
            callback.onResult(false, mapUrl, null);
        }
    }

    private void doProbe(String mapUrl, SourceMapCallback callback) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(mapUrl);
            HttpRequestResponse rr = WasmAnalyzerExtension.api.http().sendRequest(req);
            if (rr == null) { callback.onResult(false, mapUrl, null); return; }

            HttpResponse resp = rr.response();
            if (resp == null || resp.statusCode() != 200) {
                callback.onResult(false, mapUrl, null);
                return;
            }
            String body = resp.bodyToString();
            if (body != null && (body.contains("\"mappings\"") || body.contains("\"sources\""))) {
                callback.onResult(true, mapUrl, body);
            } else {
                callback.onResult(false, mapUrl, null);
            }
        } catch (Exception e) {
            WasmAnalyzerExtension.logger.logToOutput(
                "[WASM Analyzer] Source map probe error: " + mapUrl + " - " + e.getMessage());
            callback.onResult(false, mapUrl, null);
        }
    }

    private String buildMapUrl(String wasmUrl) {
        if (wasmUrl == null || wasmUrl.isBlank()) return null;
        int q = wasmUrl.indexOf('?');
        String base = q >= 0 ? wasmUrl.substring(0, q) : wasmUrl;
        if (!base.toLowerCase().endsWith(".wasm")) return null;
        return base + ".map";
    }

    public void shutdown() {
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                WasmAnalyzerExtension.logger.logToError("[WASM Analyzer] Source map prober pool did not terminate in time.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public interface SourceMapCallback {
        void onResult(boolean found, String mapUrl, String mapContent);
    }
}