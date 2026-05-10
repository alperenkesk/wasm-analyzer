package com.wasmanalyzer.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.wasmanalyzer.WasmAnalyzerExtension;
import com.wasmanalyzer.detector.WasmDetector;
import com.wasmanalyzer.model.WasmCapture;

import javax.swing.*;
import java.awt.*;
import java.util.List;

import static java.util.Collections.emptyList;

public class WasmContextMenu implements ContextMenuItemsProvider {

    private final WasmDetector detector = new WasmDetector();

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        try {
            var opt = event.messageEditorRequestResponse();
            if (opt.isEmpty()) {
                return emptyList();
            }

            HttpRequestResponse rr = opt.get().requestResponse();
            if (rr == null) {
                return emptyList();
            }

            byte[] body = null;
            String url = null;

            if (rr.response() != null) {
                body = rr.response().body().getBytes();
                url = rr.request() != null ? rr.request().url() : null;
            } else if (rr.request() != null) {
                body = rr.request().body().getBytes();
                url = rr.request().url();
            }

            if (body == null || body.length < 4) {
                return emptyList();
            }

            WasmDetector.DetectionResult result = detector.detect(body, url, null);
            if (!result.detected) {
                return emptyList();
            }

            final byte[] wasmBytes = java.util.Arrays.copyOf(result.wasmBytes, result.wasmBytes.length);
            final String captureUrl = (url != null) ? url : "unknown";
            final WasmDetector.DetectionResult.Source captureSource = result.source;

            JMenuItem item = new JMenuItem("Send to WASM Analyzer");
            item.addActionListener(e -> {
                WasmAnalyzerExtension.logger.logToOutput(
                    "[WASM Analyzer] Sending to analyzer: " + captureUrl + " (" + wasmBytes.length + " bytes)");

                WasmAnalyzerExtension.analyzerTab.addCapture(
                    wasmBytes, captureUrl, captureSource, WasmCapture.Direction.RESPONSE);

                WasmAnalyzerExtension.logger.logToOutput("[WASM Analyzer] Capture added successfully");
            });

            return List.of(item);
        } catch (Exception ex) {
            WasmAnalyzerExtension.logger.logToError("[WASM Analyzer] Context menu error: " + ex.getMessage());
            return emptyList();
        }
    }
}