package com.wasmanalyzer.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.*;
import com.wasmanalyzer.WasmAnalyzerExtension;
import com.wasmanalyzer.detector.WasmDetector;
import com.wasmanalyzer.parser.WasmParser;
import com.wasmanalyzer.parser.WasmParseResult;
import com.wasmanalyzer.patcher.WasmPatcher;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

public class WasmEditorTab implements ExtensionProvidedHttpRequestEditor,
                                      ExtensionProvidedHttpResponseEditor {

    private final EditorCreationContext context;
    private final boolean               forResponse;
    private final WasmDetector          detector;
    private final WasmParser           parser  = new WasmParser();
    private final WasmPatcher          patcher = new WasmPatcher();

    private final JPanel      panel;
    private final JTabbedPane innerTabs;
    private final JTextArea   overviewArea;
    private final JTextArea   watArea;
    private final JButton     recompileBtn;
    private final JLabel      recompileStatus;

    private final AtomicLong requestVersion = new AtomicLong(0);
    private volatile byte[]  currentWasmBytes;
    private volatile boolean modified        = false;

    private volatile HttpRequest  lastRequest;
    private volatile HttpResponse lastResponse;

    public WasmEditorTab(EditorCreationContext context, boolean forResponse, WasmDetector detector) {
        this.context     = context;
        this.forResponse = forResponse;
        this.detector    = detector;

        overviewArea  = monospaceArea(false);
        watArea       = monospaceArea(true);

        recompileBtn    = new JButton("Recompile WAT -> WASM");
        recompileStatus = new JLabel(" ");

        JPanel patchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        patchBar.add(recompileBtn);
        patchBar.add(recompileStatus);

        JPanel watPanel = new JPanel(new BorderLayout(4, 4));
        watPanel.add(new JScrollPane(watArea), BorderLayout.CENTER);
        watPanel.add(patchBar, BorderLayout.SOUTH);

        innerTabs = new JTabbedPane();
        innerTabs.addTab("Overview", new JScrollPane(overviewArea));
        innerTabs.addTab("WAT (editable)", watPanel);

        panel = new JPanel(new BorderLayout());
        panel.add(innerTabs, BorderLayout.CENTER);

        recompileBtn.addActionListener(e -> onRecompile());
    }

    @Override public String    caption()     { return "WASM"; }
    @Override public Component uiComponent() { return panel; }
    @Override public boolean   isModified()  { return modified; }

    @Override
    public Selection selectedData() {
        try {
            String sel = watArea.getSelectedText();
            if (sel == null || sel.isEmpty()) return null;
            return Selection.selection(burp.api.montoya.core.ByteArray.byteArray(sel.getBytes()));
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse rr) {
        return true;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse rr) {
        try {
            lastRequest   = rr.request();
            lastResponse  = rr.response();

            byte[] body = extractBody(rr);
            String url  = rr.request() != null ? rr.request().url() : null;

            if (body == null || body.length == 0) {
                if (url != null && url.toLowerCase().endsWith(".wasm")) {
                    overviewArea.setText("WASM request detected. Waiting for response...");
                    watArea.setText("WASM request detected. Waiting for response...");
                } else {
                    overviewArea.setText("No body content.");
                    watArea.setText("No body content.");
                }
                return;
            }

            if (body.length < 4) {
                overviewArea.setText("Body too small to be WASM.");
                watArea.setText("Body too small to be WASM.");
                return;
            }

            WasmDetector.DetectionResult result = detector.detect(body, url, null);

            if (!result.detected) {
                overviewArea.setText("Not a WASM payload.");
                watArea.setText("Not a WASM payload.");
                return;
            }

            currentWasmBytes = result.wasmBytes;
            modified = false;

            boolean editable = !forResponse && context.editorMode() != EditorMode.READ_ONLY;
            watArea.setEditable(editable);
            recompileBtn.setEnabled(editable);

            overviewArea.setText("Analyzing WASM...");
            watArea.setText("Decompiling...");

            final long myVersion = requestVersion.incrementAndGet();
            final byte[] snap = Arrays.copyOf(currentWasmBytes, currentWasmBytes.length);

            Thread t = new Thread(() -> {
                WasmParseResult pr = parser.parse(snap);
                String wat = patcher.decompile(snap);
                if (requestVersion.get() != myVersion) return;
                SwingUtilities.invokeLater(() -> {
                    if (requestVersion.get() != myVersion) return;
                    overviewArea.setText(buildOverview(pr));
                    overviewArea.setCaretPosition(0);
                    watArea.setText(wat);
                    watArea.setCaretPosition(0);
                });
            }, "wasm-editor-parse");
            t.setDaemon(true);
            t.start();

        } catch (Exception e) {
            WasmAnalyzerExtension.logger.logToError("[WASM Analyzer] Editor error: " + e.getMessage());
            overviewArea.setText("Error: " + e.getMessage());
        }
    }

    @Override
    public HttpRequest getRequest() {
        return lastRequest;
    }

    @Override
    public HttpResponse getResponse() {
        return lastResponse;
    }

    private void onRecompile() {
        if (currentWasmBytes == null) return;
        recompileStatus.setText("Recompilation requires wabt. Save WAT and compile externally.");
    }

    private byte[] extractBody(HttpRequestResponse rr) {
        try {
            if (forResponse) {
                HttpResponse r = rr.response();
                return r != null ? r.body().getBytes() : null;
            } else {
                HttpRequest r = rr.request();
                return r != null ? r.body().getBytes() : null;
            }
        } catch (Exception e) {
            return null;
        }
    }

    private String buildOverview(WasmParseResult pr) {
        StringBuilder sb = new StringBuilder("=== WASM Module Overview ===\n\n");
        if (pr.hasError()) return sb.append("Parse error: ").append(pr.error).append("\n").toString();

        sb.append(String.format("Size      : %,d bytes%n", pr.totalBytes));
        sb.append(String.format("Version   : %d%n", pr.version));
        sb.append(String.format("Functions : %d%n", pr.functionCount));
        sb.append(String.format("Types     : %d%n%n", pr.typeCount));

        sb.append("--- Sections ---\n");
        pr.sections.forEach(s -> sb.append(String.format("  %-12s %s%n", s.name, s.description)));

        if (!pr.imports.isEmpty()) {
            sb.append("\n--- Imports (").append(pr.imports.size()).append(") ---\n");
            pr.imports.forEach(i -> sb.append("  ").append(i).append('\n'));
        }
        if (!pr.exports.isEmpty()) {
            sb.append("\n--- Exports (").append(pr.exports.size()).append(") ---\n");
            pr.exports.forEach(e -> sb.append("  ").append(e).append('\n'));
        }
        var strings = pr.allStrings();
        if (!strings.isEmpty()) {
            sb.append("\n--- Strings (").append(strings.size()).append(") ---\n");
            strings.stream().limit(200).forEach(s -> sb.append("  ").append(s).append('\n'));
            if (strings.size() > 200)
                sb.append("  ... ").append(strings.size() - 200).append(" more\n");
        }
        return sb.toString();
    }

    private static JTextArea monospaceArea(boolean editable) {
        JTextArea ta = new JTextArea();
        ta.setEditable(editable);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setLineWrap(false);
        return ta;
    }
}