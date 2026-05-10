package com.wasmanalyzer.ui;

import com.wasmanalyzer.WasmAnalyzerExtension;
import com.wasmanalyzer.detector.WasmDetector;
import com.wasmanalyzer.model.WasmCapture;
import com.wasmanalyzer.model.WasmCaptureStore;
import com.wasmanalyzer.patcher.WasmPatcher;
import com.wasmanalyzer.scanner.SecretScanner;
import com.wasmanalyzer.scanner.WasmSecurityScanner;
import com.wasmanalyzer.sourcemap.SourceMapProber;
import com.wasmanalyzer.parser.WasmParser;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;

public class AnalyzerToolTab {

    private final WasmCaptureStore store = new WasmCaptureStore();
    private final WasmSecurityScanner securityScanner = new WasmSecurityScanner();
    private final WasmParser parser = new WasmParser();
    private final WasmPatcher patcher = new WasmPatcher();
    private final SecretScanner scanner = new SecretScanner();
    private final SourceMapProber sourceMapProber = new SourceMapProber();

    private final ThreadPoolExecutor bgPool = new ThreadPoolExecutor(
        2, 4, 60L, TimeUnit.SECONDS,
        new LinkedBlockingQueue<>(50),
        r -> { Thread t = new Thread(r, "wasm-bg"); t.setDaemon(true); return t; },
        new ThreadPoolExecutor.DiscardOldestPolicy()
    );
    private final JPanel root;

    // Left: capture list
    private final DefaultTableModel tableModel;
    private final JTable captureTable;

    // Right: detail tabs
    private final JTabbedPane detailTabs;
    private final JTextArea overviewPane;
    private final JTextArea watPane;
    private final JTextArea secretsPane;
    private final JTextArea securityPane;
    private final JTextArea sourcemapPane;
    private final JTextArea stringsPane;

    // Patching controls
    private final JButton recompileBtn;
    private final JButton exportWasmBtn;
    private final JButton exportWatBtn;
    private final JLabel patchStatus;

    // Settings tab (embedded)
    private final SettingsPanel settingsPanel;

    private WasmCapture selectedCapture;

    public AnalyzerToolTab() {
        root = new JPanel(new BorderLayout());

        // ── TABLE (left) ─────────────────────────────────────────
        String[] cols = {"#", "Dir", "Size (KB)", "Issues", "Source Map", "URL"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        captureTable = new JTable(tableModel);
        captureTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        captureTable.getColumnModel().getColumn(0).setMaxWidth(40);
        captureTable.getColumnModel().getColumn(1).setMaxWidth(50);
        captureTable.getColumnModel().getColumn(2).setMaxWidth(80);
        captureTable.getColumnModel().getColumn(3).setMaxWidth(60);
        captureTable.getColumnModel().getColumn(4).setMaxWidth(90);
        captureTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onCaptureSelected();
        });

        JScrollPane tableScroll = new JScrollPane(captureTable);
        tableScroll.setPreferredSize(new Dimension(420, 0));

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> { store.clear(); tableModel.setRowCount(0); clearDetail(); });

        JPanel tablePanel = new JPanel(new BorderLayout(0, 4));
        tablePanel.add(tableScroll, BorderLayout.CENTER);
        tablePanel.add(clearBtn, BorderLayout.SOUTH);

        // ── DETAIL TABS (right) ──────────────────────────────────
        detailTabs = new JTabbedPane();

        overviewPane  = monospaceArea(false);
        watPane       = monospaceArea(true);
        secretsPane   = monospaceArea(false);
        securityPane  = monospaceArea(false);
        sourcemapPane = monospaceArea(false);
        stringsPane   = monospaceArea(false);

        // Patching bar
        recompileBtn  = new JButton("Recompile WAT → WASM");
        exportWasmBtn = new JButton("Export .wasm");
        exportWatBtn  = new JButton("Export .wat");
        patchStatus   = new JLabel(" ");

        JPanel patchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        patchBar.add(recompileBtn);
        patchBar.add(exportWasmBtn);
        patchBar.add(exportWatBtn);
        patchBar.add(patchStatus);

        JPanel watTab = new JPanel(new BorderLayout(4, 4));
        watTab.add(new JScrollPane(watPane), BorderLayout.CENTER);
        watTab.add(patchBar, BorderLayout.SOUTH);

        detailTabs.addTab("Overview",   new JScrollPane(overviewPane));
        detailTabs.addTab("WAT",        watTab);
        detailTabs.addTab("Secrets",    new JScrollPane(secretsPane));
        detailTabs.addTab("Security",   new JScrollPane(securityPane));
        detailTabs.addTab("Strings",    new JScrollPane(stringsPane));
        detailTabs.addTab("Source Map", new JScrollPane(sourcemapPane));

        settingsPanel = new SettingsPanel();
        detailTabs.addTab("Settings", settingsPanel.getComponent());

        // ── SPLIT ────────────────────────────────────────────────
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, detailTabs);
        split.setDividerLocation(420);
        split.setResizeWeight(0.35);

        root.add(split, BorderLayout.CENTER);

        // ── LISTENERS ────────────────────────────────────────────
        store.addListener(capture -> SwingUtilities.invokeLater(() -> addCaptureRow(capture)));

        recompileBtn.addActionListener(e -> onRecompile());
        exportWasmBtn.addActionListener(e -> onExportWasm());
        exportWatBtn.addActionListener(e -> onExportWat());
    }

    public JComponent getComponent() { return root; }
    public WasmCaptureStore getStore() { return store; }

    public void shutdown() {
        bgPool.shutdownNow();
        sourceMapProber.shutdown();
        try {
            if (!bgPool.awaitTermination(5, TimeUnit.SECONDS)) {
                WasmAnalyzerExtension.logger.logToError("[WASM Analyzer] Analyzer tab pool did not terminate in time.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void addCapture(byte[] wasmBytes, String url, com.wasmanalyzer.detector.WasmDetector.DetectionResult.Source source, WasmCapture.Direction direction) {
        WasmCapture capture = new WasmCapture(
            UUID.randomUUID().toString(),
            direction, url, wasmBytes, source
        );
        store.add(capture);
        
        bgPool.submit(() -> analyzeCapture(capture));
    }

    public void refreshCapture(WasmCapture capture) {
        SwingUtilities.invokeLater(() -> {
            updateTableRow(capture);
            if (selectedCapture != null && selectedCapture.id.equals(capture.id)) {
                populateDetail(capture);
            }
        });
    }

    public void refresh() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            for (WasmCapture c : store.getAll()) addCaptureRow(c);
        });
    }

    private void analyzeCapture(WasmCapture capture) {
        try {
            capture.parseResult = parser.parse(capture.wasmBytes);

            if (!capture.parseResult.hasError()) {
                capture.secrets = scanner.scan(capture.parseResult.allStrings());
            }

            capture.watText = patcher.decompile(capture.wasmBytes);

            capture.securityFindings = securityScanner.scan(
                capture.parseResult,
                capture.parseResult != null ? capture.parseResult.allStrings() : List.of(),
                capture.watText
            );

            refreshCapture(capture);

            if (capture.direction == WasmCapture.Direction.RESPONSE) {
                sourceMapProber.probeAsync(capture.url, (found, mapUrl, mapContent) -> {
                    capture.sourceMapFound   = found;
                    capture.sourceMapUrl     = mapUrl;
                    capture.sourceMapContent = mapContent;
                    refreshCapture(capture);
                });
            }

        } catch (Exception e) {
            WasmAnalyzerExtension.logger.logToError(
                "[WASM Analyzer] Analysis error for " + capture.url + ": " + e.getMessage());
        }
    }

    private void addCaptureRow(WasmCapture c) {
        tableModel.addRow(new Object[]{
            tableModel.getRowCount() + 1,
            c.direction.name().substring(0, 3),
            c.wasmBytes.length / 1024,
            "…",
            "…",
            c.url
        });
    }

    private void updateTableRow(WasmCapture c) {
        List<WasmCapture> all = store.getAll();
        for (int i = 0; i < all.size(); i++) {
            if (all.get(i).id.equals(c.id)) {
                int secrets = c.secrets != null ? c.secrets.size() : -1;
                tableModel.setValueAt(secrets >= 0 ? String.valueOf(secrets) : "…", i, 3);
                tableModel.setValueAt(c.sourceMapFound ? "YES" : (c.sourceMapUrl != null ? "no" : "…"), i, 4);
                break;
            }
        }
    }

    private void onCaptureSelected() {
        int row = captureTable.getSelectedRow();
        if (row < 0 || row >= store.getAll().size()) return;
        selectedCapture = store.getAll().get(row);
        populateDetail(selectedCapture);
    }

    private void populateDetail(WasmCapture c) {
        // Overview
        StringBuilder ov = new StringBuilder();
        ov.append("URL        : ").append(c.url).append("\n");
        ov.append("Direction  : ").append(c.direction).append("\n");
        ov.append("Captured   : ").append(c.capturedAt).append("\n");
        ov.append("Size       : ").append(String.format("%,d", c.wasmBytes.length)).append(" bytes\n");
        ov.append("Detection  : ").append(c.detectionSource).append("\n");
        if (c.parseResult != null && !c.parseResult.hasError()) {
            var pr = c.parseResult;
            ov.append("\nVersion    : ").append(pr.version).append("\n");
            ov.append("Functions  : ").append(pr.functionCount).append("\n");
            ov.append("Types      : ").append(pr.typeCount).append("\n");
            ov.append("\nSections:\n");
            for (var s : pr.sections) {
                ov.append(String.format("  %-12s %s\n", s.name, s.description));
            }
            if (!pr.imports.isEmpty()) {
                ov.append("\nImports (").append(pr.imports.size()).append("):\n");
                pr.imports.forEach(i -> ov.append("  ").append(i).append("\n"));
            }
            if (!pr.exports.isEmpty()) {
                ov.append("\nExports (").append(pr.exports.size()).append("):\n");
                pr.exports.forEach(e -> ov.append("  ").append(e).append("\n"));
            }
        } else if (c.parseResult != null) {
            ov.append("\nParse error: ").append(c.parseResult.error).append("\n");
        } else {
            ov.append("\nParsing… (background)\n");
        }
        overviewPane.setText(ov.toString());
        overviewPane.setCaretPosition(0);

        // WAT
        watPane.setText(c.watText != null ? c.watText : "Decompiling… (background)");
        watPane.setCaretPosition(0);

        // Secrets
        if (c.secrets != null) {
            secretsPane.setText(buildSecretsText(c.secrets));
        } else {
            secretsPane.setText("Scanning… (background)");
        }
        secretsPane.setCaretPosition(0);

        // Strings
        if (c.parseResult != null && !c.parseResult.hasError()) {
            var strings = c.parseResult.allStrings();
            StringBuilder sb = new StringBuilder();
            sb.append(strings.size()).append(" strings extracted from data sections:\n\n");
            strings.forEach(s -> sb.append(s).append("\n"));
            stringsPane.setText(sb.toString());
        } else {
            stringsPane.setText("Parsing… (background)");
        }
        stringsPane.setCaretPosition(0);

        // Security findings
        if (c.securityFindings != null && !c.securityFindings.isEmpty()) {
            StringBuilder sec = new StringBuilder();
            sec.append(c.securityFindings.size()).append(" security finding(s):\n\n");
            WasmSecurityScanner.Severity lastSev = null;
            for (var f : c.securityFindings) {
                if (!f.severity().equals(lastSev)) {
                    sec.append("\n[").append(f.severity()).append("] ").append(f.title()).append("\n");
                    sec.append("─".repeat(50)).append("\n");
                    lastSev = f.severity();
                }
                sec.append("  ID     : ").append(f.id()).append("\n");
                sec.append("  Desc   : ").append(f.description()).append("\n");
                sec.append("  Evidence: ").append(f.evidence()).append("\n");
                sec.append("  Fix    : ").append(f.recommendation()).append("\n\n");
            }
            securityPane.setText(sec.toString());
        } else {
            securityPane.setText("No security findings.");
        }
        securityPane.setCaretPosition(0);

        // Source map
        if (c.sourceMapUrl != null) {
            if (c.sourceMapFound) {
                sourcemapPane.setText("Source map found: " + c.sourceMapUrl + "\n\n" + c.sourceMapContent);
            } else {
                sourcemapPane.setText("Probed: " + c.sourceMapUrl + "\nNot found (HTTP != 200)");
            }
        } else {
            sourcemapPane.setText("Probing…");
        }
        sourcemapPane.setCaretPosition(0);
    }

    private String buildSecretsText(List<SecretScanner.SecretFinding> findings) {
        if (findings.isEmpty()) return "No secrets found.";
        StringBuilder sb = new StringBuilder();
        sb.append(findings.size()).append(" finding(s):\n\n");
        SecretScanner.Severity lastSev = null;
        for (var f : findings) {
            if (!f.severity().equals(lastSev)) {
                sb.append("\n[").append(f.severity()).append("]\n");
                sb.append("─".repeat(40)).append("\n");
                lastSev = f.severity();
            }
            sb.append("  Rule    : ").append(f.ruleName()).append("\n");
            sb.append("  Match   : ").append(f.match()).append("\n");
            sb.append("  Context : ").append(f.context()).append("\n\n");
        }
        return sb.toString();
    }

    private void onRecompile() {
        if (selectedCapture == null) return;
        patchStatus.setText("Recompilation requires wabt (wat2wasm). Save WAT file and compile externally, or install wabt.");
    }

    private void onExportWasm() {
        if (selectedCapture == null) return;
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("module.wasm"));
        if (fc.showSaveDialog(root) == JFileChooser.APPROVE_OPTION) {
            try {
                Files.write(fc.getSelectedFile().toPath(), selectedCapture.wasmBytes);
                patchStatus.setText("Saved " + selectedCapture.wasmBytes.length + " bytes.");
            } catch (IOException ex) {
                patchStatus.setText("Save error: " + ex.getMessage());
            }
        }
    }

    private void onExportWat() {
        if (selectedCapture == null || selectedCapture.watText == null) return;
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("module.wat"));
        if (fc.showSaveDialog(root) == JFileChooser.APPROVE_OPTION) {
            try {
                Files.writeString(fc.getSelectedFile().toPath(), selectedCapture.watText);
                patchStatus.setText("WAT saved.");
            } catch (IOException ex) {
                patchStatus.setText("Save error: " + ex.getMessage());
            }
        }
    }

    private void clearDetail() {
        selectedCapture = null;
        overviewPane.setText("");
        watPane.setText("");
        secretsPane.setText("");
        securityPane.setText("");
        stringsPane.setText("");
        sourcemapPane.setText("");
        patchStatus.setText(" ");
    }

    private JTextArea monospaceArea(boolean editable) {
        JTextArea ta = new JTextArea();
        ta.setEditable(editable);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setLineWrap(false);
        return ta;
    }
}
