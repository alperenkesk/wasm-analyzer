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
import javax.swing.text.*;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.regex.Pattern;

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

    // Search
    private final JTextField searchField;
    private final JLabel searchStatus;
    private final JButton searchPrevBtn;
    private final JButton searchNextBtn;
    private java.util.List<int[]> searchMatches;
    private int searchIndex;
    private JTextArea searchTarget;
    private final DefaultHighlighter.DefaultHighlightPainter searchHighlightAll;
    private final DefaultHighlighter.DefaultHighlightPainter searchHighlightCurrent;

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

        // ── SEARCH BAR (above tabs) ──────────────────────────────
        searchField = new JTextField(20);
        searchField.setToolTipText("Search in the active tab");
        searchStatus = new JLabel(" ");
        searchHighlightAll    = new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 255, 150));
        searchHighlightCurrent = new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 200, 50));
        searchPrevBtn = new JButton("\u25B2");
        searchNextBtn = new JButton("\u25BC");
        searchPrevBtn.setEnabled(false);
        searchNextBtn.setEnabled(false);
        searchPrevBtn.setToolTipText("Previous match");
        searchNextBtn.setToolTipText("Next match");

        JButton searchBtn = new JButton("Find");
        searchBtn.addActionListener(e -> doSearch());
        searchField.addActionListener(e -> doSearch());
        searchPrevBtn.addActionListener(e -> searchNav(-1));
        searchNextBtn.addActionListener(e -> searchNav(1));

        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        searchBar.add(new JLabel("Search:"));
        searchBar.add(searchField);
        searchBar.add(searchBtn);
        searchBar.add(searchPrevBtn);
        searchBar.add(searchNextBtn);
        searchBar.add(searchStatus);

        detailTabs.addChangeListener(e -> clearSearch());

        JPanel rightPanel = new JPanel(new BorderLayout(4, 4));
        rightPanel.add(searchBar, BorderLayout.NORTH);
        rightPanel.add(detailTabs, BorderLayout.CENTER);

        // ── SPLIT ────────────────────────────────────────────────
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, rightPanel);
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

    private void doSearch() {
        String query = searchField.getText().trim();
        if (query.isEmpty()) {
            searchStatus.setText("Enter a search term.");
            return;
        }
        Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            searchStatus.setText("Invalid regex.");
            return;
        }

        JTextArea target = switch (detailTabs.getTitleAt(detailTabs.getSelectedIndex())) {
            case "Overview" -> overviewPane;
            case "WAT" -> watPane;
            case "Secrets" -> secretsPane;
            case "Security" -> securityPane;
            case "Strings" -> stringsPane;
            case "Source Map" -> sourcemapPane;
            default -> null;
        };
        if (target == null) {
            searchStatus.setText("Search not supported for this tab.");
            return;
        }

        String text = target.getText();
        if (text == null || text.isEmpty()) {
            searchStatus.setText("No content to search.");
            return;
        }

        // Clear previous search from any text area
        clearSearch();

        // Find all matches
        var matcher = pattern.matcher(text);
        java.util.ArrayList<int[]> matches = new java.util.ArrayList<>();
        while (matcher.find()) {
            matches.add(new int[]{matcher.start(), matcher.end()});
        }

        if (matches.isEmpty()) {
            searchStatus.setText("No matches found.");
            return;
        }

        // Store search state
        searchMatches = matches;
        searchIndex = 0;
        searchTarget = target;

        // Highlight all matches — current in darker yellow, rest in light yellow
        Highlighter h = target.getHighlighter();
        h.removeAllHighlights();
        try {
            for (int i = 0; i < matches.size(); i++) {
                int[] m = matches.get(i);
                h.addHighlight(m[0], m[1], i == 0 ? searchHighlightCurrent : searchHighlightAll);
            }
        } catch (BadLocationException ignored) {}

        // Scroll to first match
        target.setCaretPosition(matches.get(0)[0]);
        target.requestFocusInWindow();

        searchPrevBtn.setEnabled(matches.size() > 1);
        searchNextBtn.setEnabled(matches.size() > 1);
        searchStatus.setText("1/" + matches.size());
    }

    private void searchNav(int direction) {
        if (searchMatches == null || searchTarget == null) return;
        if (searchMatches.size() <= 1) return;

        searchIndex = (searchIndex + direction + searchMatches.size()) % searchMatches.size();

        Highlighter h = searchTarget.getHighlighter();
        h.removeAllHighlights();
        try {
            for (int i = 0; i < searchMatches.size(); i++) {
                int[] m = searchMatches.get(i);
                h.addHighlight(m[0], m[1], i == searchIndex ? searchHighlightCurrent : searchHighlightAll);
            }
        } catch (BadLocationException ignored) {}

        searchTarget.setCaretPosition(searchMatches.get(searchIndex)[0]);
        searchTarget.requestFocusInWindow();
        searchStatus.setText((searchIndex + 1) + "/" + searchMatches.size());
    }

    private void clearSearch() {
        if (searchTarget != null) {
            searchTarget.getHighlighter().removeAllHighlights();
        }
        searchMatches = null;
        searchIndex = 0;
        searchTarget = null;
        searchPrevBtn.setEnabled(false);
        searchNextBtn.setEnabled(false);
    }

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
            direction, url, wasmBytes, source,
            null
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
                int secCount  = c.secrets != null ? c.secrets.size() : 0;
                int vulnCount = c.securityFindings != null ? c.securityFindings.size() : 0;
                int totalIssues = secCount + vulnCount;
                boolean done = c.secrets != null && c.securityFindings != null;
                tableModel.setValueAt(done ? String.valueOf(totalIssues) : "…", i, 3);
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
            secretsPane.setText(buildSecretsText(c.secrets, c.watText));
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
                    sec.append("─".repeat(60)).append("\n");
                    lastSev = f.severity();
                }
                sec.append("  ID        : ").append(f.id()).append("\n");
                sec.append("  Severity  : ").append(f.severity()).append("\n");
                sec.append("  Desc      : ").append(f.description()).append("\n");
                sec.append("  Evidence  : ").append(f.evidence()).append("\n");
                String ctx = extractWatContext(c.watText, f.evidence());
                if (!ctx.isEmpty()) {
                    sec.append(ctx);
                }
                sec.append("  Risk      : ").append(riskDescription(f.id())).append("\n");
                sec.append("  Fix       : ").append(f.recommendation()).append("\n\n");
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

    private String riskDescription(String findingId) {
        return switch (findingId) {
            case "HARDCODE_SECRET" ->
                "Attackers can extract hardcoded secrets by decompiling the WASM binary using browser DevTools or wasm2wat. This can lead to account takeover, data breach, or unauthorized API access.";
            case "WEAK_CRYPTO" ->
                "Weak cryptographic algorithms (MD5, RC4, DES) are computationally cheap to break. An attacker can reverse or forge cryptographically protected data.";
            case "SOURCEMAP_LEAK" ->
                "Source map files (.wasm.map) recreate the original source code with variable names and comments, exposing application logic and business rules to anyone.";
            case "INTERNAL_ENDPOINT" ->
                "Hardcoded internal IPs/endpoints reveal network topology. Attackers can target internal services directly or use the endpoint as a pivot point.";
            case "DANGEROUS_IMPORT" ->
                "Imported functions like 'emscripten_memcpy' or WASI syscalls can cause memory corruption or arbitrary behavior if called with crafted inputs.";
            case "MEMORY_CORRUPTION" ->
                "Unsigned memory loads without bounds checking can read out-of-bounds memory, leading to information disclosure or control flow hijacking.";
            case "INJECTION_TARGET" ->
                "Dynamic calls (call_indirect, table.set) can be exploited to hijack control flow by manipulating the function table, leading to arbitrary code execution.";
            case "CLIENT_BYPASS" ->
                "Client-side authorization checks run in WASM can be patched or bypassed trivially. An attacker can modify the binary or hook the function to bypass restrictions.";
            case "STACKTRACE_LEAK" ->
                "Error messages containing file paths, line numbers, or stack traces reveal internal application structure and aid vulnerability discovery.";
            case "DEBUG_SYMBOLS" ->
                "Debug/test exports expose internal function names and potential attack surface. They indicate a production build with debugging artifacts.";
            case "LARGE_MEMORY" ->
                "Excessive memory allocations can cause denial of service by exhausting browser/system memory. User browsers may crash or become unresponsive.";
            default -> "Review the finding in context to assess business impact.";
        };
    }

    private String extractWatContext(String wat, String evidence) {
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
                ctx.append("  --- WAT context ---\n");
                for (int j = start; j < end; j++) {
                    String prefix = (j == i) ? " >" : "  ";
                    ctx.append(String.format("%s %4d: %s%n", prefix, j + 1, lines[j]));
                }
                ctx.append("  -------------------\n");
                return ctx.toString();
            }
        }
        return "";
    }

    private String buildSecretsText(List<SecretScanner.SecretFinding> findings, String watText) {
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
            sb.append("  Context : ").append(f.context()).append("\n");
            String ctx = extractWatContext(watText, f.match());
            if (!ctx.isEmpty()) {
                sb.append(ctx);
            }
            sb.append("\n");
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
