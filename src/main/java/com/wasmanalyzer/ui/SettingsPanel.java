package com.wasmanalyzer.ui;

import com.wasmanalyzer.WasmAnalyzerExtension;
import com.wasmanalyzer.settings.ExtensionSettings;

import javax.swing.*;
import java.awt.*;

public class SettingsPanel {

    private final JPanel panel;
    private final JCheckBox autoProbeCheckbox;
    private final JLabel saveStatus;

    public SettingsPanel() {
        panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        ExtensionSettings s = ExtensionSettings.getInstance();
        
        autoProbeCheckbox = new JCheckBox(
            "Automatically probe for .wasm.map source maps",
            s.isAutoProbeSourceMap()
        );
        saveStatus = new JLabel(" ");

        panel.add(makeSectionLabel("Source Map"));
        panel.add(Box.createVerticalStrut(8));
        panel.add(autoProbeCheckbox);
        panel.add(Box.createVerticalStrut(16));

        JButton saveBtn = new JButton("Save Settings");
        saveBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        saveBtn.addActionListener(e -> save());
        panel.add(saveBtn);
        panel.add(Box.createVerticalStrut(8));
        panel.add(saveStatus);
        panel.add(Box.createVerticalGlue());

        panel.add(Box.createVerticalStrut(24));
        panel.add(makeSectionLabel("About"));
        JTextArea info = new JTextArea(
            "WASM Analyzer v1.0.0\n\n" +
            "Analyzes WebAssembly binaries in Burp Suite.\n" +
            "Features:\n" +
            "  - Pure Java WASM parser (no external deps)\n" +
            "  - WAT disassembly\n" +
            "  - Secret scanner\n" +
            "  - Security vulnerability scanner\n" +
            "  - Source map probing\n\n" +
            "Decompiled output is read-only.\n" +
            "To recompile WAT, use wabt tools externally."
        );
        info.setEditable(false);
        info.setBackground(panel.getBackground());
        info.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        info.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(info);
    }

    public JComponent getComponent() { return new JScrollPane(panel); }

    private void save() {
        ExtensionSettings s = ExtensionSettings.getInstance();
        s.setAutoProbeSourceMap(autoProbeCheckbox.isSelected());
        saveStatus.setText("Settings saved.");
        WasmAnalyzerExtension.logger.logToOutput("[WASM Analyzer] Settings saved.");
    }

    private JLabel makeSectionLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setFont(lbl.getFont().deriveFont(Font.BOLD, 13f));
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        return lbl;
    }
}