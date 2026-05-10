package com.wasmanalyzer.settings;

import java.util.prefs.Preferences;

public class ExtensionSettings {

    private static ExtensionSettings INSTANCE;
    
    private static final String KEY_AUTO_PROBE_MAP = "auto_probe_sourcemap";

    private final Preferences prefs;

    public ExtensionSettings() {
        prefs = Preferences.userNodeForPackage(ExtensionSettings.class);
    }

    public static ExtensionSettings getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new ExtensionSettings();
        }
        return INSTANCE;
    }

    public boolean isAutoProbeSourceMap() {
        return prefs.getBoolean(KEY_AUTO_PROBE_MAP, true);
    }

    public void setAutoProbeSourceMap(boolean value) {
        prefs.putBoolean(KEY_AUTO_PROBE_MAP, value);
    }
}
