package com.wasmanalyzer.ui;

import burp.api.montoya.ui.editor.extension.*;
import com.wasmanalyzer.detector.WasmDetector;

public class WasmMessageEditorTabFactory
        implements HttpRequestEditorProvider, HttpResponseEditorProvider {

    private final WasmDetector detector = new WasmDetector();

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
        return new WasmEditorTab(ctx, false, detector);
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext ctx) {
        return new WasmEditorTab(ctx, true, detector);
    }
}
