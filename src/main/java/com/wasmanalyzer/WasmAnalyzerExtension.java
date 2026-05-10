package com.wasmanalyzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.wasmanalyzer.handler.WasmHttpHandler;
import com.wasmanalyzer.ui.AnalyzerToolTab;
import com.wasmanalyzer.ui.WasmContextMenu;
import com.wasmanalyzer.ui.WasmMessageEditorTabFactory;

public class WasmAnalyzerExtension implements BurpExtension {

    public static MontoyaApi      api;
    public static Logging         logger;
    public static AnalyzerToolTab analyzerTab;

    private WasmHttpHandler httpHandler;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        api    = montoyaApi;
        logger = api.logging();

        api.extension().setName("WASM Analyzer");

        analyzerTab = new AnalyzerToolTab();
        api.userInterface().registerSuiteTab("WASM Analyzer", analyzerTab.getComponent());

        WasmMessageEditorTabFactory editorFactory = new WasmMessageEditorTabFactory();
        api.userInterface().registerHttpRequestEditorProvider(editorFactory);
        api.userInterface().registerHttpResponseEditorProvider(editorFactory);

        api.userInterface().registerContextMenuItemsProvider(new WasmContextMenu());

        httpHandler = new WasmHttpHandler();
        api.http().registerHttpHandler(httpHandler);

        api.extension().registerUnloadingHandler(this::extensionUnloaded);

        logger.logToOutput("[WASM Analyzer] Extension loaded successfully.");
    }

    private void extensionUnloaded() {
        logger.logToOutput("[WASM Analyzer] Extension unloading...");

        if (httpHandler != null) {
            httpHandler.shutdown();
        }

        if (analyzerTab != null) {
            analyzerTab.shutdown();
        }

        logger.logToOutput("[WASM Analyzer] Extension unloaded cleanly.");
    }
}