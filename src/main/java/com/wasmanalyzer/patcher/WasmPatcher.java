package com.wasmanalyzer.patcher;

import com.wasmanalyzer.parser.WatWriter;

public class WasmPatcher {

    private final WatWriter pureJavaWriter = new WatWriter();

    public String decompile(byte[] wasmBytes) {
        return pureJavaWriter.toWat(wasmBytes);
    }

    public byte[] recompile(String watText) throws PatchException {
        throw new PatchException(
            "WAT to WASM recompilation requires wabt (wat2wasm).\n" +
            "Install: brew install wabt (macOS/Linux) or apt install wabt (Linux)\n" +
            "Then configure path in WASM Analyzer Settings.");
    }

    public static class PatchException extends Exception {
        public PatchException(String msg) { super(msg); }
    }
}