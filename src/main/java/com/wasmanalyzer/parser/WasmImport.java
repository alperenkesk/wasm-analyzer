package com.wasmanalyzer.parser;

public class WasmImport {
    public final String module;
    public final String name;
    public final String kind;

    public WasmImport(String module, String name, String kind) {
        this.module = module;
        this.name = name;
        this.kind = kind;
    }

    @Override
    public String toString() {
        return String.format("%s::%s (%s)", module, name, kind);
    }
}
