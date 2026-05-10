package com.wasmanalyzer.parser;

public class WasmExport {
    public final String name;
    public final String kind;
    public final int index;

    public WasmExport(String name, String kind, int index) {
        this.name = name;
        this.kind = kind;
        this.index = index;
    }

    @Override
    public String toString() {
        return String.format("%s (%s #%d)", name, kind, index);
    }
}
