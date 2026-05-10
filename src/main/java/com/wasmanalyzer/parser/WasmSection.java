package com.wasmanalyzer.parser;

public class WasmSection {
    public final int id;
    public final int sizeBytes;
    public final String name;
    public final String description;

    public WasmSection(int id, int sizeBytes) {
        this(id, sizeBytes, sectionName(id), "");
    }

    public WasmSection(int id, int sizeBytes, String name, String description) {
        this.id = id;
        this.sizeBytes = sizeBytes;
        this.name = name;
        this.description = description;
    }

    public static String sectionName(int id) {
        return switch (id) {
            case 0 -> "custom";
            case 1 -> "type";
            case 2 -> "import";
            case 3 -> "function";
            case 4 -> "table";
            case 5 -> "memory";
            case 6 -> "global";
            case 7 -> "export";
            case 8 -> "start";
            case 9 -> "element";
            case 10 -> "code";
            case 11 -> "data";
            case 12 -> "data count";
            default -> "unknown(" + id + ")";
        };
    }

    @Override
    public String toString() {
        return String.format("[%d] %s — %s", id, name, description);
    }
}
