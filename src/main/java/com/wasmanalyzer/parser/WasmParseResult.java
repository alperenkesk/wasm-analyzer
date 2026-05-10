package com.wasmanalyzer.parser;

import java.util.ArrayList;
import java.util.List;

public class WasmParseResult {
    public int version;
    public int totalBytes;
    public int typeCount;
    public int functionCount;
    public String error;

    public List<WasmSection> sections = new ArrayList<>();
    public List<WasmImport> imports = new ArrayList<>();
    public List<WasmExport> exports = new ArrayList<>();
    public List<List<String>> dataSegments = new ArrayList<>();

    public boolean hasError() {
        return error != null && !error.isEmpty();
    }

    /** Flattened list of all strings from all data segments */
    public List<String> allStrings() {
        List<String> all = new ArrayList<>();
        for (List<String> seg : dataSegments) all.addAll(seg);
        return all;
    }
}
