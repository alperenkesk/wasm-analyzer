package com.wasmanalyzer.parser;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure-Java WebAssembly binary parser — no external dependencies.
 * Parses section structure, imports, exports, and data segment strings.
 * WAT decompilation is delegated to wasm2wat (see WasmPatcher).
 */
public class WasmParser {

    private static final int WASM_MAGIC   = 0x6D736100; // '\0asm' little-endian
    private static final int MIN_STR_LEN  = 4;
    private static final int MAX_STRINGS_PER_SEGMENT = 5_000;

    public WasmParseResult parse(byte[] wasmBytes) {
        WasmParseResult result = new WasmParseResult();

        if (wasmBytes == null || wasmBytes.length < 8) {
            result.error = "Too short to be a valid WASM module (need ≥ 8 bytes)";
            return result;
        }

        ByteBuffer buf = ByteBuffer.wrap(wasmBytes).order(ByteOrder.LITTLE_ENDIAN);

        int magic = buf.getInt();
        if (magic != WASM_MAGIC) {
            result.error = String.format("Invalid magic bytes: 0x%08X (expected 0x%08X)", magic, WASM_MAGIC);
            return result;
        }
        result.version    = buf.getInt();
        result.totalBytes = wasmBytes.length;

        while (buf.remaining() >= 2) {
            int sectionId   = buf.get() & 0xFF;
            long sectionSize = readULEB128(buf);
            if (sectionSize < 0 || sectionSize > buf.remaining()) break;

            int sectionStart = buf.position();
            int sectionEnd   = sectionStart + (int) sectionSize;

            try {
                switch (sectionId) {
                    case 1  -> parseTypeSection(buf, result, sectionEnd);
                    case 2  -> parseImportSection(buf, result, sectionEnd);
                    case 3  -> parseFunctionSection(buf, result, sectionEnd);
                    case 7  -> parseExportSection(buf, result, sectionEnd);
                    case 10 -> result.sections.add(new WasmSection(10, (int) sectionSize, "code",
                                    result.functionCount + " function bodies"));
                    case 11 -> parseDataSection(buf, result, sectionEnd);
                    default -> result.sections.add(new WasmSection(sectionId, (int) sectionSize));
                }
            } catch (Exception e) {
                // Section parse failed — record it and move on
                result.sections.add(new WasmSection(sectionId, (int) sectionSize,
                    WasmSection.sectionName(sectionId), "(parse error: " + e.getMessage() + ")"));
            }

            // Always seek to next section boundary — protects against partial reads
            if (sectionEnd <= buf.limit()) {
                buf.position(sectionEnd);
            } else {
                break;
            }
        }

        return result;
    }

    // ── Section parsers ────────────────────────────────────────────────────────

    private void parseTypeSection(ByteBuffer buf, WasmParseResult r, int end) {
        int count = (int) readULEB128(buf);
        r.typeCount = count;
        r.sections.add(new WasmSection(1, 0, "type", count + " function signatures"));
        for (int i = 0; i < count && buf.position() < end; i++) {
            int form = buf.get() & 0xFF;
            if (form == 0x60) { // func type
                skipVecTypes(buf, end);  // params
                skipVecTypes(buf, end);  // returns
            }
        }
    }

    private void parseImportSection(ByteBuffer buf, WasmParseResult r, int end) {
        int count = (int) readULEB128(buf);
        r.sections.add(new WasmSection(2, 0, "import", count + " imports"));
        for (int i = 0; i < count && buf.position() < end; i++) {
            String module = readString(buf, end);
            String name   = readString(buf, end);
            int kind      = buf.get() & 0xFF;
            readULEB128(buf);  // index
            r.imports.add(new WasmImport(module, name, kindName(kind)));
        }
    }

    private void parseFunctionSection(ByteBuffer buf, WasmParseResult r, int end) {
        int count = (int) readULEB128(buf);
        r.functionCount = count;
        r.sections.add(new WasmSection(3, 0, "function", count + " declarations"));
        for (int i = 0; i < count && buf.position() < end; i++) readULEB128(buf);
    }

    private void parseExportSection(ByteBuffer buf, WasmParseResult r, int end) {
        int count = (int) readULEB128(buf);
        r.sections.add(new WasmSection(7, 0, "export", count + " exports"));
        for (int i = 0; i < count && buf.position() < end; i++) {
            String name = readString(buf, end);
            int kind    = buf.get() & 0xFF;
            int index   = (int) readULEB128(buf);
            r.exports.add(new WasmExport(name, kindName(kind), index));
        }
    }

    private void parseDataSection(ByteBuffer buf, WasmParseResult r, int sectionEnd) {
        int count = (int) readULEB128(buf);
        r.sections.add(new WasmSection(11, 0, "data", count + " segments"));

        for (int i = 0; i < count && buf.position() < sectionEnd; i++) {
            long flags = readULEB128(buf);

            // Active segment: skip init expression
            if (flags == 0) {
                skipInitExpr(buf, sectionEnd);
            } else if (flags == 2) {
                readULEB128(buf);               // explicit memory index
                skipInitExpr(buf, sectionEnd);
            }
            // flags == 1 → passive, no init expr

            long dataLen = readULEB128(buf);
            int  len     = (int) Math.min(dataLen, Math.max(0, sectionEnd - buf.position()));
            if (len < 0 || buf.position() + len > buf.limit()) break;

            byte[] segBytes = new byte[len];
            buf.get(segBytes);
            r.dataSegments.add(extractStrings(segBytes));
        }
    }

    // ── String extraction ──────────────────────────────────────────────────────

    /** Extracts printable ASCII runs of length ≥ MIN_STR_LEN from a raw byte segment. */
    private List<String> extractStrings(byte[] data) {
        List<String> strings  = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        for (byte b : data) {
            char c = (char) (b & 0xFF);
            if (c >= 0x20 && c < 0x7F) {
                current.append(c);
            } else {
                if (current.length() >= MIN_STR_LEN) {
                    strings.add(current.toString());
                    if (strings.size() >= MAX_STRINGS_PER_SEGMENT) break;
                }
                current.setLength(0);
            }
        }
        if (current.length() >= MIN_STR_LEN && strings.size() < MAX_STRINGS_PER_SEGMENT) {
            strings.add(current.toString());
        }
        return strings;
    }

    // ── Low-level helpers ──────────────────────────────────────────────────────

    private void skipInitExpr(ByteBuffer buf, int limit) {
        while (buf.position() < limit && buf.hasRemaining()) {
            if ((buf.get() & 0xFF) == 0x0B) break; // 'end' opcode
        }
    }

    private void skipVecTypes(ByteBuffer buf, int end) {
        int n = (int) readULEB128(buf);
        for (int i = 0; i < n && buf.position() < end; i++) buf.get();
    }

    private String readString(ByteBuffer buf, int end) {
        int len = (int) readULEB128(buf);
        if (len <= 0 || buf.position() + len > end || buf.position() + len > buf.limit()) return "";
        byte[] bytes = new byte[len];
        buf.get(bytes);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    private long readULEB128(ByteBuffer buf) {
        long result = 0;
        int  shift  = 0;
        while (buf.hasRemaining() && shift < 63) {
            int b = buf.get() & 0xFF;
            result |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return result;
    }

    private String kindName(int kind) {
        return switch (kind) {
            case 0 -> "func";
            case 1 -> "table";
            case 2 -> "memory";
            case 3 -> "global";
            default -> "unknown(" + kind + ")";
        };
    }
}
