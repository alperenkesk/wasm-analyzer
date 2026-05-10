package com.wasmanalyzer.model;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public class WasmCaptureStore {

    private final List<WasmCapture> captures = new CopyOnWriteArrayList<>();
    private final List<Consumer<WasmCapture>> listeners = new CopyOnWriteArrayList<>();

    public void add(WasmCapture capture) {
        captures.add(capture);
        listeners.forEach(l -> l.accept(capture));
    }

    public List<WasmCapture> getAll() {
        return Collections.unmodifiableList(captures);
    }

    public void clear() {
        captures.clear();
    }

    public void addListener(Consumer<WasmCapture> listener) {
        listeners.add(listener);
    }

    public int size() {
        return captures.size();
    }
}
