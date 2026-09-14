package com.example.demo;

import java.util.ArrayList;
import java.util.List;

public class Inventory {
    private final String label;
    private final List<String> items = new ArrayList<>();

    public Inventory(String label) {
        this.label = label;
    }

    public void add(String item) {
        if (item == null || item.isEmpty()) {
            throw new IllegalArgumentException("empty item");
        }
        items.add(item);
    }

    public int count() {
        return items.size();
    }

    public String largest() {
        String best = "";
        for (String it : items) {
            if (it.length() > best.length()) {
                best = it;
            }
        }
        return best;
    }

    public boolean contains(String item) {
        return items.contains(item);
    }
}
