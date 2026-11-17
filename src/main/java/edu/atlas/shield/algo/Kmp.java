package edu.atlas.shield.algo;

import java.util.ArrayList;
import java.util.List;

/**
 * Knuth–Morris–Pratt single-pattern search (Unit 4).
 * Used as the baseline for the trie: checking k signatures with KMP costs O(k * n).
 * Time O(n + m) per pattern, space O(m) for the prefix table.
 */
public final class Kmp {

    private Kmp() {}

    /** pi[i] = length of the longest proper prefix of p[0..i] that is also a suffix of it. */
    public static int[] prefixFunction(String p) {
        int[] pi = new int[p.length()];
        for (int i = 1, len = 0; i < p.length(); i++) {
            while (len > 0 && p.charAt(i) != p.charAt(len)) len = pi[len - 1];
            if (p.charAt(i) == p.charAt(len)) len++;
            pi[i] = len;
        }
        return pi;
    }

    /** Start indexes of every (possibly overlapping) occurrence of pattern in text. */
    public static List<Integer> findAll(String text, String pattern) {
        if (pattern == null || pattern.isEmpty()) throw new IllegalArgumentException("pattern must be non-empty");
        List<Integer> hits = new ArrayList<>();
        if (text == null || pattern.length() > text.length()) return hits;
        int[] pi = prefixFunction(pattern);
        for (int i = 0, len = 0; i < text.length(); i++) {
            while (len > 0 && text.charAt(i) != pattern.charAt(len)) len = pi[len - 1];
            if (text.charAt(i) == pattern.charAt(len)) len++;
            if (len == pattern.length()) {
                hits.add(i - len + 1);
                len = pi[len - 1];
            }
        }
        return hits;
    }
}
