package edu.atlas.shield.algo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Trie of attack signatures (Unit 4). One pass over the request text, walking the trie
 * from every start position, reports every signature that occurs anywhere in it.
 * Build O(total signature length); scan O(n * L) where L = longest signature, independent
 * of how many signatures are loaded. Baseline: one KMP pass per signature, O(k * n).
 */
public final class SignatureTrie {

    public record Match(String signature, String category, int position) {}

    private static final class Node {
        final Map<Character, Node> next = new HashMap<>();
        String signature;
        String category;
    }

    private final Node root = new Node();
    private int size;

    public void add(String signature, String category) {
        if (signature == null || signature.isEmpty()) throw new IllegalArgumentException("signature must be non-empty");
        Node cur = root;
        for (int i = 0; i < signature.length(); i++) cur = cur.next.computeIfAbsent(signature.charAt(i), c -> new Node());
        if (cur.signature == null) size++;
        cur.signature = signature;
        cur.category = category;
    }

    public List<Match> scan(String text) {
        List<Match> found = new ArrayList<>();
        if (text == null) return found;
        for (int start = 0; start < text.length(); start++) {
            Node cur = root;
            for (int i = start; i < text.length(); i++) {
                cur = cur.next.get(text.charAt(i));
                if (cur == null) break;
                if (cur.signature != null) found.add(new Match(cur.signature, cur.category, start));
            }
        }
        return found;
    }

    public int size() { return size; }
}
