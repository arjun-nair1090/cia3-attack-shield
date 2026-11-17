package edu.atlas.shield.algo;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class KmpTest {

    @Test
    void prefixFunctionMatchesTextbookExample() {
        assertArrayEquals(new int[]{0, 0, 1, 2, 3, 0, 1}, Kmp.prefixFunction("ababaca"));
    }

    @Test
    void findsOverlappingOccurrences() {
        assertEquals(List.of(0, 1, 2), Kmp.findAll("aaaaaa", "aaaa"));
    }

    @Test
    void patternLongerThanTextFindsNothing() {
        assertEquals(List.of(), Kmp.findAll("ab", "abc"));
        assertEquals(List.of(), Kmp.findAll("", "a"));
        assertEquals(List.of(), Kmp.findAll(null, "a"));
    }

    @Test
    void rejectsEmptyPattern() {
        assertThrows(IllegalArgumentException.class, () -> Kmp.findAll("abc", ""));
        assertThrows(IllegalArgumentException.class, () -> Kmp.findAll("abc", null));
    }

    @Test
    void agreesWithIndexOfOnRandomStrings() {
        Random r = new Random(42);
        for (int t = 0; t < 500; t++) {
            String text = randomAb(r, 1 + r.nextInt(60)), pat = randomAb(r, 1 + r.nextInt(5));
            List<Integer> expected = new ArrayList<>();
            for (int i = text.indexOf(pat); i >= 0; i = text.indexOf(pat, i + 1)) expected.add(i);
            assertEquals(expected, Kmp.findAll(text, pat), text + " / " + pat);
        }
    }

    static String randomAb(Random r, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append((char) ('a' + r.nextInt(2)));
        return sb.toString();
    }
}
