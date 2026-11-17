package edu.atlas.shield.algo;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class SignatureTrieTest {

    private static SignatureTrie trie(String... sigs) {
        SignatureTrie t = new SignatureTrie();
        for (String s : sigs) t.add(s, "TEST");
        return t;
    }

    @Test
    void detectsSqlInjectionInQuery() {
        SignatureTrie t = new SignatureTrie();
        t.add("' or 1=1", "SQLI");
        t.add("<script", "XSS");
        List<SignatureTrie.Match> m = t.scan("/shop/search?q=' or 1=1--");
        assertEquals(1, m.size());
        assertEquals(new SignatureTrie.Match("' or 1=1", "SQLI", 15), m.get(0));
    }

    @Test
    void reportsNestedAndOverlappingSignatures() {
        List<SignatureTrie.Match> m = trie("../", "../../etc/passwd").scan("../../etc/passwd");
        assertEquals(3, m.size()); // "../" at 0 and 3, full path at 0
    }

    @Test
    void cleanAndEmptyInputMatchNothing() {
        SignatureTrie t = trie("union select", "<script");
        assertTrue(t.scan("/shop/search?q=running+shoes").isEmpty());
        assertTrue(t.scan("").isEmpty());
        assertTrue(t.scan(null).isEmpty());
    }

    @Test
    void boundarySignatureAtVeryEndAndDuplicates() {
        SignatureTrie t = trie("sleep(", "sleep(");
        assertEquals(1, t.size());
        assertEquals(List.of(new SignatureTrie.Match("sleep(", "TEST", 3)), t.scan("id=sleep("));
        assertThrows(IllegalArgumentException.class, () -> t.add("", "X"));
    }

    @Test
    void agreesWithKmpBaselineOnRandomText() {
        Random r = new Random(7);
        for (int t = 0; t < 200; t++) {
            List<String> sigs = new ArrayList<>();
            for (int i = 0; i < 1 + r.nextInt(6); i++) sigs.add(KmpTest.randomAb(r, 1 + r.nextInt(4)));
            String text = KmpTest.randomAb(r, r.nextInt(50));
            SignatureTrie trie = trie(sigs.toArray(String[]::new));

            List<String> expected = new ArrayList<>();
            for (String s : sigs.stream().distinct().toList())
                for (int pos : Kmp.findAll(text, s)) expected.add(pos + ":" + s);
            List<String> actual = new ArrayList<>(trie.scan(text).stream().map(m -> m.position() + ":" + m.signature()).toList());
            expected.sort(Comparator.naturalOrder());
            actual.sort(Comparator.naturalOrder());
            assertEquals(expected, actual);
        }
    }
}
