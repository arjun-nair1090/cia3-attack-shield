package edu.atlas.shield.algo;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BloomFilterTest {

    private static String ip(int i) {
        return (i >>> 24 & 255) + "." + (i >>> 16 & 255) + "." + (i >>> 8 & 255) + "." + (i & 255);
    }

    @Test
    void neverReturnsFalseNegatives() {
        BloomFilter f = new BloomFilter(10_000, 0.01);
        for (int i = 0; i < 10_000; i++) f.add(ip(i * 7919));
        for (int i = 0; i < 10_000; i++) assertTrue(f.mightContain(ip(i * 7919)));
    }

    @Test
    void measuredFalsePositiveRateStaysNearTarget() {
        BloomFilter f = new BloomFilter(10_000, 0.01);
        for (int i = 0; i < 10_000; i++) f.add("bad-" + i);
        int fp = 0, trials = 100_000;
        for (int i = 0; i < trials; i++) if (f.mightContain("good-" + i)) fp++;
        double rate = (double) fp / trials;
        assertTrue(rate < 0.02, "measured FPR " + rate + " should be close to 1%");
        assertEquals(0.01, f.expectedFalsePositiveRate(), 0.005);
    }

    @Test
    void emptyFilterContainsNothing() {
        BloomFilter f = new BloomFilter(100, 0.01);
        assertFalse(f.mightContain("1.2.3.4"));
        assertFalse(f.mightContain(""));
        assertEquals(0.0, f.expectedFalsePositiveRate());
    }

    @Test
    void boundarySingleItemFilter() {
        BloomFilter f = new BloomFilter(1, 0.5);
        assertTrue(f.bitCount() >= 64 && f.hashCount() >= 1);
        f.add("only");
        assertTrue(f.mightContain("only"));
    }

    @Test
    void probesAreExactlyTheBitsAnAddSets() {
        BloomFilter f = new BloomFilter(1_000, 0.01);
        f.add("45.148.10.151");
        long[] w = f.words();
        int[] p = f.probes("45.148.10.151");
        assertEquals(f.hashCount(), p.length);
        int set = 0;
        for (long word : w) set += Long.bitCount(word);
        for (int i : p) assertTrue((w[i >>> 6] & (1L << i)) != 0, "probe " + i + " must be set");
        assertTrue(set <= p.length); // nothing else was set
    }

    @Test
    void rejectsInvalidInput() {
        assertThrows(IllegalArgumentException.class, () -> new BloomFilter(0, 0.01));
        assertThrows(IllegalArgumentException.class, () -> new BloomFilter(10, 0));
        assertThrows(IllegalArgumentException.class, () -> new BloomFilter(10, 1));
        assertThrows(IllegalArgumentException.class, () -> new BloomFilter(10, Double.NaN));
        BloomFilter f = new BloomFilter(10, 0.01);
        assertThrows(NullPointerException.class, () -> f.add(null));
        assertThrows(NullPointerException.class, () -> f.mightContain(null));
    }
}
