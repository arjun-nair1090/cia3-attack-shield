package edu.atlas.shield.algo;

import java.util.Objects;

/**
 * Bloom filter over strings (Unit 6, CO5).
 * A miss means "definitely absent"; a hit means only "possibly present" and
 * must be confirmed by an exact lookup before acting on it.
 *
 * Sizing: m = -n ln p / (ln 2)^2 bits, k = (m / n) ln 2 hash functions.
 * Hashing: one 64-bit hash split into h1, h2; i-th index = h1 + i*h2 (Kirsch–Mitzenmacher).
 * Time O(k) per add / query, space O(m) bits.
 */
public final class BloomFilter {

    private final long[] bits;
    private final int m;
    private final int k;
    private int inserted;

    public BloomFilter(int expectedItems, double falsePositiveRate) {
        if (expectedItems <= 0) throw new IllegalArgumentException("expectedItems must be > 0");
        if (!(falsePositiveRate > 0 && falsePositiveRate < 1))
            throw new IllegalArgumentException("falsePositiveRate must be in (0, 1)");
        double ln2 = Math.log(2);
        double needed = Math.ceil(-expectedItems * Math.log(falsePositiveRate) / (ln2 * ln2));
        if (needed > Integer.MAX_VALUE - 64) throw new IllegalArgumentException("filter would exceed 2^31 bits");
        m = (int) Math.max(64, needed);
        k = Math.max(1, (int) Math.round((double) m / expectedItems * ln2));
        bits = new long[(m + 63) >>> 6];
    }

    public void add(String item) {
        long h = hash64(Objects.requireNonNull(item, "item"));
        int h1 = (int) h, h2 = (int) (h >>> 32) | 1; // odd step so the k probes never collapse to one bit
        for (int i = 0; i < k; i++) {
            int idx = Math.floorMod(h1 + i * h2, m);
            bits[idx >>> 6] |= 1L << idx;
        }
        inserted++;
    }

    public boolean mightContain(String item) {
        long h = hash64(Objects.requireNonNull(item, "item"));
        int h1 = (int) h, h2 = (int) (h >>> 32) | 1;
        for (int i = 0; i < k; i++) {
            int idx = Math.floorMod(h1 + i * h2, m);
            if ((bits[idx >>> 6] & (1L << idx)) == 0) return false;
        }
        return true;
    }

    /** Theoretical false-positive rate for the current fill: (1 - e^(-kn/m))^k. */
    public double expectedFalsePositiveRate() {
        return Math.pow(1 - Math.exp(-(double) k * inserted / m), k);
    }

    public int bitCount() { return m; }
    public int hashCount() { return k; }
    public int size() { return inserted; }

    /** FNV-1a 64 followed by the SplitMix64 finalizer so every output bit depends on every input char. */
    static long hash64(String s) {
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < s.length(); i++) {
            h ^= s.charAt(i);
            h *= 0x100000001b3L;
        }
        h = (h ^ (h >>> 30)) * 0xbf58476d1ce4e5b9L;
        h = (h ^ (h >>> 27)) * 0x94d049bb133111ebL;
        return h ^ (h >>> 31);
    }
}
