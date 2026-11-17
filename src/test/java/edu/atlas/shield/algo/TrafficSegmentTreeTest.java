package edu.atlas.shield.algo;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class TrafficSegmentTreeTest {

    @Test
    void sumAndArgMaxMatchBruteForceUnderRandomUpdates() {
        Random r = new Random(1);
        int n = 300;
        TrafficSegmentTree t = new TrafficSegmentTree(n);
        long[] a = new long[n];
        for (int op = 0; op < 5_000; op++) {
            int i = r.nextInt(n);
            if (r.nextBoolean()) { long d = r.nextInt(50); a[i] += d; t.add(i, d); }
            else { long v = r.nextInt(50); a[i] = v; t.set(i, v); }
            int l = r.nextInt(n), h = l + r.nextInt(n - l);
            long s = 0; int best = l;
            for (int j = l; j <= h; j++) { s += a[j]; if (a[j] > a[best]) best = j; }
            assertEquals(s, t.sum(l, h));
            assertEquals(best, t.argMax(l, h));
        }
    }

    @Test
    void boundarySingleBucket() {
        TrafficSegmentTree t = new TrafficSegmentTree(1);
        t.add(0, 5);
        assertEquals(5, t.sum(0, 0));
        assertEquals(0, t.argMax(0, 0));
    }

    @Test
    void setOverwritesInsteadOfAdding() {
        TrafficSegmentTree t = new TrafficSegmentTree(10);
        t.add(3, 100);
        t.set(3, 0); // ring-buffer reuse: an old second is cleared before reuse
        assertEquals(0, t.sum(0, 9));
    }

    @Test
    void tiesPickEarliestSecondAndEmptyTreeIsAllZero() {
        TrafficSegmentTree t = new TrafficSegmentTree(8);
        assertEquals(0, t.sum(0, 7));
        assertEquals(0, t.argMax(0, 7));
        t.set(2, 9);
        t.set(6, 9);
        assertEquals(2, t.argMax(0, 7));
        assertEquals(6, t.argMax(3, 7));
    }

    @Test
    void rejectsInvalidRanges() {
        assertThrows(IllegalArgumentException.class, () -> new TrafficSegmentTree(0));
        TrafficSegmentTree t = new TrafficSegmentTree(5);
        assertThrows(IndexOutOfBoundsException.class, () -> t.sum(3, 2));
        assertThrows(IndexOutOfBoundsException.class, () -> t.sum(-1, 2));
        assertThrows(IndexOutOfBoundsException.class, () -> t.add(5, 1));
    }
}
