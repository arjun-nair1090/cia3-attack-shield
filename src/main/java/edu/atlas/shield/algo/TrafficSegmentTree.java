package edu.atlas.shield.algo;

/**
 * Segment tree over per-second request counts (Unit 3).
 * Answers "how many requests between second l and r?" and "which second in [l, r] peaked?"
 * Update O(log n), query O(log n), space O(n). Baseline: plain array, O(1) update / O(n) query.
 */
public final class TrafficSegmentTree {

    private final int n;
    private final long[] sum;
    private final int[] maxIdx; // index of the leftmost maximum leaf in the node's range
    private final long[] leaf;

    public TrafficSegmentTree(int buckets) {
        if (buckets <= 0) throw new IllegalArgumentException("buckets must be > 0");
        n = buckets;
        sum = new long[4 * n];
        maxIdx = new int[4 * n];
        leaf = new long[n];
        build(1, 0, n - 1);
    }

    public int size() { return n; }

    public long get(int i) { check(i, i); return leaf[i]; }

    public void add(int i, long delta) { set(i, get(i) + delta); }

    public void set(int i, long value) {
        check(i, i);
        leaf[i] = value;
        update(1, 0, n - 1, i);
    }

    public long sum(int l, int r) { check(l, r); return sum(1, 0, n - 1, l, r); }

    /** Leftmost index of the maximum count in [l, r]. */
    public int argMax(int l, int r) { check(l, r); return argMax(1, 0, n - 1, l, r); }

    private void build(int node, int lo, int hi) {
        if (lo == hi) { maxIdx[node] = lo; return; }
        int mid = (lo + hi) >>> 1;
        build(2 * node, lo, mid);
        build(2 * node + 1, mid + 1, hi);
        maxIdx[node] = lo;
    }

    private void update(int node, int lo, int hi, int i) {
        if (lo == hi) { sum[node] = leaf[i]; return; }
        int mid = (lo + hi) >>> 1;
        if (i <= mid) update(2 * node, lo, mid, i); else update(2 * node + 1, mid + 1, hi, i);
        sum[node] = sum[2 * node] + sum[2 * node + 1];
        maxIdx[node] = better(maxIdx[2 * node], maxIdx[2 * node + 1]);
    }

    private long sum(int node, int lo, int hi, int l, int r) {
        if (r < lo || hi < l) return 0;
        if (l <= lo && hi <= r) return sum[node];
        int mid = (lo + hi) >>> 1;
        return sum(2 * node, lo, mid, l, r) + sum(2 * node + 1, mid + 1, hi, l, r);
    }

    private int argMax(int node, int lo, int hi, int l, int r) {
        if (r < lo || hi < l) return -1;
        if (l <= lo && hi <= r) return maxIdx[node];
        int mid = (lo + hi) >>> 1;
        return better(argMax(2 * node, lo, mid, l, r), argMax(2 * node + 1, mid + 1, hi, l, r));
    }

    /** a always comes from the left half, so on a tie keeping a gives the leftmost index. -1 = none. */
    private int better(int a, int b) {
        if (a < 0) return b;
        if (b < 0) return a;
        return leaf[b] > leaf[a] ? b : a;
    }

    private void check(int l, int r) {
        if (l < 0 || r >= n || l > r) throw new IndexOutOfBoundsException("range [" + l + ", " + r + "] outside [0, " + (n - 1) + "]");
    }
}
