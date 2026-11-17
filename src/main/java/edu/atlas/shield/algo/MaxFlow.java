package edu.atlas.shield.algo;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Edmonds–Karp max-flow with min-cut extraction (Unit 5).
 * Models the defended network (internet -> edge -> load balancer -> app servers -> DB) with link
 * capacities in requests/s; the max flow is the most traffic it can carry and the min cut is the
 * set of saturated links an attacker should hit first — i.e. the bottleneck to reinforce.
 * Time O(V * E^2), space O(V + E).
 */
public final class MaxFlow {

    public record Edge(int from, int to, long capacity) {}

    /** augmentingPaths: BFS rounds that pushed flow; Edmonds–Karp bounds it by O(V * E) whatever the capacities. */
    public record Result(long maxFlow, List<Edge> minCut, boolean[] sourceSide, int augmentingPaths) {}

    private final int n;
    private final List<Integer>[] adj; // edge indexes leaving each node
    private final List<Integer> to = new ArrayList<>();
    private final List<Long> cap = new ArrayList<>();
    private final List<Edge> original = new ArrayList<>();

    @SuppressWarnings("unchecked")
    public MaxFlow(int nodes) {
        if (nodes < 2) throw new IllegalArgumentException("need at least 2 nodes");
        n = nodes;
        adj = new List[n];
        for (int i = 0; i < n; i++) adj[i] = new ArrayList<>();
    }

    /** Adds a directed link; edge e and its residual twin are stored at indexes e and e ^ 1. */
    public void addEdge(int u, int v, long capacity) {
        checkNode(u);
        checkNode(v);
        if (capacity < 0) throw new IllegalArgumentException("capacity must be >= 0");
        adj[u].add(to.size());
        to.add(v); cap.add(capacity);
        adj[v].add(to.size());
        to.add(u); cap.add(0L);
        original.add(new Edge(u, v, capacity));
    }

    public Result solve(int s, int t) {
        checkNode(s);
        checkNode(t);
        if (s == t) throw new IllegalArgumentException("source and sink must differ");
        long[] residual = cap.stream().mapToLong(Long::longValue).toArray();
        long flow = 0;
        int paths = 0;
        int[] parentEdge = new int[n];
        while (bfs(s, t, residual, parentEdge)) {
            long push = Long.MAX_VALUE;
            for (int v = t; v != s; v = to.get(parentEdge[v] ^ 1)) push = Math.min(push, residual[parentEdge[v]]);
            for (int v = t; v != s; v = to.get(parentEdge[v] ^ 1)) {
                residual[parentEdge[v]] -= push;
                residual[parentEdge[v] ^ 1] += push;
            }
            // Each residual pair sums to its capacity, so only the running total can overflow.
            if (push > Long.MAX_VALUE - flow) throw new IllegalArgumentException("max flow exceeds " + Long.MAX_VALUE + "; use smaller capacities");
            flow += push;
            paths++;
        }
        // After the last failed BFS, parentEdge marks exactly the nodes reachable from s in the residual graph.
        boolean[] sourceSide = new boolean[n];
        for (int v = 0; v < n; v++) sourceSide[v] = v == s || parentEdge[v] >= 0;
        List<Edge> cut = new ArrayList<>();
        for (Edge e : original) if (sourceSide[e.from()] && !sourceSide[e.to()] && e.capacity() > 0) cut.add(e);
        return new Result(flow, cut, sourceSide, paths);
    }

    /** Shortest augmenting path by edge count — this choice is what makes it Edmonds–Karp. */
    private boolean bfs(int s, int t, long[] residual, int[] parentEdge) {
        Arrays.fill(parentEdge, -1);
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        queue.add(s);
        boolean[] seen = new boolean[n];
        seen[s] = true;
        while (!queue.isEmpty()) {
            int u = queue.poll();
            for (int e : adj[u]) {
                int v = to.get(e);
                if (!seen[v] && residual[e] > 0) {
                    seen[v] = true;
                    parentEdge[v] = e;
                    if (v == t) return true;
                    queue.add(v);
                }
            }
        }
        return false;
    }

    private void checkNode(int v) {
        if (v < 0 || v >= n) throw new IllegalArgumentException("node " + v + " outside [0, " + (n - 1) + "]");
    }
}
