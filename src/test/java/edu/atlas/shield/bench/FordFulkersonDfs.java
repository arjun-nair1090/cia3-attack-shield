package edu.atlas.shield.bench;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Benchmark baseline only, never used by the app: Ford–Fulkerson that takes the first augmenting path a
 * depth-first search finds. Same residual-graph representation as {@code MaxFlow}, so the only difference
 * measured is DFS paths versus Edmonds–Karp's shortest (BFS) paths. Time O(E * maxFlow) for integer capacities.
 */
final class FordFulkersonDfs {

    private final int n;
    private final List<Integer>[] adj;
    private final List<Integer> to = new ArrayList<>();
    private final List<Long> cap = new ArrayList<>();

    @SuppressWarnings("unchecked")
    FordFulkersonDfs(int nodes) {
        n = nodes;
        adj = new List[n];
        for (int i = 0; i < n; i++) adj[i] = new ArrayList<>();
    }

    void addEdge(int u, int v, long capacity) {
        adj[u].add(to.size());
        to.add(v); cap.add(capacity);
        adj[v].add(to.size());
        to.add(u); cap.add(0L);
    }

    /**
     * @param deadline System.nanoTime() after which to give up (DFS paths can need millions of augmentations)
     * @return {flow found, augmenting paths, 1 if it finished / 0 if it ran out of time}
     */
    long[] solve(int s, int t, long deadline) {
        long[] residual = cap.stream().mapToLong(Long::longValue).toArray();
        int[] parentEdge = new int[n], next = new int[n], stack = new int[n];
        boolean[] seen = new boolean[n];
        long flow = 0, paths = 0;
        while (true) {
            // Iterative DFS (recursion would overflow the stack on 10,000-node paths).
            Arrays.fill(seen, false);
            Arrays.fill(next, 0);
            int top = 0;
            stack[top++] = s;
            seen[s] = true;
            while (top > 0 && stack[top - 1] != t) {
                int u = stack[top - 1];
                if (next[u] == adj[u].size()) { top--; continue; }
                int e = adj[u].get(next[u]++), v = to.get(e);
                if (!seen[v] && residual[e] > 0) {
                    seen[v] = true;
                    parentEdge[v] = e;
                    stack[top++] = v;
                }
            }
            if (top == 0) return new long[]{flow, paths, 1};
            if (System.nanoTime() > deadline) return new long[]{flow, paths, 0};
            long push = Long.MAX_VALUE;
            for (int v = t; v != s; v = to.get(parentEdge[v] ^ 1)) push = Math.min(push, residual[parentEdge[v]]);
            for (int v = t; v != s; v = to.get(parentEdge[v] ^ 1)) {
                residual[parentEdge[v]] -= push;
                residual[parentEdge[v] ^ 1] += push;
            }
            flow += push;
            paths++;
        }
    }
}
