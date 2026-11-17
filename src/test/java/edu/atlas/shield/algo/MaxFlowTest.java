package edu.atlas.shield.algo;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class MaxFlowTest {

    /** CLRS Figure 26.1: max flow 23. */
    private static MaxFlow clrs() {
        MaxFlow g = new MaxFlow(6);
        g.addEdge(0, 1, 16); g.addEdge(0, 2, 13); g.addEdge(2, 1, 4); g.addEdge(1, 3, 12);
        g.addEdge(3, 2, 9);  g.addEdge(2, 4, 14); g.addEdge(4, 3, 7); g.addEdge(3, 5, 20);
        g.addEdge(4, 5, 4);
        return g;
    }

    private static long cutCapacity(MaxFlow.Result r) {
        return r.minCut().stream().mapToLong(MaxFlow.Edge::capacity).sum();
    }

    @Test
    void textbookNetworkHasFlow23AndMatchingCut() {
        MaxFlow.Result r = clrs().solve(0, 5);
        assertEquals(23, r.maxFlow());
        assertEquals(23, cutCapacity(r));
    }

    @Test
    void findsBottleneckLinkInDefendedNetwork() {
        // internet(0) -> cdn(1) 10000 -> lb(2) 800 -> app1(3), app2(4) 5000 each -> db(5)
        MaxFlow g = new MaxFlow(6);
        g.addEdge(0, 1, 10_000); g.addEdge(1, 2, 800);
        g.addEdge(2, 3, 5_000);  g.addEdge(2, 4, 5_000);
        g.addEdge(3, 5, 5_000);  g.addEdge(4, 5, 5_000);
        MaxFlow.Result r = g.solve(0, 5);
        assertEquals(800, r.maxFlow());
        assertEquals(List.of(new MaxFlow.Edge(1, 2, 800)), r.minCut());
    }

    @Test
    void disconnectedNetworkCarriesNothing() {
        MaxFlow g = new MaxFlow(4);
        g.addEdge(0, 1, 5);
        g.addEdge(2, 3, 5);
        MaxFlow.Result r = g.solve(0, 3);
        assertEquals(0, r.maxFlow());
        assertTrue(r.minCut().isEmpty());
    }

    @Test
    void boundarySingleLinkAndParallelLinks() {
        MaxFlow one = new MaxFlow(2);
        one.addEdge(0, 1, 7);
        assertEquals(7, one.solve(0, 1).maxFlow());

        MaxFlow par = new MaxFlow(2);
        par.addEdge(0, 1, 3);
        par.addEdge(0, 1, 4);
        assertEquals(7, par.solve(0, 1).maxFlow());
    }

    @Test
    void maxFlowEqualsMinCutOnRandomNetworks() {
        Random rnd = new Random(3);
        for (int t = 0; t < 200; t++) {
            int n = 2 + rnd.nextInt(10);
            MaxFlow g = new MaxFlow(n);
            for (int e = 0; e < rnd.nextInt(30); e++) g.addEdge(rnd.nextInt(n), rnd.nextInt(n), rnd.nextInt(20));
            MaxFlow.Result r = g.solve(0, n - 1);
            assertEquals(r.maxFlow(), cutCapacity(r));
            assertTrue(r.sourceSide()[0]);
            assertFalse(r.sourceSide()[n - 1]);
        }
    }

    @Test
    void rejectsInvalidInput() {
        assertThrows(IllegalArgumentException.class, () -> new MaxFlow(1));
        MaxFlow g = new MaxFlow(3);
        assertThrows(IllegalArgumentException.class, () -> g.addEdge(0, 1, -1));
        assertThrows(IllegalArgumentException.class, () -> g.addEdge(0, 3, 1));
        assertThrows(IllegalArgumentException.class, () -> g.solve(1, 1));
    }

    @Test
    void totalFlowBeyondLongRangeIsRejectedNotWrapped() {
        MaxFlow g = new MaxFlow(2);
        g.addEdge(0, 1, Long.MAX_VALUE);
        assertEquals(Long.MAX_VALUE, g.solve(0, 1).maxFlow()); // exactly at the limit still works
        g.addEdge(0, 1, 1);
        assertThrows(IllegalArgumentException.class, () -> g.solve(0, 1)); // used to return Long.MIN_VALUE
    }
}
