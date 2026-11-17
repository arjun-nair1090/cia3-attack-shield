package edu.atlas.shield.core;

import edu.atlas.shield.algo.SignatureTrie.Match;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ShieldEngineTest {

    private static Match m(String category) { return new Match("x", category, 0); }

    @Test
    void decidePolicyTable() {
        assertEquals(Verdict.ALLOW, ShieldEngine.decide(false, List.of()));
        assertEquals(Verdict.FLAG, ShieldEngine.decide(false, List.of(m("SCANNER"))));
        assertEquals(Verdict.BLOCK, ShieldEngine.decide(false, List.of(m("SQLI"))));
        assertEquals(Verdict.BLOCK, ShieldEngine.decide(false, List.of(m("SCANNER"), m("XSS"))));
        assertEquals(Verdict.BLOCK, ShieldEngine.decide(true, List.of()));
    }

    @Test
    void normalizeUndoesDoubleEncodingAndCase() {
        assertEquals("q=' or 1=1", ShieldEngine.normalize("q=%2527%2520OR%25201%253D1"));
        assertEquals("<script>", ShieldEngine.normalize("%3CSCRIPT%3E"));
        assertEquals("100%zz", ShieldEngine.normalize("100%ZZ")); // malformed escape kept, not crashed on
        assertEquals("", ShieldEngine.normalize(""));
    }

    @Test
    void pipelineBlocksRealAttacksAndPassesCleanTraffic() {
        ShieldEngine e = new ShieldEngine();
        assertEquals(Verdict.BLOCK, e.inspect("10.0.0.1", "/shop/search?q=%2527%20or%201=1--").verdict());
        assertEquals(Verdict.BLOCK, e.inspect("10.0.0.1", "/shop/search?q=${jndi:ldap://x/a}").verdict());
        assertEquals(Verdict.FLAG, e.inspect("10.0.0.1", "/wp-admin").verdict());
        assertEquals(Verdict.ALLOW, e.inspect("10.0.0.1", "/shop/search?q=o%27reilly+java+book").verdict());
        assertEquals(4, e.stats().total());
    }

    @Test
    void blocklistedIpIsBlockedAfterRuntimeAdd() {
        ShieldEngine e = new ShieldEngine();
        assertEquals(Verdict.ALLOW, e.inspect("203.0.113.7", "/shop/cart").verdict());
        assertTrue(e.addBadIp("203.0.113.7"));
        assertFalse(e.addBadIp("203.0.113.7")); // duplicate
        Inspection in = e.inspect("203.0.113.7", "/shop/cart");
        assertEquals(Verdict.BLOCK, in.verdict());
        assertTrue(in.bloomHit() && in.confirmedBadIp());
        assertThrows(IllegalArgumentException.class, () -> e.addBadIp("not-an-ip"));
    }

    @Test
    void blocklistUploadIsParsedStrictly() {
        ShieldEngine.ParsedBlocklist p = ShieldEngine.parseBlocklist("# my list\r\n203.0.113.7\r\n\r\n203.0.113.7\n2001:db8::1\n");
        assertEquals(List.of("203.0.113.7", "2001:db8::1"), p.ips());
        assertEquals(1, p.duplicates());

        IllegalArgumentException bad = assertThrows(IllegalArgumentException.class,
                () -> ShieldEngine.parseBlocklist("1.2.3.4\n999.1.1.1\nhello\n"));
        assertTrue(bad.getMessage().contains("line 2") && bad.getMessage().contains("line 3"), bad.getMessage());
        assertThrows(IllegalArgumentException.class, () -> ShieldEngine.parseBlocklist(""));
        assertThrows(IllegalArgumentException.class, () -> ShieldEngine.parseBlocklist("# only a comment\n\n"));
    }

    @Test
    void rebuildMeasuresFalsePositivesNearTheoryAndSwapsTheList() {
        ShieldEngine e = new ShieldEngine();
        ShieldEngine.Rebuild r = e.rebuildBlocklist(0.05, null); // same 135k list, looser filter
        assertEquals(e.stats().blocklistSize(), r.blocklistSize());
        assertEquals(100_000, r.sampled());
        assertTrue(r.theoreticalFpr() < 0.05);                                      // below target: not yet at design capacity
        assertEquals(r.theoreticalFpr(), r.measuredFpr(), 0.01, "measured FPR should track theory");
        assertTrue(r.bloomBits() < new ShieldEngine().stats().bloomBits());          // looser target => smaller filter

        r = e.rebuildBlocklist(0.01, ShieldEngine.parseBlocklist("203.0.113.7\n203.0.113.8\n"));
        assertEquals(2, r.blocklistSize());
        assertEquals(Verdict.BLOCK, e.inspect("203.0.113.8", "/shop/cart").verdict());
        assertEquals(Verdict.ALLOW, e.inspect("45.148.10.151", "/shop/cart").verdict()); // old list is gone
        assertThrows(IllegalArgumentException.class, () -> e.rebuildBlocklist(0, null));
        assertThrows(IllegalArgumentException.class, () -> e.rebuildBlocklist(0.9, null));
    }

    @Test
    void trafficWindowCountsAndRejectsBadRanges() {
        ShieldEngine e = new ShieldEngine();
        for (int i = 0; i < 5; i++) e.inspect("10.0.0.2", "/shop/search?q=<script>");
        ShieldEngine.TrafficWindow w = e.traffic(60);
        assertEquals(5, w.total());
        assertEquals(5, w.totalBlocked());
        assertEquals(60, w.all().length);
        assertThrows(IllegalArgumentException.class, () -> e.traffic(0));
        assertThrows(IllegalArgumentException.class, () -> e.traffic(601));
    }
}
