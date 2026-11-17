package edu.atlas.shield.bench;

import edu.atlas.shield.algo.BloomFilter;
import edu.atlas.shield.algo.Kmp;
import edu.atlas.shield.algo.MaxFlow;
import edu.atlas.shield.algo.SignatureTrie;
import edu.atlas.shield.algo.TrafficSegmentTree;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.Set;
import java.util.function.LongSupplier;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Reproducible experiments for the report. Excluded from the normal build; run with
 * <pre>./mvnw test -Dgroups=bench -DexcludedGroups=none</pre>
 * Method: every measurement is 3 warm-up runs (JIT) then 7 timed runs; we report the median and the min/max.
 * Inputs come from fixed random seeds, so a rerun on the same machine measures the same work.
 * Every experiment also checks that the algorithm and its baseline agree, so speed is never bought with a wrong answer.
 * Results are written as CSV to docs/bench/ and charted as SVG by {@link Charts}.
 */
@Tag("bench")
class BenchmarkTest {

    static final Path OUT = Path.of("docs", "bench");

    /** Redraw every chart from the CSVs now on disk (also after running a single experiment). */
    @AfterAll
    static void charts() { Charts.drawAll(); }
    static final int WARMUP = 3, RUNS = 7;

    /** {median, min, max} wall time in milliseconds. The supplier's result is kept so the JIT cannot skip the work. */
    static double[] time(LongSupplier work) {
        long sink = 0;
        for (int i = 0; i < WARMUP; i++) sink += work.getAsLong();
        double[] ms = new double[RUNS];
        for (int i = 0; i < RUNS; i++) {
            long t0 = System.nanoTime();
            sink += work.getAsLong();
            ms[i] = (System.nanoTime() - t0) / 1e6;
        }
        if (sink == 42) System.out.print(""); // consume the sink
        Arrays.sort(ms);
        return new double[]{ms[RUNS / 2], ms[0], ms[RUNS - 1]};
    }

    static void write(String file, String header, List<String> rows) {
        try {
            Files.createDirectories(OUT);
            Files.writeString(OUT.resolve(file), header + "\n" + String.join("\n", rows) + "\n", UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        System.out.println("\n== " + file + "\n" + header + "\n" + String.join("\n", rows));
    }

    static String f(double x) { return String.format(Locale.ROOT, "%.4f", x); }


    // ------------------------------------------------------------------ 1. signature scanning

    static List<String[]> realSignatures() {
        List<String[]> out = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(Path.of("src/main/resources/data/signatures.txt"), UTF_8)) {
                if (line.isBlank() || line.startsWith("#")) continue;
                int bar = line.indexOf('|');
                out.add(new String[]{line.substring(0, bar), line.substring(bar + 1).toLowerCase(Locale.ROOT)});
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out;
    }

    /** Request lines like the shop sees: 70 % benign, 30 % carrying a real signature, some URL-encoded. */
    static List<String> requests(int count, List<String[]> sigs, Random r) {
        String[] benign = {"/shop/index.html", "/shop/product?id=%d", "/shop/search?q=running+shoes+size+%d",
                "/shop/search?q=o%%27reilly+java+book", "/shop/cart?item=%d&qty=2", "/shop/search?q=select+a+union+jack+flag"};
        List<String> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            String url = benign[r.nextInt(benign.length)].formatted(r.nextInt(1000));
            if (r.nextInt(10) < 3) {
                String p = sigs.get(r.nextInt(sigs.size()))[1];
                url = "/shop/search?q=" + (r.nextBoolean() ? URLEncoder.encode(p, UTF_8) : p) + "&page=" + r.nextInt(9);
            }
            String decoded; // the engine scans decoded, lower-cased text; do the same once, outside the timing
            try { decoded = URLDecoder.decode(url, UTF_8); } catch (IllegalArgumentException malformed) { decoded = url; }
            out.add(decoded.toLowerCase(Locale.ROOT));
        }
        return out;
    }

    @Test
    void signatureScanning() {
        Random r = new Random(1);
        List<String[]> real = realSignatures();
        List<String> texts = requests(2_000, real, r);
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789'\"<>/=;()-_.%";
        List<String> rows = new ArrayList<>();
        for (int k : new int[]{real.size(), 500, 5_000}) {
            List<String> sigs = new ArrayList<>();
            for (String[] s : real) sigs.add(s[1]);
            Set<String> uniq = new HashSet<>(sigs);
            while (sigs.size() < k) { // synthetic extra signatures, 4-16 chars, so the set can grow
                StringBuilder sb = new StringBuilder();
                for (int len = 4 + r.nextInt(13); sb.length() < len; ) sb.append(alphabet.charAt(r.nextInt(alphabet.length())));
                if (uniq.add(sb.toString())) sigs.add(sb.toString());
            }
            SignatureTrie trie = new SignatureTrie();
            for (String s : sigs) trie.add(s, "X");

            long trieHits = 0, kmpHits = 0, idxHits = 0;
            for (String t : texts) {
                trieHits += trie.scan(t).size();
                for (String s : sigs) kmpHits += Kmp.findAll(t, s).size();
                for (String s : sigs) for (int i = t.indexOf(s); i >= 0; i = t.indexOf(s, i + 1)) idxHits++;
            }
            assertEquals(kmpHits, trieHits, "trie and KMP must find the same matches");
            assertEquals(idxHits, trieHits, "trie and indexOf must find the same matches");

            double[] tTrie = time(() -> { long c = 0; for (String t : texts) c += trie.scan(t).size(); return c; });
            double[] tKmp = time(() -> { long c = 0; for (String t : texts) for (String s : sigs) c += Kmp.findAll(t, s).size(); return c; });
            double[] tIdx = time(() -> {
                long c = 0;
                for (String t : texts) for (String s : sigs) for (int i = t.indexOf(s); i >= 0; i = t.indexOf(s, i + 1)) c++;
                return c;
            });
            for (Object[] v : new Object[][]{{"trie (one pass)", tTrie}, {"KMP once per signature", tKmp}, {"String.indexOf per signature", tIdx}}) {
                double[] t = (double[]) v[1];
                rows.add(String.join(",", (String) v[0], String.valueOf(k), String.valueOf(texts.size()),
                        f(t[0]), f(t[1]), f(t[2]), f(t[0] * 1000 / texts.size()), String.valueOf(trieHits)));
            }
        }
        write("signature-scan.csv", "method,signatures,requests,median_ms,min_ms,max_ms,us_per_request,matches", rows);
    }

    // ------------------------------------------------------------------ 2. Bloom precheck vs exact set

    static String randomPublicIp(Random r) { return (11 + r.nextInt(200)) + "." + r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256); }

    static long usedHeap() {
        Runtime rt = Runtime.getRuntime();
        for (int i = 0; i < 4; i++) System.gc();
        return rt.totalMemory() - rt.freeMemory();
    }

    @Test
    void bloomVersusExactSet() {
        Random r = new Random(2);
        List<String> rows = new ArrayList<>();
        int lookups = 1_000_000;
        for (int n : new int[]{135_530, 500_000, 1_000_000}) {
            List<String> listed = new ArrayList<>(n);
            Set<String> uniq = new HashSet<>(n * 2);
            while (listed.size() < n) { String ip = randomPublicIp(r); if (uniq.add(ip)) listed.add(ip); }
            uniq = null;

            // Memory: heap retained by a HashSet of n fresh IP strings, measured around its construction.
            long before = usedHeap();
            Set<String> exact = new HashSet<>();
            for (String ip : listed) exact.add(new String(ip.toCharArray()));
            long setBytes = usedHeap() - before;

            BloomFilter bloom = new BloomFilter(n, 0.01);
            listed.forEach(bloom::add);
            long bloomBytes = bloom.bitCount() / 8;

            // Traffic: 99 % of lookups are not listed (the normal case for a blocklist), 1 % are.
            List<String> queries = new ArrayList<>(lookups);
            for (int i = 0; i < lookups; i++)
                queries.add(i % 100 == 0 ? listed.get(r.nextInt(n)) : "10." + r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256));

            long exactChecks = 0, agree = 0;
            for (String q : queries) {
                boolean viaBloom = bloom.mightContain(q);
                if (viaBloom) exactChecks++;
                if ((viaBloom && exact.contains(q)) == exact.contains(q)) agree++;
            }
            assertEquals(lookups, agree, "Bloom + exact check must give exactly the HashSet's answers (no false negatives)");

            double[] tSet = time(() -> { long c = 0; for (String q : queries) if (exact.contains(q)) c++; return c; });
            double[] tBloom = time(() -> { long c = 0; for (String q : queries) if (bloom.mightContain(q)) c++; return c; });
            double[] tBoth = time(() -> { long c = 0; for (String q : queries) if (bloom.mightContain(q) && exact.contains(q)) c++; return c; });
            rows.add(row("HashSet only", n, lookups, tSet, setBytes, lookups));
            rows.add(row("Bloom filter alone", n, lookups, tBloom, bloomBytes, 0));
            rows.add(row("Bloom then exact on hit", n, lookups, tBoth, bloomBytes + setBytes, exactChecks));
        }
        write("bloom-vs-exact.csv", "method,listed_ips,lookups,median_ms,min_ms,max_ms,ns_per_lookup,memory_bytes,exact_lookups", rows);
    }

    private static String row(String method, int n, int lookups, double[] t, long bytes, long exactLookups) {
        return String.join(",", method, String.valueOf(n), String.valueOf(lookups), f(t[0]), f(t[1]), f(t[2]),
                f(t[0] * 1e6 / lookups), String.valueOf(bytes), String.valueOf(exactLookups));
    }

    // ------------------------------------------------------------------ 3. Bloom false-positive rate vs theory

    @Test
    void bloomFalsePositiveRateAgainstTheory() {
        int design = 100_000, probes = 200_000;
        BloomFilter f = new BloomFilter(design, 0.01);
        List<String> rows = new ArrayList<>();
        int inserted = 0;
        for (int pct : new int[]{10, 25, 50, 75, 100, 125, 150, 200}) {
            for (; inserted < design * pct / 100; inserted++) f.add("listed-" + inserted);
            int fp = 0;
            for (int i = 0; i < probes; i++) if (f.mightContain("clean-" + pct + "-" + i)) fp++;
            rows.add(String.join(",", String.valueOf(pct), String.valueOf(inserted), String.valueOf(f.bitCount()),
                    String.valueOf(f.hashCount()), f((double) fp / probes), f(f.expectedFalsePositiveRate()), String.valueOf(probes)));
        }
        write("bloom-fpr.csv", "fill_pct,inserted,bits,hashes,measured_fpr,theoretical_fpr,probes", rows);
    }

    // ------------------------------------------------------------------ 4. segment tree vs plain array

    @Test
    void segmentTreeVersusArray() {
        List<String> rows = new ArrayList<>();
        int ops = 100_000;
        for (int n : new int[]{60, 600, 6_000, 60_000}) {
            Random r = new Random(4);
            int[][] plan = new int[ops][3]; // {kind 0=update 1=query, a, b}
            for (int[] p : plan) {
                p[0] = r.nextInt(2);
                int a = r.nextInt(n), b = r.nextInt(n);
                p[1] = p[0] == 0 ? a : Math.min(a, b);
                p[2] = p[0] == 0 ? r.nextInt(1000) : Math.max(a, b);
            }
            TrafficSegmentTree tree = new TrafficSegmentTree(n);
            long[] arr = new long[n];
            for (int[] p : plan) { // agreement check on the full workload
                if (p[0] == 0) { tree.set(p[1], p[2]); arr[p[1]] = p[2]; continue; }
                long s = 0; int best = p[1];
                for (int i = p[1]; i <= p[2]; i++) { s += arr[i]; if (arr[i] > arr[best]) best = i; }
                assertEquals(s, tree.sum(p[1], p[2]));
                assertEquals(best, tree.argMax(p[1], p[2]));
            }
            double[] tTree = time(() -> {
                long c = 0;
                for (int[] p : plan) if (p[0] == 0) tree.set(p[1], p[2]); else c += tree.sum(p[1], p[2]) + tree.argMax(p[1], p[2]);
                return c;
            });
            double[] tArr = time(() -> {
                long c = 0;
                for (int[] p : plan) {
                    if (p[0] == 0) { arr[p[1]] = p[2]; continue; }
                    long s = 0; int best = p[1];
                    for (int i = p[1]; i <= p[2]; i++) { s += arr[i]; if (arr[i] > arr[best]) best = i; }
                    c += s + best;
                }
                return c;
            });
            for (Object[] v : new Object[][]{{"segment tree", tTree}, {"plain array", tArr}}) {
                double[] t = (double[]) v[1];
                rows.add(String.join(",", (String) v[0], String.valueOf(n), String.valueOf(ops), f(t[0]), f(t[1]), f(t[2]), f(t[0] * 1e6 / ops)));
            }
        }
        write("segment-tree.csv", "method,buckets,operations,median_ms,min_ms,max_ms,ns_per_op", rows);
    }

    // ------------------------------------------------------------------ 5. Edmonds–Karp vs DFS Ford–Fulkerson

    /** A chain s=0 -> 1 -> ... -> t guarantees a path; 4 extra random links per node make it a real network. */
    static int[][] network(int v, long maxCap, Random r) {
        List<int[]> edges = new ArrayList<>();
        for (int i = 0; i + 1 < v; i++) edges.add(new int[]{i, i + 1});
        for (int i = 0; i < 4 * v; i++) {
            int a = r.nextInt(v), b = r.nextInt(v);
            if (a != b) edges.add(new int[]{a, b});
        }
        int[][] out = new int[edges.size()][];
        for (int i = 0; i < out.length; i++) out[i] = new int[]{edges.get(i)[0], edges.get(i)[1], (int) (1 + r.nextLong(maxCap))};
        return out;
    }

    /** Like time(), but a run slower than 2 s is measured once (runs = 1) instead of 10 times. {median, min, max, runs} */
    static double[] timeAdaptive(LongSupplier work) {
        long t0 = System.nanoTime();
        work.getAsLong();
        double first = (System.nanoTime() - t0) / 1e6;
        if (first > 2_000) return new double[]{first, first, first, 1};
        double[] t = time(work);
        return new double[]{t[0], t[1], t[2], RUNS};
    }

    static final long FF_BUDGET_NANOS = 60_000_000_000L; // 60 s per DFS Ford-Fulkerson solve, then "did not finish"

    @Test
    void edmondsKarpVersusDfsFordFulkerson() {
        List<String> rows = new ArrayList<>();
        String header = "method,nodes,links,max_capacity,max_flow,augmenting_paths,finished,runs,median_ms,min_ms,max_ms";
        for (long maxCap : new long[]{10, 1_000_000}) {
            for (int v : new int[]{100, 1_000, 10_000}) {
                int[][] edges = network(v, maxCap, new Random(5L * v + maxCap));
                MaxFlow ek = new MaxFlow(v);
                FordFulkersonDfs ff = new FordFulkersonDfs(v);
                for (int[] e : edges) { ek.addEdge(e[0], e[1], e[2]); ff.addEdge(e[0], e[1], e[2]); }
                MaxFlow.Result rEk = ek.solve(0, v - 1);
                long cut = rEk.minCut().stream().mapToLong(MaxFlow.Edge::capacity).sum();
                assertEquals(rEk.maxFlow(), cut, "max flow = min cut");
                double[] tEk = timeAdaptive(() -> ek.solve(0, v - 1).maxFlow());
                rows.add(String.join(",", "Edmonds-Karp (BFS paths)", String.valueOf(v), String.valueOf(edges.length), String.valueOf(maxCap),
                        String.valueOf(rEk.maxFlow()), String.valueOf(rEk.augmentingPaths()), "yes", String.valueOf((int) tEk[3]), f(tEk[0]), f(tEk[1]), f(tEk[2])));

                long t0 = System.nanoTime();
                long[] rFf = ff.solve(0, v - 1, t0 + FF_BUDGET_NANOS);
                double firstMs = (System.nanoTime() - t0) / 1e6;
                String ffRow;
                if (rFf[2] == 0) { // out of time: report how far it got, never a made-up number
                    ffRow = String.join(",", "Ford-Fulkerson (DFS paths)", String.valueOf(v), String.valueOf(edges.length), String.valueOf(maxCap),
                            String.valueOf(rFf[0]), String.valueOf(rFf[1]), "no (60 s budget)", "1", f(firstMs), f(firstMs), f(firstMs));
                } else {
                    assertEquals(rEk.maxFlow(), rFf[0], "both must find the same maximum flow");
                    double[] tFf = firstMs > 2_000 ? new double[]{firstMs, firstMs, firstMs, 1}
                            : timeAdaptive(() -> ff.solve(0, v - 1, Long.MAX_VALUE)[0]);
                    ffRow = String.join(",", "Ford-Fulkerson (DFS paths)", String.valueOf(v), String.valueOf(edges.length), String.valueOf(maxCap),
                            String.valueOf(rFf[0]), String.valueOf(rFf[1]), "yes", String.valueOf((int) tFf[3]), f(tFf[0]), f(tFf[1]), f(tFf[2]));
                }
                rows.add(ffRow);
                System.out.println(rows.get(rows.size() - 2) + System.lineSeparator() + ffRow);
            }
        }
        write("max-flow.csv", header, rows);
    }
}
