package edu.atlas.shield.core;

import edu.atlas.shield.algo.BloomFilter;
import edu.atlas.shield.algo.SignatureTrie;
import edu.atlas.shield.algo.TrafficSegmentTree;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * The request-screening pipeline:
 *   1. Bloom filter: is the source IP possibly on the blocklist?  (O(k), no false negatives)
 *   2. Exact set:    only on a Bloom hit, confirm it              (rules out Bloom false positives)
 *   3. Trie scan:    which attack signatures appear in the URL?   (one pass for all signatures)
 *   4. decide():     turn the evidence into ALLOW / FLAG / BLOCK
 *   5. Segment tree: count the request into its one-second bucket (spike detection)
 */
@Service
public class ShieldEngine {

    public static final int WINDOW_SECONDS = 600;
    private static final Pattern IPV4 = Pattern.compile("((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1?\\d?\\d)");
    private static final Pattern IPV6 = Pattern.compile("[0-9a-fA-F:]{2,39}");

    public static final int RUNTIME_HEADROOM = 10_000; // room for IPs blocked at runtime before the FPR degrades

    private BloomFilter bloom;
    private double bloomTargetFpr = 0.01;
    private Set<String> exactBadIps;
    private List<String> badIpList; // for the simulator to draw real attacker IPs from
    private final SignatureTrie trie = new SignatureTrie();
    private final List<String[]> signatures = new ArrayList<>(); // {category, signature}
    private final TrafficSegmentTree allTraffic = new TrafficSegmentTree(WINDOW_SECONDS);
    private final TrafficSegmentTree blockedTraffic = new TrafficSegmentTree(WINDOW_SECONDS);
    private long lastSecond = -1;

    private long total, allowed, flagged, blocked, bloomHits, bloomFalsePositives, signatureHits, totalNanos;

    public ShieldEngine() {
        badIpList = readLines("data/bad-ips.txt");
        exactBadIps = new HashSet<>(badIpList);
        bloom = buildBloom(exactBadIps, bloomTargetFpr);
        for (String line : readLines("data/signatures.txt")) {
            int bar = line.indexOf('|');
            if (bar <= 0 || bar == line.length() - 1) throw new IllegalStateException("bad signature line: " + line);
            String category = line.substring(0, bar), sig = line.substring(bar + 1).toLowerCase(Locale.ROOT);
            trie.add(sig, category);
            signatures.add(new String[]{category, sig});
        }
    }

    // ponytail: one global lock around the pipeline; per-bucket atomics if throughput ever matters more than clarity.
    /** Screen a live request: run the pipeline, then count it into the stats and the traffic window. */
    public synchronized Inspection inspect(String ip, String rawRequest) {
        Inspection in = analyze(ip, rawRequest);
        record(in.timeMillis() / 1000, in.verdict());
        total++;
        totalNanos += in.nanos();
        if (in.bloomHit()) bloomHits++;
        if (in.bloomHit() && !in.confirmedBadIp()) bloomFalsePositives++;
        if (!in.matches().isEmpty()) signatureHits++;
        switch (in.verdict()) {
            case ALLOW -> allowed++;
            case FLAG -> flagged++;
            case BLOCK -> blocked++;
        }
        return in;
    }

    /** Run the pipeline without counting anything: for "what would the shield do with this text?" */
    public synchronized Inspection analyze(String ip, String rawRequest) {
        long start = System.nanoTime();
        String text = normalize(rawRequest == null ? "" : rawRequest);

        boolean bloomHit = ip != null && bloom.mightContain(ip);
        boolean confirmed = bloomHit && exactBadIps.contains(ip);
        List<SignatureTrie.Match> matches = trie.scan(text);
        Verdict verdict = decide(confirmed, matches);

        List<String> reasons = new ArrayList<>();
        if (confirmed) reasons.add("IP on blocklist (Bloom hit, confirmed exactly)");
        else if (bloomHit) reasons.add("Bloom false positive, cleared by exact check");
        for (SignatureTrie.Match m : matches) reasons.add(m.category() + ": " + m.signature());

        long nanos = System.nanoTime() - start;
        long now = System.currentTimeMillis();
        int[] probes = ip == null ? new int[0] : bloom.probes(ip); // for the dashboard; outside the timed section
        return new Inspection(now, ip, rawRequest, text, verdict, bloomHit, confirmed, probes, matches, reasons, nanos);
    }

    /**
     * Security policy: turn the evidence about one request into a verdict.
     *
     * @param confirmedBadIp the source IP is on the blocklist (Bloom hit AND exact check agreed)
     * @param matches        every attack signature found in the decoded URL; each has category()
     *                       in {SQLI, XSS, TRAVERSAL, CMDI, LOG4SHELL, SSRF, SCANNER}
     */
    static Verdict decide(boolean confirmedBadIp, List<SignatureTrie.Match> matches) {
        boolean exploit = false, probe = false;
        for (SignatureTrie.Match m : matches) {
            if (m.category().equals("SCANNER")) probe = true;
            else exploit = true;
        }
        if (exploit || confirmedBadIp) return Verdict.BLOCK; // one exploit pattern, or an operator-listed IP, is enough
        if (probe) return Verdict.FLAG;                      // recon like /wp-admin: watch it, don't lock anyone out
        return Verdict.ALLOW;
    }

    /** URL-decode up to twice (unmasks %2527 -> %27 -> '), then lower-case. Malformed % escapes are kept as-is. */
    static String normalize(String raw) {
        String s = raw;
        for (int i = 0; i < 2; i++) {
            try {
                String d = URLDecoder.decode(s, UTF_8);
                if (d.equals(s)) break;
                s = d;
            } catch (IllegalArgumentException malformed) {
                break;
            }
        }
        return s.toLowerCase(Locale.ROOT);
    }

    public static boolean isIp(String ip) {
        return ip != null && (IPV4.matcher(ip).matches() || (ip.contains(":") && IPV6.matcher(ip).matches()));
    }

    public synchronized boolean addBadIp(String ip) {
        if (!isIp(ip)) throw new IllegalArgumentException("not an IP address: " + ip);
        if (!exactBadIps.add(ip)) return false;
        bloom.add(ip);
        badIpList.add(ip);
        return true;
    }

    private static BloomFilter buildBloom(Set<String> ips, double targetFpr) {
        BloomFilter f = new BloomFilter(ips.size() + RUNTIME_HEADROOM, targetFpr);
        ips.forEach(f::add);
        return f;
    }

    public record ParsedBlocklist(List<String> ips, int duplicates) {}

    /**
     * One IP per line; blank lines and # comments are skipped. Any malformed line rejects the whole upload
     * (reporting the first line numbers), so a typo can never silently shrink the blocklist.
     */
    public static ParsedBlocklist parseBlocklist(String text) {
        if (text == null || text.isBlank()) throw new IllegalArgumentException("blocklist is empty");
        Set<String> seen = new java.util.LinkedHashSet<>();
        List<String> bad = new ArrayList<>();
        int duplicates = 0, lineNo = 0, badCount = 0;
        for (String line : text.split("\n", -1)) {
            lineNo++;
            String ip = line.strip();
            if (ip.isEmpty() || ip.startsWith("#")) continue;
            if (!isIp(ip)) {
                if (++badCount <= 5) bad.add("line " + lineNo + " (\"" + (ip.length() > 40 ? ip.substring(0, 40) + "…" : ip) + "\")");
            } else if (!seen.add(ip)) duplicates++;
        }
        if (badCount > 0)
            throw new IllegalArgumentException(badCount + " line(s) are not IP addresses: " + String.join(", ", bad)
                    + (badCount > 5 ? ", …" : ""));
        if (seen.isEmpty()) throw new IllegalArgumentException("blocklist has no IP addresses, only blank lines or comments");
        return new ParsedBlocklist(List.copyOf(seen), duplicates);
    }

    public record Rebuild(int blocklistSize, int duplicatesIgnored, int bloomBits, int bloomHashes, double targetFpr,
                          double theoreticalFpr, double measuredFpr, int sampled) {}

    /**
     * Rebuild the Bloom filter for a new target false-positive rate, optionally over a new blocklist
     * (null keeps the current one). Then measure the real false-positive rate on 100,000 private
     * 10.x.x.x addresses that are not on the list, to set beside the theory (1 - e^(-kn/m))^k.
     */
    public synchronized Rebuild rebuildBlocklist(double targetFpr, ParsedBlocklist upload) {
        if (!(targetFpr >= 0.0001 && targetFpr <= 0.5)) throw new IllegalArgumentException("falsePositiveRate must be in [0.0001, 0.5]");
        if (upload != null) {
            badIpList = new ArrayList<>(upload.ips());
            exactBadIps = new HashSet<>(upload.ips());
        }
        bloom = buildBloom(exactBadIps, targetFpr);
        bloomTargetFpr = targetFpr;

        java.util.Random r = new java.util.Random(42); // fixed seed: the same rebuild measures the same number
        int sampled = 0, fp = 0;
        while (sampled < 100_000) {
            String ip = "10." + r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256);
            if (exactBadIps.contains(ip)) continue; // only true negatives can be false positives
            sampled++;
            if (bloom.mightContain(ip)) fp++;
        }
        return new Rebuild(exactBadIps.size(), upload == null ? 0 : upload.duplicates(), bloom.bitCount(), bloom.hashCount(),
                targetFpr, bloom.expectedFalsePositiveRate(), (double) fp / sampled, sampled);
    }

    /** Ring buffer of one-second buckets: clear every bucket we skipped over before counting into the current one. */
    private void record(long second, Verdict verdict) {
        advanceTo(second);
        int idx = (int) (second % WINDOW_SECONDS);
        allTraffic.add(idx, 1);
        if (verdict == Verdict.BLOCK) blockedTraffic.add(idx, 1);
    }

    private void advanceTo(long second) {
        if (second <= lastSecond) return;
        for (long s = Math.max(lastSecond + 1, second - WINDOW_SECONDS + 1); s <= second; s++) {
            int idx = (int) (s % WINDOW_SECONDS);
            allTraffic.set(idx, 0);
            blockedTraffic.set(idx, 0);
        }
        lastSecond = second;
    }

    public record TrafficWindow(int seconds, long[] all, long[] blocked, long total, long totalBlocked,
                                int peakSecondsAgo, long peakCount) {}

    /** Last {@code seconds} seconds, oldest first. Sums and the peak come from the segment trees. */
    public synchronized TrafficWindow traffic(int seconds) {
        if (seconds < 1 || seconds > WINDOW_SECONDS)
            throw new IllegalArgumentException("seconds must be in [1, " + WINDOW_SECONDS + "]");
        long now = System.currentTimeMillis() / 1000;
        advanceTo(now);
        long[] all = new long[seconds], blk = new long[seconds];
        for (int i = 0; i < seconds; i++) {
            int idx = (int) ((now - seconds + 1 + i) % WINDOW_SECONDS);
            all[i] = allTraffic.get(idx);
            blk[i] = blockedTraffic.get(idx);
        }
        // The window [now-seconds+1, now] is at most two contiguous ranges in the ring.
        int hi = (int) (now % WINDOW_SECONDS), lo = hi - seconds + 1;
        long sumAll, sumBlocked;
        int peakIdx;
        if (lo >= 0) {
            sumAll = allTraffic.sum(lo, hi);
            sumBlocked = blockedTraffic.sum(lo, hi);
            peakIdx = allTraffic.argMax(lo, hi);
        } else {
            int wrapLo = lo + WINDOW_SECONDS;
            sumAll = allTraffic.sum(wrapLo, WINDOW_SECONDS - 1) + allTraffic.sum(0, hi);
            sumBlocked = blockedTraffic.sum(wrapLo, WINDOW_SECONDS - 1) + blockedTraffic.sum(0, hi);
            int a = allTraffic.argMax(wrapLo, WINDOW_SECONDS - 1), b = allTraffic.argMax(0, hi);
            peakIdx = allTraffic.get(b) > allTraffic.get(a) ? b : a;
        }
        int ago = Math.floorMod(hi - peakIdx, WINDOW_SECONDS);
        return new TrafficWindow(seconds, all, blk, sumAll, sumBlocked, ago, allTraffic.get(peakIdx));
    }

    public record Stats(long total, long allowed, long flagged, long blocked, long bloomHits, long bloomFalsePositives,
                        long signatureHits,
                        int blocklistSize, int bloomBits, int bloomHashes, double bloomExpectedFpr,
                        int signatures, double avgInspectMicros, double bloomTargetFpr) {}

    public synchronized Stats stats() {
        return new Stats(total, allowed, flagged, blocked, bloomHits, bloomFalsePositives, signatureHits,
                exactBadIps.size(), bloom.bitCount(), bloom.hashCount(), bloom.expectedFalsePositiveRate(),
                trie.size(), total == 0 ? 0 : totalNanos / 1000.0 / total, bloomTargetFpr);
    }

    /** Snapshot of the Bloom filter's bit array for the dashboard's bit-field view. */
    public synchronized long[] bloomWords() { return bloom.words(); }

    synchronized List<String> badIps() { return List.copyOf(badIpList); }

    List<String[]> signatures() { return signatures; }

    private static List<String> readLines(String path) {
        List<String> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new ClassPathResource(path).getInputStream(), UTF_8))) {
            for (String line; (line = r.readLine()) != null; ) {
                line = line.replace("\r", ""); // keep meaningful trailing spaces like "; cat "
                if (!line.isBlank() && !line.startsWith("#")) out.add(line);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + path, e);
        }
        if (out.isEmpty()) throw new IllegalStateException(path + " is empty");
        return out;
    }
}
