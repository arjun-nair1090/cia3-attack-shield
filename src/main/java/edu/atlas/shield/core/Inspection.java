package edu.atlas.shield.core;

import edu.atlas.shield.algo.SignatureTrie;

import java.util.List;

/**
 * Everything the shield decided about one request, and why.
 * {@code normalized} is the decoded text the trie scanned; match positions index into it.
 * {@code bloomProbes} are the k bit positions the Bloom filter checked for the source IP.
 */
public record Inspection(
        long timeMillis,
        String ip,
        String request,
        String normalized,
        Verdict verdict,
        boolean bloomHit,
        boolean confirmedBadIp,
        int[] bloomProbes,
        List<SignatureTrie.Match> matches,
        List<String> reasons,
        long nanos) {}
