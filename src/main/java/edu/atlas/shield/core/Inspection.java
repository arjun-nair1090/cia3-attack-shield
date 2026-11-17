package edu.atlas.shield.core;

import edu.atlas.shield.algo.SignatureTrie;

import java.util.List;

/** Everything the shield decided about one request, and why. */
public record Inspection(
        long timeMillis,
        String ip,
        String request,
        Verdict verdict,
        boolean bloomHit,
        boolean confirmedBadIp,
        List<SignatureTrie.Match> matches,
        List<String> reasons,
        long nanos) {}
