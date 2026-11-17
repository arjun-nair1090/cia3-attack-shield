package edu.atlas.shield.core;

import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.util.List;
import java.util.Random;
import java.util.function.Consumer;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Synthetic load generator with ground truth. Each request is labelled attack or benign *before*
 * it goes through the real ShieldEngine pipeline, so we can measure detection rate and false-alarm rate.
 */
@Service
public class TrafficSimulator {

    private static final String[] BENIGN = {
            "/shop/index.html", "/shop/cart", "/shop/product?id=%d", "/shop/search?q=running+shoes",
            "/shop/search?q=o%%27reilly+java+book", "/shop/search?q=select+a+union+jack+flag",
            "/shop/search?q=rock+%%26+roll", "/shop/search?q=50%%25+off+deals", "/shop/product?id=%d&ref=home",
    };
    private static final String[] ATTACK_TEMPLATES = {
            "/shop/search?q=%s", "/shop/product?id=1%s", "/shop/%s", "/shop/search?q=shoes%s&page=2",
    };

    public record Result(int requests, int attacks, int benign, long allowed, long flagged, long blocked,
                         double detectionRate, double falseAlarmRate, long bloomFalsePositives,
                         long elapsedMillis, long requestsPerSecond) {}

    private final ShieldEngine engine;

    public TrafficSimulator(ShieldEngine engine) { this.engine = engine; }

    /** @param sample receives a thinned stream of inspections (about 200) for the live feed */
    public Result run(int requests, double attackRatio, long seed, Consumer<Inspection> sample) {
        if (requests < 1 || requests > 1_000_000) throw new IllegalArgumentException("requests must be in [1, 1000000]");
        if (!(attackRatio >= 0 && attackRatio <= 1)) throw new IllegalArgumentException("attackRatio must be in [0, 1]");
        Random r = new Random(seed);
        List<String> badIps = engine.badIps();
        List<String[]> sigs = engine.signatures();
        int every = Math.max(1, requests / 200);
        int attacks = 0, caught = 0, falseAlarms = 0;
        long allowed = 0, flagged = 0, blocked = 0, bloomFp = 0;

        long start = System.nanoTime();
        for (int i = 0; i < requests; i++) {
            boolean attack = r.nextDouble() < attackRatio;
            String ip, url;
            if (attack) {
                attacks++;
                int kind = r.nextInt(3); // bad IP only, payload only, or both
                ip = kind != 1 ? badIps.get(r.nextInt(badIps.size())) : randomBenignIp(r);
                url = kind != 0 ? attackUrl(r, sigs) : BENIGN[r.nextInt(BENIGN.length)].formatted(r.nextInt(500));
            } else {
                ip = randomBenignIp(r);
                url = BENIGN[r.nextInt(BENIGN.length)].formatted(r.nextInt(500));
            }
            Inspection in = engine.inspect(ip, url);
            switch (in.verdict()) {
                case ALLOW -> allowed++;
                case FLAG -> flagged++;
                case BLOCK -> blocked++;
            }
            if (in.bloomHit() && !in.confirmedBadIp()) bloomFp++;
            boolean stopped = in.verdict() != Verdict.ALLOW;
            if (attack && stopped) caught++;
            if (!attack && stopped) falseAlarms++;
            if (i % every == 0) sample.accept(in);
        }
        long elapsed = Math.max(1, (System.nanoTime() - start) / 1_000_000);
        int benign = requests - attacks;
        return new Result(requests, attacks, benign, allowed, flagged, blocked,
                attacks == 0 ? 1 : (double) caught / attacks,
                benign == 0 ? 0 : (double) falseAlarms / benign,
                bloomFp, elapsed, requests * 1000L / elapsed);
    }

    /** Private 10.x.x.x range: never on a public blocklist, so any Bloom hit here is a true false positive. */
    private static String randomBenignIp(Random r) {
        return "10." + r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(256);
    }

    /** Real attackers obfuscate: randomly upper-case, URL-encode or double-encode the payload. */
    private static String attackUrl(Random r, List<String[]> sigs) {
        String payload = sigs.get(r.nextInt(sigs.size()))[1];
        payload = switch (r.nextInt(4)) {
            case 0 -> payload.toUpperCase();
            case 1 -> URLEncoder.encode(payload, UTF_8);
            case 2 -> URLEncoder.encode(URLEncoder.encode(payload, UTF_8), UTF_8);
            default -> payload.replace(" ", "+");
        };
        return ATTACK_TEMPLATES[r.nextInt(ATTACK_TEMPLATES.length)].formatted(payload);
    }
}
