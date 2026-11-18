package edu.atlas.shield.bench;

import edu.atlas.shield.core.Inspection;
import edu.atlas.shield.core.ShieldEngine;
import edu.atlas.shield.core.Verdict;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Detection measured on data the signatures were NOT written from (the built-in flood is circular: its attacks
 * come from the signature list itself, so it always scores ~100 %).
 * <ul>
 *   <li>Attacks: public payload lists from PayloadsAllTheThings (MIT), pinned to one commit; see the Data section of README.md.</li>
 *   <li>Benign: 10,000 random English Wikipedia article titles (CC BY-SA 4.0) typed into the shop search box.</li>
 * </ul>
 * Every input is sent the way a browser sends a search: /shop/search?q=URL-encoded text, from a clean IP, so only
 * the signature stage can catch it. Run with the benchmarks: ./mvnw test -Dgroups=bench -DexcludedGroups=none
 */
@Tag("bench")
class HeldOutEvaluationTest {

    static final Path EVAL = Path.of("src/test/resources/eval");

    static List<String> lines(Path p) {
        try {
            return Files.readAllLines(p, UTF_8).stream().map(s -> s.replace("\r", "")).filter(s -> !s.isBlank()).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static String asSearch(String text) { return "/shop/search?q=" + URLEncoder.encode(text, UTF_8); }

    static String csv(String s) { return '"' + s.replace("\"", "\"\"") + '"'; }

    @Test
    void detectionOnHeldOutPayloadsAndRealBenignText() throws IOException {
        ShieldEngine engine = new ShieldEngine();
        Map<String, int[]> perCategory = new LinkedHashMap<>(); // category -> {payloads, caught}
        List<String> missed = new ArrayList<>(), falseAlarms = new ArrayList<>();
        int attacks = 0, caught = 0;

        List<Path> files;
        try (Stream<Path> s = Files.list(EVAL.resolve("attacks"))) { files = s.sorted().toList(); }
        for (Path f : files) {
            String category = f.getFileName().toString().split("-", 2)[0]; // file names start with SQLI-, XSS-, ...
            for (String payload : lines(f)) {
                Inspection in = engine.analyze("10.20.30.40", asSearch(payload));
                boolean stopped = in.verdict() != Verdict.ALLOW;
                int[] c = perCategory.computeIfAbsent(category, k -> new int[2]);
                c[0]++;
                attacks++;
                if (stopped) { c[1]++; caught++; }
                else missed.add(String.join(",", category, csv(f.getFileName().toString()), csv(payload)));
            }
        }

        List<String> benign = lines(EVAL.resolve("benign/wikipedia-titles.txt"));
        int alarms = 0;
        for (String title : benign) {
            Inspection in = engine.analyze("10.20.30.41", asSearch(title));
            if (in.verdict() != Verdict.ALLOW) {
                alarms++;
                falseAlarms.add(String.join(",", in.verdict().name(), csv(title), csv(String.join("; ", in.reasons()))));
            }
        }

        List<String> rows = new ArrayList<>();
        for (var e : perCategory.entrySet())
            rows.add(String.join(",", e.getKey(), String.valueOf(e.getValue()[0]), String.valueOf(e.getValue()[1]),
                    BenchmarkTest.f((double) e.getValue()[1] / e.getValue()[0])));
        rows.add(String.join(",", "ALL ATTACKS", String.valueOf(attacks), String.valueOf(caught), BenchmarkTest.f((double) caught / attacks)));
        rows.add(String.join(",", "BENIGN (false alarms)", String.valueOf(benign.size()), String.valueOf(alarms), BenchmarkTest.f((double) alarms / benign.size())));
        BenchmarkTest.write("held-out-detection.csv", "set,inputs,stopped,rate", rows);

        // Precision: of everything stopped, how much was really an attack (attack and benign sets weighted as tested).
        double precision = (double) caught / (caught + alarms);
        System.out.printf(Locale.ROOT, "recall %.4f, false-alarm rate %.4f, precision %.4f%n",
                (double) caught / attacks, (double) alarms / benign.size(), precision);
        BenchmarkTest.write("held-out-missed.csv", "category,source_file,payload", missed);
        BenchmarkTest.write("held-out-false-alarms.csv", "verdict,title,reasons", falseAlarms);

        assertTrue(attacks > 1_000 && benign.size() >= 5_000, "evaluation data is missing from " + EVAL);
    }
}
