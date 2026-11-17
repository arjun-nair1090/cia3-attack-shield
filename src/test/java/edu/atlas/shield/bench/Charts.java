package edu.atlas.shield.bench;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Minimal static SVG line charts for the report (no plotting library, so the benchmark run is the only tool needed).
 * Static images cannot have hover, so every chart sits next to its CSV table in the report: the table is the
 * accessible view. Palette: categorical slots 1-3 of the dataviz reference palette (validated all-pairs, light).
 * Identity is never colour alone: every series has a legend entry, a direct end label and its own marker shape.
 */
final class Charts {

    enum Style { LINE, DASHED, POINTS } // POINTS over DASHED: measured values sitting on a theory curve

    record Series(String name, double[] x, double[] y, Style style) {
        Series(String name, double[] x, double[] y) { this(name, x, y, Style.LINE); }

        Series as(Style s) { return new Series(name, x, y, s); }
    }

    private static final String[] COLOR = {"#2a78d6", "#eb6834", "#1baf7a"};
    private static final String SURFACE = "#fcfcfb", INK = "#0b0b0b", INK2 = "#52514e", GRID = "#e4e3df";
    private static final int W = 720, H = 400, L = 76, R = 190, T = 56, B = 56;

    private Charts() {}

    /** Every report chart, drawn from the CSV files in docs/bench (so charts can be redrawn without re-measuring). */
    static void drawAll() {
        List<String> sig = rows("signature-scan.csv"), mem = rows("bloom-vs-exact.csv"), fpr = rows("bloom-fpr.csv"), seg = rows("segment-tree.csv");
        if (!sig.isEmpty()) line("signature-scan.svg", "Scanning one request for every signature", "signatures loaded",
                "microseconds per request (median)", true, true, List.of(
                        series(sig, "trie (one pass)", "Trie, one pass", 1, 6, 1),
                        series(sig, "KMP once per signature", "KMP per signature", 1, 6, 1),
                        series(sig, "String.indexOf per signature", "indexOf per signature", 1, 6, 1)), Double.NaN, "");
        if (!mem.isEmpty()) line("bloom-memory.svg", "Memory to hold the blocklist", "listed IP addresses",
                "megabytes", true, true, List.of(
                        series(mem, "HashSet only", "HashSet of strings", 1, 7, 1e-6),
                        series(mem, "Bloom filter alone", "Bloom filter, 1 % FPR", 1, 7, 1e-6)), Double.NaN, "");
        if (!fpr.isEmpty()) line("bloom-fpr.svg", "Bloom filter false positives as it fills past its design size",
                "% of design capacity filled", "false-positive rate, %", false, false, List.of(
                        series(fpr.stream().map(r -> "m," + r).toList(), "m", "Measured", 1, 5, 100).as(Style.POINTS),
                        series(fpr.stream().map(r -> "t," + r).toList(), "t", "Theory (1-e^(-kn/m))^k", 1, 6, 100).as(Style.DASHED)),
                1.0, "design target 1 %");
        if (!seg.isEmpty()) line("segment-tree.svg", "Range sum + peak queries mixed with updates", "one-second buckets",
                "nanoseconds per operation (median)", true, true, List.of(
                        series(seg, "segment tree", "Segment tree", 1, 6, 1),
                        series(seg, "plain array", "Plain array", 1, 6, 1)), Double.NaN, "");
    }

    /** Data rows of a CSV in docs/bench (header dropped), or empty if that experiment has not been run. */
    private static List<String> rows(String file) {
        try {
            Path p = BenchmarkTest.OUT.resolve(file);
            return Files.exists(p) ? Files.readAllLines(p, UTF_8).stream().skip(1).filter(l -> !l.isBlank()).toList() : List.of();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** One series: the rows whose first column is {@code key}, x and y from the given columns (unquoted CSV only). */
    private static Series series(List<String> rows, String key, String label, int xCol, int yCol, double yScale) {
        List<String[]> mine = rows.stream().map(r -> r.split(",")).filter(c -> c[0].equals(key)).toList();
        double[] x = new double[mine.size()], y = new double[mine.size()];
        for (int i = 0; i < x.length; i++) {
            x[i] = Double.parseDouble(mine.get(i)[xCol]);
            y[i] = Double.parseDouble(mine.get(i)[yCol]) * yScale;
        }
        return new Series(label, x, y);
    }

    /** @param refY a dashed horizontal reference line (e.g. a design target), or NaN for none */
    static void line(String file, String title, String xLabel, String yLabel, boolean logX, boolean logY,
                     List<Series> series, double refY, String refLabel) {
        if (series.size() > COLOR.length) throw new IllegalArgumentException("at most 3 series per chart");
        double x0 = Double.MAX_VALUE, x1 = -Double.MAX_VALUE, y0 = Double.MAX_VALUE, y1 = -Double.MAX_VALUE;
        for (Series s : series)
            for (int i = 0; i < s.x().length; i++) {
                x0 = Math.min(x0, s.x()[i]); x1 = Math.max(x1, s.x()[i]);
                y0 = Math.min(y0, s.y()[i]); y1 = Math.max(y1, s.y()[i]);
            }
        if (!Double.isNaN(refY)) { y0 = Math.min(y0, refY); y1 = Math.max(y1, refY); }
        Axis ay = Axis.of(logY ? y0 : 0, y1, logY);
        Axis ax = new Axis(x0, x1, logX, xTicks(series)); // x ticks sit exactly on the tested sizes

        StringBuilder svg = new StringBuilder();
        svg.append(String.format(Locale.ROOT, "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 %d %d' width='%d' height='%d' "
                + "font-family='Archivo, Segoe UI, Helvetica, Arial, sans-serif' role='img' aria-label='%s'>\n", W, H, W, H, esc(title)));
        svg.append(String.format(Locale.ROOT, "<rect width='%d' height='%d' fill='%s'/>\n", W, H, SURFACE));
        svg.append(String.format(Locale.ROOT, "<text x='%d' y='28' font-size='17' font-weight='700' fill='%s'>%s</text>\n", L - 60, INK, esc(title)));

        int pw = W - L - R, ph = H - T - B;
        for (double v : ay.ticks()) { // recessive grid + y labels
            double py = T + ph - ay.frac(v) * ph;
            svg.append(String.format(Locale.ROOT, "<line x1='%d' x2='%d' y1='%.1f' y2='%.1f' stroke='%s' stroke-width='1'/>\n", L, L + pw, py, py, GRID));
            svg.append(String.format(Locale.ROOT, "<text x='%d' y='%.1f' font-size='12' fill='%s' text-anchor='end'>%s</text>\n", L - 8, py + 4, INK2, num(v)));
        }
        for (double v : ax.ticks()) {
            double px = L + ax.frac(v) * pw;
            svg.append(String.format(Locale.ROOT, "<text x='%.1f' y='%d' font-size='12' fill='%s' text-anchor='middle'>%s</text>\n", px, T + ph + 18, INK2, num(v)));
        }
        svg.append(String.format(Locale.ROOT, "<line x1='%d' x2='%d' y1='%d' y2='%d' stroke='%s'/>\n", L, L + pw, T + ph, T + ph, INK2));
        svg.append(String.format(Locale.ROOT, "<text x='%d' y='%d' font-size='13' fill='%s' text-anchor='middle'>%s</text>\n", L + pw / 2, H - 12, INK2, esc(xLabel + (logX ? " (log scale)" : ""))));
        svg.append(String.format(Locale.ROOT, "<text x='%d' y='%d' font-size='13' fill='%s'>%s</text>\n", L - 60, 46, INK2, esc(yLabel + (logY ? " (log scale)" : ""))));

        if (!Double.isNaN(refY)) {
            double py = T + ph - ay.frac(refY) * ph;
            svg.append(String.format(Locale.ROOT, "<line x1='%d' x2='%d' y1='%.1f' y2='%.1f' stroke='%s' stroke-width='1.5' stroke-dasharray='6 4'/>\n", L, L + pw, py, py, INK2));
            svg.append(String.format(Locale.ROOT, "<text x='%d' y='%.1f' font-size='12' fill='%s'>%s</text>\n", L + pw + 10, py + 4, INK2, esc(refLabel)));
        }

        List<double[]> ends = new ArrayList<>();
        for (int pass = 0; pass < 2; pass++) // dashed curves first, so points and solid lines sit on top
            for (int s = 0; s < series.size(); s++) {
                Series se = series.get(s);
                if ((se.style() == Style.DASHED) != (pass == 0)) continue;
                StringBuilder pts = new StringBuilder();
                for (int i = 0; i < se.x().length; i++)
                    pts.append(String.format(Locale.ROOT, "%.1f,%.1f ", L + ax.frac(se.x()[i]) * pw, T + ph - ay.frac(se.y()[i]) * ph));
                if (se.style() != Style.POINTS)
                    svg.append(String.format(Locale.ROOT, "<polyline points='%s' fill='none' stroke='%s' stroke-width='2' stroke-linejoin='round'%s/>\n",
                            pts.toString().trim(), COLOR[s], se.style() == Style.DASHED ? " stroke-dasharray='7 5'" : ""));
                if (se.style() != Style.DASHED)
                    for (int i = 0; i < se.x().length; i++)
                        svg.append(marker(s, L + ax.frac(se.x()[i]) * pw, T + ph - ay.frac(se.y()[i]) * ph));
                int last = se.x().length - 1;
                ends.add(new double[]{T + ph - ay.frac(se.y()[last]) * ph, s});
            }
        // Direct labels at the line ends, nudged apart so they never collide.
        ends.sort((a, b) -> Double.compare(a[0], b[0]));
        for (int i = 1; i < ends.size(); i++) ends.get(i)[0] = Math.max(ends.get(i)[0], ends.get(i - 1)[0] + 16);
        for (double[] e : ends) {
            int s = (int) e[1];
            if (series.get(s).style() == Style.DASHED)
                svg.append(String.format(Locale.ROOT, "<line x1='%d' x2='%d' y1='%.1f' y2='%.1f' stroke='%s' stroke-width='2' stroke-dasharray='4 3'/>\n",
                        L + pw + 8, L + pw + 22, e[0] - 4, e[0] - 4, COLOR[s]));
            else svg.append(marker(s, L + pw + 16, e[0] - 4));
            svg.append(String.format(Locale.ROOT, "<text x='%d' y='%.1f' font-size='12.5' fill='%s'>%s</text>\n", L + pw + 26, e[0], INK, esc(series.get(s).name())));
        }
        svg.append("</svg>\n");
        try {
            Files.writeString(BenchmarkTest.OUT.resolve(file), svg.toString(), UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Circle, square, diamond: shape is the secondary encoding next to colour. Surface ring keeps overlaps legible. */
    private static String marker(int s, double x, double y) {
        String common = String.format(Locale.ROOT, "fill='%s' stroke='%s' stroke-width='2'", COLOR[s], SURFACE);
        return switch (s) {
            case 0 -> String.format(Locale.ROOT, "<circle cx='%.1f' cy='%.1f' r='5' %s/>\n", x, y, common);
            case 1 -> String.format(Locale.ROOT, "<rect x='%.1f' y='%.1f' width='10' height='10' rx='1.5' %s/>\n", x - 5, y - 5, common);
            default -> String.format(Locale.ROOT, "<path d='M%.1f %.1f l6 6 l-6 6 l-6 -6 z' %s/>\n", x, y - 6, common);
        };
    }

    private static List<Double> xTicks(List<Series> series) {
        java.util.TreeSet<Double> t = new java.util.TreeSet<>();
        for (Series s : series) for (double x : s.x()) t.add(x);
        return new ArrayList<>(t);
    }

    /** fixedTicks == null: y axis, bounds rounded out (log: whole decades; linear: whole steps from 0) so no point touches an edge. */
    private record Axis(double lo, double hi, boolean log, List<Double> fixedTicks) {
        static Axis of(double lo, double hi, boolean log) {
            if (log) {
                double a = Math.pow(10, Math.floor(Math.log10(lo))), b = Math.pow(10, Math.ceil(Math.log10(hi)));
                return new Axis(a, b > a ? b : a * 10, true, null);
            }
            double step = nice(hi / 5);
            return new Axis(0, Math.ceil(hi / step * 1.0001) * step, false, null);
        }

        /** The x axis keeps 4 % padding at each end so end markers are never cut by the frame. */
        double frac(double v) {
            double f = log ? (Math.log10(v) - Math.log10(lo())) / Math.max(1e-9, Math.log10(hi()) - Math.log10(lo()))
                           : (v - lo()) / Math.max(1e-12, hi() - lo());
            return fixedTicks == null ? f : 0.04 + 0.92 * f;
        }

        List<Double> ticks() {
            if (fixedTicks != null) return fixedTicks;
            List<Double> t = new ArrayList<>();
            if (log) for (double p = lo(); p <= hi() * 1.0001; p *= 10) t.add(p);
            else {
                double step = nice(hi() / 5);
                for (double v = 0; v <= hi() * 1.0001; v += step) t.add(v);
            }
            return t;
        }

        private static double nice(double raw) {
            double p = Math.pow(10, Math.floor(Math.log10(raw))), m = raw / p;
            return (m < 1.5 ? 1 : m < 3 ? 2 : m < 7 ? 5 : 10) * p;
        }
    }

    static String num(double v) {
        if (v == 0) return "0";
        if (Math.abs(v) >= 1000) return String.format(Locale.ROOT, "%,.0f", v);
        if (Math.abs(v) >= 10) return String.format(Locale.ROOT, "%.0f", v);
        if (Math.abs(v) >= 1) return String.format(Locale.ROOT, "%.1f", v).replace(".0", "");
        return new java.math.BigDecimal(String.format(Locale.ROOT, "%.3g", v)).stripTrailingZeros().toPlainString();
    }

    private static String esc(String s) { return s.replace("&", "&amp;").replace("<", "&lt;").replace("'", "&#39;"); }
}
