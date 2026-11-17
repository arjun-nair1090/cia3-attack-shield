# Attack Shield: feature roadmap

Everything this app could do, ranked by how many CIA 3 marks it earns per hour of work and how hard it makes a professor stare at the projector.
Nothing below is speculative padding: every feature names the rubric line it serves, the algorithm it shows off, and its cost.

**Tiers.** Must = without it we lose rubric marks. Should = the "wow" layer. Could = only if time is left. Won't = considered and rejected, with the reason.
**Effort.** S = under 2 h, M = half a day, L = 1–2 days, for one person.

---

## 0. Where we are (17 Nov 2026)

| Built | Status |
|---|---|
| Bloom filter, signature trie + KMP, traffic segment tree, Edmonds–Karp min-cut | merged (#1–#4), 26 unit tests green |
| Pipeline, live dashboard (SSE), demo shop, flood simulator with ground-truth labels | draft PR #5 |
| Security: encoded-path bypass closed, dashboard API local-only, self-only blocklist | in #5 |
| Verdict policy `ShieldEngine.decide()` + 5 engine tests | in #5. 100k synthetic flood: 100 % detection, 0 % false alarms, 340k req/s (circular: attacks come from our own signature list, see M8) |

**What the code graph says** (graphify, 221 nodes, 11 clusters): `ShieldEngine` is the god node: 28 edges, bridging 7 of 11 clusters (betweenness 0.23). It loads data, runs the pipeline, owns the traffic ring buffer, and keeps stats. That is the first thing a "separation of concerns" examiner will poke (Java backend quality, 10 marks). See B1.

---

## 1. Must-haves: rubric gaps

| # | Feature | Rubric line it fixes | Effort |
|---|---|---|---|
| M1 | **`decide()` policy (done)**: exploit match or listed IP → BLOCK, scanner-only → FLAG. The report must discuss the cost: a listed IP may be a shared carrier IP, so innocent users behind it are blocked too. | Correctness 20, viva 15 | done |
| M2 | **Benchmark suite** at 3 sizes per algorithm vs a baseline, exported as CSV for the report (table in §5). Runnable as `./mvnw test -Dgroups=bench` and from the dashboard. | Complexity & performance 15 | M |
| M3 | **Bloom filter: theory vs measurement chart.** Fill the filter from 10 % to 150 % of its design capacity; plot measured FPR against (1 − e^(−kn/m))^k. Shows exactly when a Bloom filter stops helping. | "Sound probabilistic behaviour" (Correctness 20), CO5 | S |
| M4 | **"Inspect any text" box.** Paste a URL, header or payload, get the verdict, matched offsets and timings. No HTTP round-trip, so the examiner can change the sample input mid-viva (§10 of the brief says they will). `POST /api/inspect`. | Demo & viva 15 | S |
| M5 | **Upload your own data**: blocklist (.txt), signatures (`category|pattern`), network (JSON). Reports line numbers of malformed rows, duplicate count, empty-file error. Bloom target FPR as a slider that rebuilds the filter live. | "User can upload data, configure parameters" (min. scope), validation | M |
| M6 | **Engine & API tests**: `normalize()` double-encoding, ring-buffer wrap after 600 s, `decide()` table test, MockMvc 400s for every bad input, a regression test for the `/%73hop` bypass. | Correctness 20, API quality 10 | M |
| M7 | **README**: prerequisites (JDK 25+), `./mvnw spring-boot:run`, curl examples per endpoint, phone-on-Wi-Fi instructions, Windows firewall note, screenshots, dataset attribution (ipsum, Unlicense). | Documentation 5 | S |
| M8 | **Real labelled traffic.** Replay the CSIC 2010 HTTP dataset (≈ 61k labelled normal/attack requests) through the engine; report precision, recall and false-alarm rate on real data, not only our synthetic flood. *Check its licence terms before committing the file; otherwise ship a download script.* | "Actual or realistic data" (non-negotiable) | M |

---

## 2. Should-haves: the wow layer

Ordered by impact on the professor per hour spent.

**W1. The payload autopsy (the hero).** The latest notable request is typeset large in the middle of the screen. The exact bytes the trie matched are highlighted at the offsets the Java `Match.position()` returned, labelled with their category. Above it, small: what the attacker actually sent (`%2527%2520or%25201%3D1`). Below it, large: what the shield read after decoding (`' or 1=1`). The double-encoding trick being undone on screen is the single best 5 seconds of the demo. Effort M.

**W2. Pipeline step-through.** Press space and the last request replays slowly through the four stages.
- **Bloom:** the k = 7 probed bit positions light up on a strip of the 1.39 M-bit array.
- **Exact check:** skipped or run, and why.
- **Trie:** the walked path appears character by character, with dead ends greyed out.
- **Verdict:** the rule that fired.

This turns "explain your algorithm" in the viva into pointing at the screen. Needs one endpoint that returns the trace (bit indexes, trie walk). Effort M.

**W3. Scan-to-attack QR code.** A QR code on the dashboard opens the shop on the professor's phone. No typing IP addresses during the demo. ZXing can generate it on the server: it is infrastructure, not an assessed algorithm. Effort S.

**W4. The race.** Same 100k requests, two lanes:
- **Signature scan:** the trie against one KMP pass per signature.
- **IP check:** Bloom then exact, against exact-only. The lanes report time *and* memory: about 170 KB for the filter versus roughly 10–15 MB for a `HashSet` of 135k strings. That estimate must be measured before we quote it.

Progress bars fill at their real speed, so the professor watches one lane finish while the other is still crawling. Satisfies the baseline requirement visibly. Effort M (shares code with M2).

**W5. Aho–Corasick upgrade.** Add KMP-style failure links to the trie. Scanning drops from O(n·L) to O(n + matches), and the two Unit 4 techniques become one structure, which makes a strong viva story. Keep the current trie as the baseline, so the race gets a third lane. Effort M.

**W6. Latency percentiles with randomized Quickselect.** p50/p95/p99 inspection time from the last 10k inspections, computed by randomized selection (expected O(n)) against sort-then-index (O(n log n)). This adds a second CO5 technique cheaply. Effort S.

**W7. Flood alarm from the segment tree.** When the last-10 s sum exceeds k × the previous-60 s average, a banner reads "Flood: 48,210 requests in 10 s, peak 9,804/s at 14:02:31". Both numbers come from O(log n) range queries. The threshold multiplier is a slider. Effort S.

**W8. Break the bottleneck.** On the network view, click a min-cut link to add capacity. Edmonds–Karp re-runs, the cut jumps somewhere else, and throughput rises until a new bottleneck appears. Optionally overlay the current flood rate, so links over capacity glow. Effort S.

**W9. Inspect more than the URL.**
- **Request headers:** scan `User-Agent` and `Referer` with the same trie. That catches `sqlmap` and `nikto`, and Log4Shell lives in headers anyway.
- **Login form:** give the shop a login form whose POST body is inspected too.

Removes the biggest "but what about…" limitation. Effort S.

**W10. Presenter controls.** Keys 1–4 switch between Live, Race, Network and Evidence. `R` resets the counters, `F` launches the default flood, and `.` toggles slow-motion step-through. No mouse hunting on stage. Effort S.

---

## 3. Frontend design direction

### The brief, in one line
Make one real attack visibly arrive, get taken apart, and get stopped, readable from the back of a lit classroom on a washed-out projector.

### Why the current look has to go
The current dashboard is the default "hacker dashboard": near-black background, one red accent, ALL-CAPS tracked labels, monospace for every small label, and `A · B` meta strings. It is what any generator produces for "cyber", so it reads as AI slop. It also fails the real constraint: **projectors wash out dark themes in a lit room**.

### Concept: the security scanner
Airport baggage X-ray, not a movie hacker terminal. Requests are items going through a scanner. The screen is bright, cool and clinical. Colour means *material*:
- calm blue for traffic that passes;
- a single contraband orange for anything stopped.

Threat is never shown by colour alone: FLAG is orange *hatching*, BLOCK is solid orange. That works for colour-blind viewers and in greyscale screenshots in the report.

### Palette
| Token | Hex | Role |
|---|---|---|
| `--film` | `#F2F5F7` | Background. A cool scanner-white, deliberately not cream |
| `--graphite` | `#1E2630` | Text and strokes |
| `--steel` | `#6B7A89` | Secondary text, axes, gridlines |
| `--pass` | `#2459D6` | Allowed traffic, primary data series |
| `--stop` | `#E8650A` | Blocked: the only warm colour on screen |
| `--evidence` | `#FFE45C` | Highlighter fill behind matched bytes in the autopsy |

Dark mode exists for laptop rehearsal. It is not the default.

### Type
- **Archivo** (variable, width 62–125) for everything human. Use the condensed width for the big counters, so they are tall and dense, and the normal width for body text. Sentence case everywhere, with no tracked-out caps.
- **Martian Mono** *only* for actual request text: the payload, URLs, IPs. Monospace marks "this is what was on the wire"; it never decorates labels.
- **Scale:** 16 / 20 / 28 / 44 / 72 px, with the payload at 44–72 px depending on its length. The minimum on the projector view is 20 px.
- **Bundle both fonts** as woff2 in `static/fonts/`. Classroom Wi-Fi is not to be trusted, so nothing may load from a CDN.

### Layout (16:9, no scrolling on the Live view)
```
┌──────────────────────────────────────────────────────────────────┐
│ Attack Shield        Guarding 10.1.136.206:8080/shop     [QR]    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   sent    /shop/search?q=%2527%2520or%25201%3D1--                │
│                                                                  │
│   read    /shop/search?q=' or 1=1--                              │
│                          ████████  SQL injection, offset 15      │
│                                                                  │
│   Bloom: not listed  ▸  exact: skipped  ▸  trie: 1 match  ▸  BLOCKED in 41 µs
│                                                                  │
├────────────────────────────────────────┬─────────────────────────┤
│ ▁▁▂▁▁▁▃▁▁█▇▆▂▁▁▁  last 60 s            │  51,204 inspected       │
│ flood: 48,210 in 10 s, peak 9,804/s    │   9,877 stopped         │
│                                        │      12 Bloom false     │
│                                        │         alarms caught   │
├────────────────────────────────────────┴─────────────────────────┤
│ 14:02:31  stopped  45.148.10.151   /shop/search?q=<script>…       │
│ 14:02:31  passed   10.4.18.2       /shop/product?id=42            │
└──────────────────────────────────────────────────────────────────┘
```
- Left-aligned throughout; the payload lines share one left edge, so "sent" and "read" compare at a glance.
- The autopsy takes about 45 % of the height. Everything else is quiet.
- On phone width, the autopsy stacks above the counters and the feed hides its IP column.

### Principles
1. **Spend boldness in one place:** the autopsy. Counters, chart and feed stay plain and calm.
2. **Every number names its source.** A one-line caption under each panel says which Java class produced it ("Peak found by the segment tree in O(log n)"). The examiner should never ask where a number came from.
3. **Motion only when a request arrives.** The autopsy swaps with a short wipe in the direction of the pipeline; a stopped request leaves one orange afterimage on its feed row. No ambient pulsing, no fade-in on page load. `prefers-reduced-motion` swaps the wipe for an instant change.
4. **Attacker text is never markup.** Everything is `textContent`; highlights are built as separate DOM nodes split at server-given offsets. The dashboard must not be vulnerable to the attacks it reports.
5. **Copy is plain verbs:** "Stopped", "Passed", "Flagged for review"; "Launch flood", not "Submit". Errors say what to fix: "Line 14: missing `|` between category and pattern".
6. **Accessibility floor:** 4.5:1 contrast for text, visible keyboard focus, the feed as a real `<table>` with headers, and an `aria-live="polite"` region announcing stops at most once per second.

---

## 4. Backend quality

**B1. Break up the god node** (from the graphify finding). Split `ShieldEngine` into:
- `Blocklist`: Bloom filter plus the exact set, with loading, adding and stats.
- `SignatureScanner`: the trie, normalisation and loading.
- `TrafficWindow`: the ring buffer over two segment trees.
- `ShieldEngine`: orchestration and `decide()` only. About 80 lines.

Same behaviour, and each teammate owns one class for the viva. Effort M.

**B2. Publish events off the request thread.** A bounded queue plus one sender thread, so a slow dashboard can never delay the shop. When the queue is full, drop events and show a "dropped N events" count. Effort S.

**B3. Consistent errors.** One `@RestControllerAdvice` returning `{error, field}` with the right status codes. That means 413 for oversized uploads and 400 for malformed JSON instead of Spring's default page. Effort S.

**B4. Config in one place.** Window length, Bloom target FPR, flood threshold and local-only mode in `application.properties`, with defaults documented in the README. Effort S.

---

## 5. Evidence plan (benchmarks)

Every row: three input sizes, five warm-up runs then ten timed runs, median plus spread, run on the same machine, CSV saved under `docs/bench/`.

| Algorithm | Baseline | Sizes | What should happen |
|---|---|---|---|
| Signature trie (and Aho–Corasick) | KMP once per signature; naive `indexOf` loop | 10k / 100k / 1M requests × 49, 500, 5,000 signatures | Trie time is flat as the signature count grows; the KMP baseline grows linearly |
| Bloom → exact | Exact `HashSet` only | 10k / 100k / 1M lookups; 135k / 500k / 1M listed IPs | Similar speed, but far less memory (estimated ~70×: 170 KB vs ~12 MB; to be measured); FPR tracks theory up to design capacity |
| Segment tree | Plain array: O(1) update, O(n) range sum | 600 / 6,000 / 60,000 buckets × 100k queries | Log-shaped growth against linear growth; crossover at small n is shown honestly |
| Edmonds–Karp | Ford–Fulkerson with DFS paths | 100 / 1,000 / 10,000 nodes, plus the classic "1,000,000-capacity" trap graph | EK's augmentation count is bounded by O(VE); DFS-FF blows up on the trap graph |
| Randomized Quickselect (W6) | Sort then index | 10k / 100k / 1M latencies | Expected O(n) against O(n log n) |

The report must state when the "better" algorithm is *not* better. For example, the segment tree loses to the plain array at 60 buckets. Honest crossovers earn more marks than cherry-picked wins.

---

## 6. Could-haves

- **Attack origin map.** Look up each IP's country from the DB-IP Lite range table (CC BY 4.0), binary-searching its sorted ranges. It looks great, but it's tens of MB of data and none of it is a syllabus algorithm. Effort L.
- **Per-IP rate limiting.** One segment tree per hot IP, keeping the top-k by count in a binary heap (Unit 2). It's real, but it's a third data structure to defend in the viva. Effort M.
- **Event history in SQLite.** Lets the evidence survive restarts. Optional per the brief. Effort M.
- **Sound on stop.** One soft click, off by default. Effort S.

## 7. Won't do (and why)

- **Machine-learning anomaly detection.** It isn't on the syllabus, and the brief wants our own algorithm at the centre, not a model.
- **A React rewrite.** It's worth 5 marks at most. Plain JS keeps `./mvnw spring-boot:run` as the only command, which protects reproducibility.
- **A user-login system.** Local-only dashboard access already solves the real risk, and auth adds code with no marks attached.
- **Public cloud deployment.** It would put a deliberately attackable target on the internet. The brief accepts a local demo.
- **Packet capture or firewall integration.** It's OS-specific and fragile on stage, and HTTP-level inspection is the honest scope.

---

## 8. The 8-minute demo script

| Time | What happens | What it proves |
|---|---|---|
| 0:00 | The professor scans the QR code and browses the shop: "passed" rows appear | Real HTTP, real pipeline |
| 1:00 | They type `' or 1=1--`, and the autopsy fills the screen with the match highlighted | Trie, verdict, live SSE |
| 2:00 | We send a double-encoded payload; "sent" and "read" differ on screen | Normalisation, robustness |
| 3:00 | Step-through: Bloom bits light up, then the trie walk | Algorithm visibility |
| 4:00 | "Block my IP" from their phone; their next request stops at the Bloom filter | Bloom → exact, runtime update |
| 5:00 | Launch a 200k flood: the spike, the flood banner, detection and false-alarm rates | Segment tree, measured success |
| 6:00 | The race, with time and memory per lane | Baselines (15 marks) |
| 7:00 | Network view: the min-cut, then "reinforce" it and watch the cut move | Unit 5 |
| 7:30 | The examiner edits the input in the "inspect any text" box | Handles changed input live |

**Rehearse offline:** phone hotspot, a firewall rule for the port, fonts bundled. Have a `--shield.dashboard.local-only=false` fallback ready if the projector laptop isn't the server.

## 9. Order of work and ownership

| Week | Work | Suggested owner |
|---|---|---|
| 11 | M1, M7 skeleton, proposal | all |
| 12 | B1 split, M6 tests, M4 inspect box | Engine owner |
| 13 | §3 redesign + W1 autopsy, W3 QR, W10 keys | Frontend owner |
| 13 | M2 + W4 race, M3 Bloom chart, W6 Quickselect | Algorithms owner |
| 14 | M5 uploads, M8 CSIC replay, W2 step-through, W5 Aho–Corasick | split |
| 15 | Report numbers from `docs/bench/`, rehearse §8 twice | all |

Each person should be able to explain one Unit 4–6 technique end to end: the Bloom filter, the trie or Aho–Corasick, or Edmonds–Karp. Commits under their own name make the contribution traceable.
