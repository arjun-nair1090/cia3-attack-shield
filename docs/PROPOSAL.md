# Project proposal: Attack Shield

**Course:** Advanced Algorithms, CIA 3 · B.Tech CS AI & ML, Semester V · ATLAS uGDX, 2026–27
**Team:** Arjun Nair, register no. `__________` (individual submission; faculty approval for working alone: `__________`)

## Problem

Small web services, such as a campus store, are probed by automated attack scanners within minutes of going online.
These scanners try SQL injection, cross-site scripting, path traversal and command injection, often from addresses
already on public abuse feeds. Commercial web application firewalls are expensive and opaque. The goal is a request
filter that is **fast enough for every request**, **never blocks a request because of a probabilistic error**, and
**shows exactly why** it stopped each request.

## Target users

- **The operator of a small web service** (for example a campus IT administrator) who needs bad requests screened
  and wants every decision explained.
- **A security instructor** who uses the live dashboard to show students real attacks being caught and taken apart.

## Features

1. A screening pipeline in front of a demo shop: blocklist precheck → exact confirmation → signature scan → verdict
   (block / flag / allow). Each stopped request is answered with a 403.
2. A live dashboard showing each stopped request as sent and as decoded, with the matched bytes highlighted.
3. An inspect box: paste any text, and Java decodes and judges it without affecting the statistics.
4. A per-second traffic chart over the last 10 minutes, with the peak second.
5. Bloom filter tuning: choose a false-positive target, optionally upload a blocklist, and compare the measured rate
   with the theoretical one.
6. A network bottleneck tool: maximum throughput and the minimum cut of a server network.
7. A labelled flood generator to measure throughput and plumbing under load.

## Techniques and why each fits

| Technique (unit) | Used for | Why this and not the obvious alternative |
|---|---|---|
| Bloom filter (Unit 6, CO5) | Blocklist precheck on 135,530 IPs | Answers "definitely not listed" for about 98 % of requests from a structure about 85 times smaller than a hash set. No false negatives; false positives are removed by an exact check. |
| Trie multi-pattern matching (Unit 4); KMP as baseline | Attack-signature scan | One pass finds every signature, at a cost independent of how many signatures exist. Running KMP once per signature grows linearly with the signature count. |
| Segment tree (Unit 3) | Range sums and peak over the traffic window | O(log n) updates and queries, vs O(n) for scanning an array, whatever window length is asked for. |
| Edmonds–Karp max-flow / min-cut (Unit 5) | Network bottleneck | The number of augmenting paths does not depend on the capacities (O(VE)). DFS Ford–Fulkerson can need as many paths as the flow value, which is huge for capacities in requests per second. |

All four are implemented by hand in Java, with no algorithm libraries, and are covered by unit tests. The browser
only displays results.

## Data sources

- **Blocklist:** a snapshot of the ipsum malicious-IP feed (135,530 addresses; Unlicense).
- **Signatures:** written for this project from the OWASP attack families (49 signatures in 7 categories).
- **Held-out evaluation:** public attack payloads from PayloadsAllTheThings (MIT, pinned commit) and 10,000 random
  Wikipedia titles as benign searches (CC BY-SA 4.0). None of this data is used to write the signatures.
- **Load:** a seeded, labelled traffic generator.

## Measurable success criteria

| # | Criterion | Target |
|---|---|---|
| 1 | Listed IPs missed | 0 |
| 2 | Requests blocked because of a Bloom false positive | 0 |
| 3 | Measured Bloom false-positive rate vs theory, up to design capacity | within 0.1 percentage points |
| 4 | Signature scan cost from 49 to 5,000 signatures | flat (trie), against linear growth for the KMP baseline |
| 5 | Mean pipeline latency per request | ≤ 10 µs |
| 6 | False alarms on real benign text | < 1 % |
| 7 | Detection rate on held-out public payloads | measured and reported honestly, with the misses analysed |
| 8 | Each algorithm benchmarked against a baseline on ≥ 3 input sizes | median of 7 runs, results cross-checked |

## Deliverables

A Spring Boot application with a REST API and dashboard; unit and API tests; a benchmark and evaluation suite with
CSV results and charts; a README; and a technical report (`docs/REPORT.md`) with design, pseudocode, correctness
arguments, complexity and results.
