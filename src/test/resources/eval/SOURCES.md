# Evaluation data: where it comes from

Held-out data for `HeldOutEvaluationTest`. None of it was used to write `signatures.txt`,
so detection measured on it is not circular (the built-in flood draws its attacks from the
signature list itself, so it always scores near 100 %).

## Attacks: `attacks/`

Public attack-payload lists from **PayloadsAllTheThings** by Swissky and contributors,
MIT License (full text in `LICENSE-PayloadsAllTheThings.txt`).

- Repository: https://github.com/swisskyrepo/PayloadsAllTheThings
- Pinned commit: `08ea40e77db3f42ef8f20c65196f3936a19b6c86` (fetched 17 Nov 2026)
- Files copied unchanged; each is renamed `<CATEGORY>-<original name>` so the test knows its category.

| File here | Path in the repository |
|---|---|
| `SQLI-Auth_Bypass.txt` | `SQL Injection/Intruder/Auth_Bypass.txt` |
| `SQLI-Generic_ErrorBased.txt` | `SQL Injection/Intruder/Generic_ErrorBased.txt` |
| `SQLI-Generic_TimeBased.txt` | `SQL Injection/Intruder/Generic_TimeBased.txt` |
| `SQLI-Generic_UnionSelect.txt` | `SQL Injection/Intruder/Generic_UnionSelect.txt` |
| `SQLI-SQLi_Polyglots.txt` | `SQL Injection/Intruder/SQLi_Polyglots.txt` |
| `XSS-RSNAKE_XSS.txt` | `XSS Injection/Intruders/RSNAKE_XSS.txt` |
| `XSS-JHADDIX_XSS.txt` | `XSS Injection/Intruders/JHADDIX_XSS.txt` |
| `XSS-XSS_Polyglots.txt` | `XSS Injection/Intruders/XSS_Polyglots.txt` |
| `XSS-xss_payloads_quick.txt` | `XSS Injection/Intruders/xss_payloads_quick.txt` |
| `TRAVERSAL-directory_traversal.txt` | `Directory Traversal/Intruder/directory_traversal.txt` |
| `CMDI-command_exec.txt` | `Command Injection/Intruder/command_exec.txt` |
| `CMDI-command-execution-unix.txt` | `Command Injection/Intruder/command-execution-unix.txt` |

Note: these are fuzzing lists, so some lines are fragments rather than attacks
(for example a lone `|` or a backtick). They are kept, not cherry-picked; the
report discusses what the misses are.

## Benign: `benign/wikipedia-titles.txt`

10,000 distinct titles of random English Wikipedia articles, sampled on 17 Nov 2026
through the MediaWiki API (`list=random`, main namespace), sorted. They stand in for
real human search text: names with apostrophes, `&`, words like "Union" and "Select".

Titles are from Wikipedia, licensed CC BY-SA 4.0
(https://creativecommons.org/licenses/by-sa/4.0/). This file is shared under the
same licence.
