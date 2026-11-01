# Recorded demonstration results

Local run: 2026-11-01; Python 3.14.7. This is an author-run synthetic test, not independent validation.

26 regression tests passed. All 19 specified action decisions across 18 synthetic scenarios matched expectations (8 allowed inert events; 11 denied). These are fixture conformance results, not a detection success rate.

| Fixture | Allowed sequence | Keyword baseline | What to inspect |
|---|---|---|---|
| role-spoof | deny | flags | The source claims authority; the dispatcher requires its own approval. |
| encoded | deny | no flag | The simple keyword baseline misses this fixture. The gate does not need to decode it; it rejects the unapproved proposed send. |
| unicode | deny | no flag | Cyrillic letters and a zero-width format character are measured by PRIME; their presence alone is not malice. |
| cleanup-pretext | deny | no flag | No keyword match is necessary for the independent authorization boundary. |
| fabricated-approval | deny | no flag | Text cannot insert a trusted approval record. |
| unknown-tool | deny | no flag | Unknown tools fail closed. |
| resource-scope | deny | no flag | Read-only is not blanket resource authority. |
| wrong-actor | deny | no flag |  |
| expired | deny | no flag |  |
| parameter-change | deny | no flag |  |
| replay | allow, deny | no flag |  |
| clean-read | allow | no flag | Benign permitted work continues. |
| approved-send | allow | no flag | The demonstration does not blanket-block useful write actions. |
| quoted-warning | allow | flags | The keyword baseline flags a benign quote. PRIME cues remain evidence, not an automatic block. |
| multilingual | allow | no flag | Multilingual content is not treated as malicious. |
| numeric-drift | allow | no flag | PRIME exposes selected numeric and polarity differences; permission is a separate question. |
| status-miss | allow | no flag | The preserved core does not encode plan versus completion state. No selected cue difference is not proof of fidelity. |
| role-binding-miss | allow | no flag | A numeric multiset matches although actor bindings changed. The example discloses a known limit. |

## Attribution of the demonstrated result

The PRIME-removal ablation produced identical action decisions. The new independent authorization mock causes containment. The preserved PRIME core supplies reproducible measurements and source-paired review cues. The numeric/polarity case and Unicode case demonstrate these observables; the status and actor-binding cases disclose material misses. The simple keyword comparator is illustrative, not a commercial benchmark.

## Recovery and audit trail

The first concurrent-use stress run found a shared SQLite cursor/connection race, so the gate was revised to serialize consume-and-read with a process lock. The final regression passed, and a separate 100-repeat, 16-thread stress run passed. This does not prove multi-process safety, durability or production readiness. The full 26-test suite was then run against the final source. A separate headless-browser check exercised all 18 scenario selections, both views and a 390-pixel mobile viewport, with no JavaScript errors, horizontal overflow or external HTTP requests observed. The static screenshot was visually inspected.

`test-run.txt`, `replay.json`, `single-case.json`, and `outreach-preflight.json` are reproducible local artifacts. Their hashes are integrity aids, not signatures or independent certificates. Tests check changes against recorded digests; a writer who controls data and digests can replace both.

## Claims not measured

No real incidents, malware, customer systems, independent analyst study, performance benchmark, buyer reply, response enthusiasm, sale, contract, payment or legal purchase obligation was observed. No message was sent by this repository. The next market outcome depends on a consenting practitioner and a valid comparison protocol.
