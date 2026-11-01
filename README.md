# PRIME security demonstrator

A reproducible, offline demonstration of two different things:

1. Nathaniel Michael Jaffe-Norris’s preserved AEE × LOGODECRYPT PRIME core produces source-paired text observables, selected review cues and unsigned integrity receipts.
2. A separate, newly written mock dispatcher refuses proposed actions without exact, actor-bound, unexpired, single-use authorization.

This is a synthetic defensive evaluation harness, not a malware neutralizer, vulnerability scanner or production security boundary. It does not execute payloads, contact any target, send a message or delete a file. No corpus or private customer data is included.

## See the demonstration

Open `site/index.html` locally. It is a self-contained visual replay of the checked-in evidence. It uses no external scripts, analytics, uploads or network calls. The page does not run PRIME in your browser; regenerate the data with Python to reproduce it.

```sh
git clone https://github.com/socio-sapien/prime-security-demonstrator.git
cd prime-security-demonstrator
python3 -m unittest discover -s tests -v
python3 security_demo.py > replay.json
python3 security_demo.py --case fixtures/example-local-case.json > single-case.json
python3 security_demo.py --verify single-case.json
python3 outreach_plan.py
```

Python 3.10+ standard library; no API key, paid service, model download or package installation. A local JSON case is read as data. Its text is never executed. Text/context are each bounded to 64 KiB; proposed actions are bounded to 50. Do not paste secrets or proprietary logs into GitHub issues.

## What the checked-in run actually shows

- 18 synthetic scenarios and 19 proposed mock actions. The replay outputs match all 19 explicitly specified decisions.
- Known unapproved sends, deletions, out-of-scope reads, changed recipients, expired approvals, wrong actors and token replay are denied in the mock dispatcher.
- A scoped read and independently approved exact write still proceed as inert events.
- PRIME records two mixed-script tokens and U+200B in the camouflage specimen.
- PRIME exposes the selected `12 → 15` and `failed → passed` differences in the paired-text specimen.
- The included deliberately simple keyword baseline flags a benign quotation and misses encoded/camouflaged instructions. This is not a comparison with commercial products or current best detectors.
- PRIME itself misses plan-versus-completion drift and number/actor rebinding in two explicit fixtures. Those misses are kept in the demo.
- 26 local regression tests pass, including schema/size bounds, tamper checks, a concurrent single-use test and a PRIME-removal ablation.

The decisive ablation: removing PRIME does not change any gate decision. Authorization, not a PIC or T_d score, causes the demonstrated containment. PRIME’s separately demonstrated contribution is inspectable text evidence. Whether that evidence improves real analyst accuracy, speed or cost still needs a blinded external evaluation.

## Mechanism and trust boundary

```text
untrusted text + manually specified proposed mock action
                  |
       +----------+------------------+
       |                             |
PRIME observables              mock authorization gate
cue spans / paired text        trusted test authority only
unsigned receipt               actor + exact args + expiry + single-use
       |                             |
review evidence                allowed / denied inert event
       +----------------+------------+
                        |
                  replay receipt
```

This is not an end-to-end agent: no LLM or planner translates text into actions. Fixture actions are deliberately specified by the test author. `fixtures/trusted_test_setup.json` supplies simulated owner approvals only to the bundled test harness. `--case` never accepts approvals embedded in a submitted case. The virtual test clock is 1000; expiry values are fixture ticks, not wall-clock timestamps. Real deployment requires authenticated identity/approvals, complete effect mediation, durable revocation/consumption, crash and multi-process handling, rate limiting and an independent security review. The in-memory store resets each run; this code must not be treated as production authorization.

## Claim boundaries

PIC and T_d reproduce formula labels from the preserved core. They are not calibrated probabilities, truth scores, pathogen measures or evidence that malware was disabled. The geometric/toroidal containment mechanism in earlier promotional text has not been implemented or validated here. No tested result establishes universal threat detection, 100% accuracy, competitive uniqueness, a legal duty to purchase, buyer enthusiasm or prompt payment.

SHA-256 receipts detect a change relative to a retained digest. They are unsigned: a party able to rewrite a report can recompute its hash. They do not establish identity, an independent timestamp, custody or independent verification.

## Work products

- [Threat model and evaluation protocol](docs/EVALUATION.md)
- [Evidence-based market path and preflight sequence](docs/OUTREACH.md)
- [Test/run results](docs/RESULTS.md)
- [Preserved core provenance](docs/PROVENANCE.md)
- `evidence/replay.json`: full source-paired calculations and mock traces.
- `evidence/test-run.txt`: recorded local test output, not an independent certification.
- `outreach_plan.py`: offline, fail-closed engagement-preflight simulation. It sends nothing.

## Commercial evaluation proposal, not an offer already accepted

A suitable first engagement is a bounded, human-reviewed evaluation: the practitioner supplies authorized synthetic/redacted examples and baseline outcomes; both parties agree error labels and acceptance criteria before a blind held-out run. Compare reviewer error and time with/without PRIME; disclose every miss. Discuss fees only after scope, decision-maker, budget and evidence are established. No price, contract or payment is implied by viewing this repository.

## Rights

The existing core is preserved from Nathaniel’s public repository with attribution and pinned provenance. No new blanket open-source licence or customer-data licence has been granted by this demonstration. Public visibility is not permission to use third-party private data. Contact the repository owner about commercial rights and engagement terms.
