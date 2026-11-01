# Evaluation protocol and threat model

## Threat to demonstrate

An untrusted document can contain apparent instructions, forged roles or fabricated approvals. A model may propose an unwanted tool action after reading it. This harness begins after that proposal: it supplies proposed actions explicitly and checks a mock dispatcher. It does not test whether a real model would propose them.

## Preconditions and attacker control

The attacker can alter source text and the proposed action/approval identifier. They cannot edit the program, the synthetic harness’s trusted setup, the approval store or its actor. A local administrator controlling these files is outside the boundary. The fixture’s `attack` label is an author-supplied label, not PRIME’s verdict. A `read_demo` succeeds only for the fixed resource `public-demo`. No tool has an external adapter.

## Three distinct experiments

1. Text observability: preserve exact source/context, identify selected number/polarity differences and Unicode controls, verify byte/canonical receipts. Show false negatives rather than burying them.
2. Authorization: test actor, action arguments, expiry, unknown tools/resources, single-use and concurrency. The gate uses an atomic conditional SQLite update plus a process lock; approval is consumed before the inert effect. A crash after consumption would lose an action, not retry it. No durable or multi-process guarantee is claimed.
3. Contribution ablation: repeat the same actions with PRIME removed. Identical decisions demonstrate that enforcement is independent. A trivial keyword baseline provides an educational contrast only. No benchmark superiority is inferred.

## Production hardening not performed

No authenticated approval UI, durable/revocable approval service, external tool integration, actual agent loop, incident replay, malware sandbox, live pentest, signed attestation, confidential intake, threat-intelligence feed, certification or independent red team is included. Denial of service, model/vendor behavior, downstream adapter bugs, bypass via another execution path, compromised host and stolen credentials are not tested.

## Next evidence needed from a consenting practitioner

- A specifically named problem and owner, plus permission to use synthetic/redacted specimens.
- Preregistered labels and a baseline process. Split examples before tuning.
- Randomized/blinded reviewer crossover with and without PRIME evidence. Record correct/incorrect/abstained outcomes, severity, review time and disagreements.
- Held-out cases covering obfuscation, multilingual benign controls, legitimate quotations, status drift and actor-number binding. Publish counts and intervals, not only favorable examples.
- No action can affect a real system until the organization’s existing authentication and approvals permit it. Evaluate human-facing evidence separately from any authorization layer.
- Acceptance, commercial scope, confidentiality, rights and payment terms must be voluntarily agreed; observing a demo creates no obligation to buy.

## Public design references (consulted 2026-11-01)

These sources motivate the test categories; they have not endorsed this project or independently assessed it.

- OWASP AI Agent Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- OWASP MCP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- OWASP prompt-injection glossary: https://genai.owasp.org/glossary/prompt-injection/
- Microsoft’s harmless-canary approach to testing prompt injection in tool responses: https://learn.microsoft.com/en-us/microsoft-cloud/dev/dev-proxy/concepts/test-ai-agent-prompt-injection-tool-responses

No tests were run against third-party infrastructure.
