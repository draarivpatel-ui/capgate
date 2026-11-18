# CapGate

**Deterministic agent tool-call capability firewall, recursive shell-AST unwrapper, and adversarial bypass benchmark workbench.**

CapGate catches nested command wrappers, obfuscated shell flags, executable heredocs, encoded path escapes, and obfuscated SSRF IP literals before an agent tool call reaches execution, while keeping false positives at zero on benign developer workflows.

## Key Capabilities

- **Recursive Shell AST Unwrapper (`js/shell-ast.mjs`):** Tokenizes quotes, escapes, command substitutions `$()` / backticks, pipelines, and heredocs; recursively unwraps wrapper chains (`env`, `timeout`, `nohup`, `ionice`, `xargs`, `sudo`, etc.) and nested `-c` / stdin-reading shells (`sh`, `bash`, `zsh`, `dash`).
- **Typed Capability Firewall (`js/capability-gate.mjs`):** Enforces default-deny command allowlists, workspace path confinement (catching `%2e%2e`, backslash, and quoted `..` traversal), SSRF IP normalization (decimal integers, hex `0xa9fea9fe`, octal `0177.0.0.1`, IPv6 `::ffff:127.0.0.1`), and secret environment/file rules.
- **36-Case Adversarial Bypass Benchmark (`js/corpus.mjs`, `js/benchmark.mjs`):** Side-by-side comparison of Naive Keyword Regex, Flat First-Token Gate, and CapGate Recursive AST across 24 unsafe traces (6 bypass families) and 12 benign developer/false-positive traps.
- **SARIF 2.1.0 & Unsigned SHA-256 Policy Receipt Export:** Exports findings in standard SARIF 2.1.0 format and local SHA-256 policy digests via WebCrypto.
- **Zero-Dependency Static Workbench:** Plain HTML, CSS, and ES modules with `connect-src 'none'` CSP.

## Scope & Guardrails

- Benchmark scores measure detection over the authored 36-case synthetic corpus, not every possible kernel or runtime escape.
- CapGate performs static shell-AST and capability analysis in Node/browser; it does not sandbox live OS syscalls or interpret inline Python/Node code passed to `python3 -c` / `node -e`.
- WebCrypto SHA-256 receipts are unsigned local integrity hashes, not cryptographic signatures.

## Verification & Benchmark

Run with Node 18+:

```sh
npm test
npm run eval:check
npm run eval:json
```

Observed results across the 36-case corpus (24 unsafe across 6 families, 12 benign):
- **Naive Substring Regex:** Precision `0.8333`, Recall `0.4167`, F1 `0.5556`, Accuracy `0.5556`, FPR `0.1667`.
- **Flat First-Token Gate:** Precision `1.0000`, Recall `0.0833`, F1 `0.1538`, Accuracy `0.3889`, FPR `0.0000`.
- **CapGate AST + Policy:** Precision `1.0000`, Recall `1.0000`, F1 `1.0000`, Accuracy `1.0000`, FPR `0.0000`.
