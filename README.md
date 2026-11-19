# CapGate

**Live studio:** [https://aariv.me/capgate/](https://aariv.me/capgate/)

CapGate is a firewall for the tool calls an autonomous coding agent makes. Before a `shell_exec`, `fs_read`, `fs_write`, `http_fetch` or `env_read` call runs, CapGate parses it, unwraps every layer of nested shell (`env`, `timeout`, `nohup`, `xargs`, `sh -c`, heredocs piped into `bash`, command substitution), and checks each real command, path, URL and variable against a typed capability policy. It runs offline in the browser or in Node, with no dependencies and no network access.

## The problem

Agent sandboxes often guard tool calls with a keyword filter or by checking the first word of a command. Both are easy to walk around:

- `timeout 10 nohup pkill -9 node` starts with `timeout`, so a first-word check sees a harmless command.
- `cat <<'END' | env sh` with `r'm' -rf /tmp/x` inside hides `rm` behind quotes and a heredoc, so a keyword scan never sees `rm`.
- `http://0xa9fea9fe/latest/meta-data/` is the cloud metadata address written in hex, so a string match on `169.254.169.254` misses it.

## The ten-second proof

The top of the page cycles through the 13 attacks in the corpus that both baselines let through. For each one it shows the raw call, the three verdicts side by side (keyword regex, first-word gate, CapGate), and a decision trace: the raw call, each unwrapped layer with its depth, the rule that fired on the layer that tripped it, and the final decision. One click opens the same call in the inspector, where you can edit it or change the policy and watch the verdict update.

## What is in the studio

- **Decision trace** for any call, built from CapGate's real AST records and findings (`js/viewmodel.mjs`).
- **Risk gauge and side-by-side verdicts** for the inspected call, plus a safe rewrite when one exists.
- **Editable policy:** workspace root, maximum shell nesting depth, outbound network, private and encoded IP blocking, secret environment variables. Every change re-scores the call and the whole benchmark.
- **Benchmark board:** one card per detector with recall, precision, F1 and false positive rate bars and a confusion matrix, and a family by detector grid of correct verdicts.
- **Exports:** SARIF 2.1.0 for the whole corpus, and a policy receipt with an unsigned local SHA-256 digest.
- **Light and dark themes** that follow the system setting, with a toggle.

## Benchmark

The corpus has 36 authored tool calls: 24 unsafe calls in six families (wrapper chains, nested shell flags, heredoc pipes, quoted path traversal, SSRF with encoded IPs, secret exfiltration) and 12 benign traps that mention dangerous words without doing anything dangerous (`echo "Never run rm -rf..."`, a `cat` heredoc containing `sudo`, an allowlisted GitHub API fetch).

| Detector | Precision | Recall | F1 | Accuracy | False positive rate | TP / FP / TN / FN |
| --- | --- | --- | --- | --- | --- | --- |
| Naive keyword regex | 0.8333 | 0.4167 | 0.5556 | 0.5556 | 0.1667 | 10 / 2 / 10 / 14 |
| Flat first-token gate | 1.0000 | 0.0833 | 0.1538 | 0.3889 | 0.0000 | 2 / 0 / 12 / 22 |
| **CapGate AST + policy** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 24 / 0 / 12 / 0 |

Read these numbers for what they are. The corpus was written by the same author as the engine, alongside it, so a perfect score shows that CapGate handles every pattern it was designed for, not that it would catch an unseen attack. The baselines are the two common guards it is meant to replace, and their misses are real: the keyword regex blocks two of the benign traps and lets 14 attacks through, and the first-word gate catches only 2 of 24.

## Limitations

- CapGate is static analysis. It never executes a command, does not sandbox system calls, and does not replace OS or container isolation.
- An allowlisted tool can still run other code, and CapGate trusts the allowlist. Probed on the default policy, all of these are allowed: inline code in `python3 -c "import os; os.remove('x')"` or `node -e`, `npm run clean` (which runs whatever `package.json` says), and `git -c core.pager=sh log`. Tighten the allowlist for real use.
- Unlisted commands such as `eval` or `find` are not denied outright; they get the `ESCALATE` decision, which holds the call for a human instead of running it.
- Shell syntax is large, and constructs the parser does not model can hide a command.
- The 36-case corpus is small and was not written by an independent red team.
- Policy receipts are unsigned SHA-256 hashes for local integrity checks, not signatures.

## Run it and test it

Node 18 or newer, nothing to install.

```bash
npm test                 # 27 tests: shell parser, capability gate, view models, page checks
npm run eval             # benchmark table
npm run eval:check       # fails if CapGate drops below F1 0.98, gains a false positive, or stops beating both baselines
npm run eval:json        # full report with every row
python3 -m http.server   # then open http://localhost:8000/
```

| File | What it holds |
| --- | --- |
| `js/shell-ast.mjs` | Tokenizer and recursive unwrapper for wrappers, `-c` shells, heredocs and substitutions |
| `js/capability-gate.mjs` | Policy, rules, baselines, SARIF export |
| `js/corpus.mjs`, `js/benchmark.mjs` | The 36 cases and the scoring |
| `js/viewmodel.mjs` | Pure models for the trace, gauge, verdicts, detector cards and family grid |
| `js/app.js` | Page controller; all text goes through `textContent` |
| `video/` | Demo walkthrough steps and narration |

## License

MIT
