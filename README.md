# CapGate

**Live studio:** [https://aariv.me/capgate/](https://aariv.me/capgate/)

CapGate is a firewall for the tool calls an autonomous coding agent makes. Before a `shell_exec`, `fs_read`, `fs_write`, `http_fetch` or `env_read` call runs, CapGate parses it, unwraps every layer of nested shell (`env`, `timeout`, `nohup`, `xargs`, `sh -c`, heredocs piped into `bash`, command substitution, interpreters fed code on stdin), and checks each real command, path, URL and variable against a typed capability policy. It runs offline in the browser or in Node, with no dependencies and no network access.

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
- **Live attack editor:** type any command in the hero and watch the verdict, risk score and firing rules update as you type. Family chips jump to a class of hidden attack.
- **Policy-diff explainer:** for every proof case, the hero shows which baseline allowed the attack and which CapGate rule caught it.
- **Verifiable receipts:** SARIF 2.1.0 for the whole corpus, plus a policy receipt with a canonical SHA-256 digest and integrity signature. Paste a receipt into the verify panel to see VALID or TAMPERED with the changed field.
- **Audit exports:** a formula-safe CSV of the corpus rows (no cell can execute as a spreadsheet formula) and a SHA-256 fingerprinted JSON audit document whose canonical hash re-verifies against any edit.
- **Single-key shortcuts:** `n` next attack, `i` open in inspector, `t` theme, `r` rerun benchmark, `e` export receipt. They never fire with a modifier held or while a control accepts text, and a "Keys" toggle in the header switches them off (WCAG 2.1.4).
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
- Unknown tools and missing tool names are denied by default. Empty required arguments escalate instead of silently allowing. A malformed policy shape (a string where an array belongs, a non-numeric depth) falls back to the safe default instead of disabling a rule.
- Inline interpreter code (`python3 -c`, `node -e`, `ruby -e`, `npx`, arbitrary `npm run <script>`) is blocked or escalated; shell-shaped payloads are scanned recursively for hidden blocked commands. Program text fed to an interpreter through stdin, process substitution, `/dev/fd` or `/dev/stdin` is held for review, and bare wrappers (`env`, bare `sudo`, bare `xargs`) are never silent allows. Interpreter preload and module flags (`node -r/--require/--import/--loader/--eval/-e/--inspect`, `python3 -m`, `php -d` ini injection) count as code channels. `npm test` and `npm start` remain allowed as conventional entrypoints, but `npm test -- --require=...` passthrough flags, lifecycle subcommands (`install`, `ci`, `unlink`, `pack`, `publish`, ...), context redirects (`--prefix`, `--registry`, `--userconfig`, ...) and `npm config set` escalate because they run or redirect package code. Set `allowInlineCode: true` only for trusted one-offs.
- Environment assignments are audited as execution and resolution channels: code-loading variables (`BASH_ENV`, `LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`, `GIT_SSH_COMMAND`, `PROMPT_COMMAND`, `BASH_FUNC_*`, ...) escalate, resolution and egress redirects (`PATH`, `HOME`, `TMPDIR`, `IFS`, proxies, `NPM_CONFIG_*`, `GOPROXY`, TLS trust stores, ...) are held for review, and pager/editor values that name a shell or risky binary are caught while safe values like `PAGER=cat` stay allowed. Assignment-only segments with no command are still audited.
- Git execution-config overrides (`core.pager`, `core.editor`, `core.hooksPath`, `core.sshCommand`, `alias.*`, `-c`, `-c=`, `--config-env=`, `--exec-path`) are blocked. Remote URLs in `clone`/`fetch`/`pull`/`push` arguments are SSRF-checked like any other host. `git push` without `--dry-run` is held for human review, and hook-executing subcommands (`commit`, `merge`, `rebase`, `pull`, `am`, `checkout`, `clone`, `difftool`, `submodule update`, `worktree add`, `bisect run`, mutating `stash` verbs, ...) escalate; read-only forms like `git worktree list` stay allowed.
- Path inspection normalizes repeated percent-encoding, overlong UTF-8, NUL/control bytes, zero-width and format characters, lone surrogates, fullwidth lookalikes, Unicode separators, backslash separators, `....//`, `..;/`, escaped-dot forms, and space or NBSP padded traversal segments before checking traversal, workspace confinement and sensitive files. Env-assignment values that reference paths (`curl -F file=@/etc/passwd`) get the same checks. Windows drive-letter and UNC paths are always outside a POSIX workspace root, and Windows hive files (`config/SAM`, `Repair`) count as sensitive.
- URL hosts are normalized before IP checks: ideographic and fullwidth dot and digit lookalikes, percent-encoded dots and separators, NUL suffixes, IPv6 zone ids, slash-less `http:host` forms, WHATWG tab/LF/CR stripping, and IPv6 forms embedding IPv4 (mapped `::ffff:`, compatible `::`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) are all decoded; wildcard-DNS rebinding services (`*.nip.io`, `*.sslip.io`, `*.xip.io`, `*.1u.ms`, `*.rebind.network`, `localtest.me`, `lvh.me`, `*.traefik.me`, `*.vcap.me`, `*.fip.io`, `*.ip6.name`) and bare `instance-data`/`metadata` are treated as internal. Non-HTTP schemes (`file:`, `gopher:`, `dict:`, `ldap:`, `smb:`, `telnet:`, `tftp:`) and curl connect overrides (`--resolve`, `--connect-to`, `--unix-socket`) are held.
- Secret variable matching covers suffix forms (`*_KEY`, `*_PAT`, `*_PASS`, `*_CREDS`, `JWT`, `*_PASSPHRASE`, `*_SIGNING`) alongside the original name list, so `GITHUB_PAT` or `STRIPE_KEY` cannot slip through while `PATH_INFO` or `DEPLOY_PATTERN` stay allowed.
- Unlisted commands such as `eval` or `find` are not denied outright; they get the `ESCALATE` decision, which holds the call for a human instead of running it.
- Shell option parsing mirrors real getopt forms: glued and clustered `-c` (`bash -c'x'`, `bash -xcq`), `-o`/`+o` set options, `--rcfile`/`--init-file` startup scripts (a code channel), unquoted `$IFS`/`${IFS}` word separators, brace alternates `{a,b}` and ranges inside path checks, and `find -exec`/`-execdir`/`-ok`/`-okdir`/`-delete` payload extraction all reach the command scanner. Redirect targets are stripped from argv before positional parsing (`sh >o -c 'x'` cannot shift the payload past the flag scan) and are still path-checked as write targets. Compound-statement keywords (`if`/`then`/`do`/`!`, `for`/`select`/`case`, `[[ ]]`, function definitions) are treated as scaffolding so the real command inside is what gets judged.
- Parameter expansions that carry path values (`${x:-p}`, `${x/a/p}`, `${x:=p}`, `${x:?m}`, `${x:+a}`, `${x#p}`, `${x%p}`) are extracted and checked like literal paths, and a bare dynamic path arg on a file reader (`cat $f`, `cat ${x}`) is held for review.
- Command-string and program-loader channels on allowlisted tools are held: `git submodule foreach '<shell>'`, the `remote-*` transport helpers, `git bisect run`/`hook run`, `rg --pre`/`--hostname-bin`, `sort --compress-program`, GNU `sed` `e`/`W`/`R` script commands, `pytest -p`/`-c`/`--import-mode`, `node --run`/`--test-reporter`/`--inspect*`/`--openssl-config`, `npm unpublish`, and mutating `npm pkg` verbs. `git fetch`/`fetch-pack`/`ls-remote` and remote-URL mutating verbs (`remote add`/`set-url`/`update`/`prune`/`show`) escalate as egress channels, `git clean` escalates as a destructive sweep, and exec-config keys (`remote.*.proxy|helper|*pack`, `tar.*.command`, `maintenance.*`, `lfs.*`, `interactive.*`, `submodule.*.update`, `merge.*.recursive`, `init.templatedir`, `help.manViewer`, `gpg.ssh.*`, `protocol.*`, `imap.*`, `sendmail.*`) are blocked through `git -c` and `git config` alike. Pager/editor env values that are whole command lines (`PAGER='cat /etc/passwd'`) are held even when they start with a safe binary name, and trap actions are deep-scanned for blocked commands, network egress, and sensitive paths.
- Sensitive-path matching also covers `.env`-suffixed basenames (`prod.env`), `secret`/`secrets` substrings (`secrets.yaml`, `mysecret.txt`, `topsecret.env`), `credentials*` basenames, `*.token`/`*.secrets`/`*.credentials` suffixes, `.pgpass`, `.my.cnf`, `.pg_service.conf`, `.boto`, `.s3cfg`, `.dockercfg`, `.azure/*`, gh CLI `hosts.yml`, `wallet.dat`, `*.pst` archives, and `database.{yml,yaml,json}`; `secretar*` names stay out.
- Wildcard arguments on file-reading commands are matched against sensitive-path samples: `cat .env*`, `cat id_*` and `cat *` deny, while `cat src/*.js` and `ls *` stay allowed.
- Program channels that hide inside a flag are held: `curl -K`/`--config`, `wget --config`/`-i`, `ssh -F`, `awk` `system()`/`@include`/`-f`/`-i`, `xargs -a`, and git's `--upload-pack`/`-u`, `ext::` transports, `archive --remote`, `shell`, `fast-import`, `svn`, `p4`, `imap-send`, and protocol daemons.
- Shell syntax is large, and constructs the parser does not model can hide a command.
- The 36-case corpus is small and was not written by an independent red team.
- Receipts are tamper-evident: any edit to the covered fields breaks the canonical SHA-256 and the derived integrity signature. The key is derived from the receipt payload itself, so this proves integrity against accidental or casual tampering, not authenticity against a party that can rewrite the whole artifact.

## Run it and test it

Node 18 or newer, nothing to install.

```bash
npm test                 # 246 tests: shell parser, capability gate, hardening, receipts, exports, shortcuts, page checks
npm run eval             # benchmark table
npm run eval:check       # fails if CapGate drops below F1 0.98, gains a false positive, or stops beating both baselines
npm run eval:json        # full report with every row
python3 -m http.server   # then open http://localhost:8000/
```

| File | What it holds |
| --- | --- |
| `js/shell-ast.mjs` | Tokenizer and recursive unwrapper for wrappers, `-c` shells, heredocs and substitutions |
| `js/capability-gate.mjs` | Policy, rules, deny-by-default, normalization, baselines, SARIF export |
| `js/hash.mjs`, `js/receipt.mjs` | Dependency-free SHA-256 / HMAC and canonical tamper-evident receipts |
| `js/audit-export.mjs` | Formula-safe CSV export and SHA-256 fingerprinted JSON audit document |
| `js/shortcuts.mjs` | WCAG 2.1.4 single-key shortcut guards and key map |
| `js/corpus.mjs`, `js/benchmark.mjs` | The 36 cases and the scoring |
| `js/viewmodel.mjs` | Pure models for the trace, gauge, verdicts, detector cards and family grid |
| `js/app.js` | Page controller; live attack editor, policy diff, receipt verify; text via `textContent` |
| `video/` | Demo walkthrough steps and narration |

## License

MIT
