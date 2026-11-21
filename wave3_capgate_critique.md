# CapGate Wave 3 critique

Scope: fresh adversarial probes against `js/shell-ast.mjs`, `js/capability-gate.mjs`, `js/receipt.mjs` and `js/hash.mjs`, plus the 37 cross-model Hydra probes in `wave3-lead-e/capgate-hydra-probes.md` (CG-01 through CG-37). Every probe that failed or surprised was written as a regression test in `tests/wave3-regressions.test.mjs`; fixes stayed in the engine, never in the eval.

## Verified numbers

- Tests: 81/81 pass (`npm test`), up from 56/56 at the Wave 2 baseline. The 25 new tests are all in `tests/wave3-regressions.test.mjs`.
- Benchmark: `npm run eval:check` reports CapGate AST P=1.0000 R=1.0000 F1=1.0000 Acc=1.0000 FPR=0.0000 on the 36-case corpus (24 unsafe, 12 benign), unchanged from baseline.
- UI: real-pointer verification at 1440x900 and 390x844 in headless Chromium, zero console errors, all interactive controls exercised (attack advance, family chip, live editor, benchmark rerun, receipt export/verify round trip, theme toggle). Layout audit found no horizontal overflow, no clipped text, no invisible controls on either viewport.

## Defects closed: 29

### Decoder and host layer

1. **IPv6-embedded IPv4 SSRF.** `isPrivateOrInternalHost` only unfolded one mapped form. `::ffff:0:127.0.0.1`, compressed `::ffff:7f00:1`, IPv4-compatible `::7f00:1`, NAT64 `64:ff9b::/96`, 6to4 `2002:7f00:1::` and hex-tail forms all read as public IPv6 and passed `allowNetwork`. A full hextet parser now expands every embedding layout before the IPv4 check.
2. **Numeric-host fail-open.** Malformed numeric hosts such as `127.0.0.257` fell through to the DNS-name path and were treated as public. Numeric-looking hosts that fail strict parsing now fail closed.
3. **Rebinding suffix gaps.** `xip.io`, `1u.ms`, `rebind.network`-style wildcard DNS services were absent from the internal list; expanded, plus bare single-label hosts treated as internal.
4. **URL authority confusion.** Percent-encoded `/`, `?`, `#` inside the authority (`%2f`, `%3f`, `%23`, double-encoded variants) were not cut, so `http://127.0.0.1%2f.evil.test/` style inputs could hide the real host boundary. Host normalization now decodes, strips control/NUL bytes, folds Unicode dots (U+3002, U+FF0E, U+FF61), and cuts at the first real or decoded separator.
5. **WHATWG tab/LF/CR in scheme (CG-10).** `http\t://127.0.0.1/` matched no URL pattern, so the extractor saw no host while a real fetcher strips the control characters and resolves loopback. `extractUrlsAndHosts` now removes ASCII tab/LF/CR before matching, matching WHATWG URL parsing.

### Path layer

6. **Path normalization gaps.** Zero-width and format characters, lone UTF-16 surrogates, overlong UTF-8, Unicode separator lookalikes and backslash separators could hide `..` or sensitive filenames. `normalizeForInspection` strips them before and after decoding.
7. **Traversal edge cases.** A bare `.` segment was misread as traversal (false positive on `grep -r x .`), while dot-space padding like `../ ` slipped the old `^\.+[\s.]*$` segment test. Traversal now requires at least two dots and catches mixed dot/space padding.
8. **Sensitive path coverage.** `id_dsa`, generic secret filenames (`secret.txt`, `*.pem`-adjacent names), environment dumps (`environment`, `env.list`), `.envrc`, `.aws/config`, `.git/config`, SSH host key and known-hosts files, and shell history files were all readable. `SENSITIVE_PATH_PATTERNS` covers them.
9. **Env-value path references.** `curl -F file=@/etc/passwd` tokenizes as `NAME=value`, so the path scan skipped it entirely. Env-assignment words whose values are path-rooted (`/`, `~`, `$`, `.` or contain `@/`) now go through the same traversal, workspace and sensitive checks.

### Environment channels

10. **Env-only segments dropped.** `PATH=/tmp/evil` or `JAVA_TOOL_OPTIONS=-Xmx1g` with no command produced no AST record, so no env rule ever ran. Pure-assignment segments now surface as `__env_only__` records and are audited.
11. **Execution-channel env vars.** Roughly seventy code-loading variables were unchecked: `BASH_ENV`, `ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_*`, `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONEXECUTABLE`, `PERL5OPT`, `RUBYOPT`, `LUA_PATH`, `PHP_INI_SCAN_DIR`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_EXEC_PATH`, `GIT_CONFIG_GLOBAL/SYSTEM`, `GIT_TEMPLATE_DIR`, `HOSTALIASES`, `RESOLV_HOST_CONF`, `NLSPATH`, `LOCPATH`, `GCONV_PATH`, `TEXTDOMAINDIR`, `INPUTRC`, `LESSOPEN/CLOSE`, `WGETRC`, `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `CLASSPATH`, `GOFLAGS`, `PROMPT_COMMAND`, `BASH_FUNC_*`, `NSS_WRAPPER_*`, `GIT_CONFIG_KEY_*/VALUE_*`, `NODE_REPL_EXTERNAL_MODULE`, `PERL_MM_OPT` and more. All now held under `EXEC_CHANNEL_ENV`.
12. **Resolution and egress redirects.** `PATH`, `HOME`, `TMPDIR`, `IFS`, `CDPATH`, `XDG_*`, proxy variables (`HTTP_PROXY`, `ALL_PROXY`, `no_proxy`, ...), `NPM_CONFIG_*`, `GIT_DIR`, `GIT_WORK_TREE`, `GOPROXY`/`GOSUMDB`/`GOPRIVATE`/`GOTOOLCHAIN`, `LOCALDOMAIN`, `RES_OPTIONS`, prompt variables, TLS trust stores (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_NO_VERIFY`) and similar redirects were silent. Held under `REDIRECT_ENV` for review.
13. **Pager/editor injection.** `PAGER=sh -c ...`, `GIT_PAGER`, `EDITOR`, `VISUAL`, `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `FCEDIT`, `SUDO_EDITOR`, `MANPAGER`, `SYSTEMD_PAGER`, `DELTA_PAGER`, `LESSKEY`, `BROWSER` and friends now escalate when the value names a shell, metacharacters, a path, or a known-risky binary, while safe values like `PAGER=cat` or `EDITOR=vim` stay allowed.

### Shell AST

14. **Wrapper coverage gaps.** `flock`, `ssh-agent`, `firejail`, `systemd-run`, `coproc` and zsh precommand builtins (`command`, `builtin`, `exec`, `hash`, `type`) were not unwrapped, hiding the real command. `bwrap` was wrongly treated as transparent (it sandboxes rather than passes through) and was removed from the simple-wrapper set. Bare wrappers now surface `__bare_<name>__` instead of silently allowing.
15. **Wrapper operand parsing.** Combined short value flags (`timeout -ksIGTERM 5`, `env -S` clusters) shifted the operand boundary so the real command could be skipped. Value flags now parse in attached and clustered forms.
16. **Command-string builtins.** `eval`, `watch` and `script -c` take a shell command as a string argument that was never parsed. Their payloads now go through the same recursive analysis.
17. **Dynamic command names.** `$CMD`, `$(which rm)` and similar expansions in command position were invisible. They now surface for review instead of being dropped.
18. **xargs argv injection.** `xargs -I{} sh -c {}` and `cat <<EOF | xargs sh -c` feed stdin words as argv to a shell or interpreter. xargs targets that lead to shells, interpreters or network tools are now held; `ls | xargs echo` stays allowed.
19. **Redirect and pipeline tokenizing.** `2>&1`, `|&`, `&>`, fd-prefixed redirects (`exec 3>/etc/x`) and pipe feeders were mis-tokenized, hiding redirect targets and pipe-connected commands.
20. **Arithmetic vs command substitution.** `$((1+2))` was mistaken for `$(cmd)` substitution, producing phantom command records. Arithmetic expansion is now distinguished.
21. **Process substitution as program text.** `bash < <(printf '...')`, `python3 <(evil.py)`, `/dev/fd/N` and `/dev/stdin` passed to shells or interpreters deliver executable text through a channel the arg scan could not see. Held under a dedicated finding; data consumers like `cat <(ls)` stay allowed.

### Interpreters and package tools

22. **Interpreter preload and module flags.** `node -r/--require/--import/--loader/--eval/-e/--print/--inspect` (space and `=` forms), `python3 -m` module execution, `php -d auto_prepend_file|extension|include_path` ini injection and equivalent flags on other interpreters were not all treated as code channels.
23. **npm lifecycle, context and passthrough.** `npm unlink`, `npm stop/restart/version/pack/publish/explore/edit/hook`, `npm config set/delete/edit`, context redirects (`--prefix`, `--userconfig`, `--globalconfig`, `--cache`, `--registry`, `--location`), `npx`/`pnpm`/`yarn` first-argument execution and `npm <script> -- <args>` passthrough (where `npm test -- --require=/tmp/evil` preloads code despite `npm test` being exempt) are now covered. Read-only subcommands (`view`, `info`, `search`, `outdated`, `ls-remote`, `ping`, `sbom`, ...) stay allowed.
24. **git remote URL SSRF and hook surface.** `git clone/fetch/pull/push <url>` arguments were never host-checked, `--exec-path` and `--config-env` (space form) redirected execution, `-c key=value` could set `core.pager`/`core.sshCommand`/aliases, and hook-running subcommands (`checkout`, `switch`, `clone`, `restore`, `difftool`, `mergetool`, `instaweb`, `send-email`, `notes`, `replace`, `bundle`, `daemon`, `credential*`, `worktree add/remove`, `submodule update`, `bisect run`, mutating `stash` verbs) escaped review. Remote URLs are now SSRF-checked and all of the above are held; `git worktree list` was fixed to stay allowed.
25. **ssh option injection.** `ssh -o ProxyCommand=...`, `LocalCommand`, `PermitLocalCommand` in both separate-argument and attached (`-oProxyCommand=`) forms were unchecked.
26. **Non-HTTP schemes and curl overrides.** `file:`, `gopher:`, `dict:`, `ldap:`, `smb:`, `telnet:`, `tftp:`, `mqtt:`, `javascript:`, `data:` URLs and curl connect overrides (`--resolve`, `--connect-to`, `--unix-socket`, `--abstract-unix-socket`) plus `@file` uploads (`--data @/etc/passwd`, `-F file=@...`, `--upload-file`) bypassed host and path inspection.
27. **sed script execution.** sed's `e` command, the `s///e` flag, `r`/`w` file commands inside script text and `-f` script files run commands or touch paths invisible to argument-level scans. Sed scripts are now parsed for all of these.
28. **Receipt verification gaps.** `verifyReceipt` ignored `digest.algorithm` (MD5 or any declared scheme still "verified" under SHA-256+HMAC-SHA256), accepted extra digest keys, never checked `tool`/`version` identity, and treated a structurally empty digest as comparable rather than malformed. The algorithm is pinned, the digest shape is enforced, identity fields are covered, and wrong tool/version reports TAMPERED on the covered fields.
29. **canonicalJson undefined parity.** Object properties with `undefined` values serialized as `null`, colliding with real `null` in the canonical form (a receipt could not distinguish them). `canonicalJson` now omits undefined object properties exactly like `JSON.stringify`, while array behavior is unchanged.

## What survived (documented, not fixed)

- **Script-file contents.** `bash evil.sh`, `python3 evil.py`, `bash /dev/stdin < payload` deliver program text through a file the static gate cannot read. The command is still inspected; the file body is out of scope for a pure function. Disclosed in the README.
- **TOCTOU / symlink races (CG-14, CG-26).** The gate inspects the literal path string; it cannot bind the file object inspected to the file object later read, and cannot resolve symlinks without filesystem access. This is inherent to static analysis and is why the README says CapGate does not replace OS isolation.
- **DNS rebinding between check and resolution.** A hostname that resolves publicly at inspection time can resolve privately at fetch time. The gate checks the name, not the resolution; `blockPrivateIps` covers literal IPs only.
- **SARIF freshness (CG-33).** Receipts carry no timestamp or nonce by design; a stale receipt replays as VALID because it is still a valid receipt for its payload. Consumers needing freshness must bind receipts to their own clock.
- **canonicalJson duplicate keys (CG-35).** `JSON.parse` collapses duplicates before canonicalization, so two source documents that differ only in duplicate keys produce identical canonical forms. Unfixable at this layer; noted for consumers parsing untrusted JSON.
- **informationUri (CG-37).** The SARIF export carries a hard-coded repository URL; whether a consumer validates it is the consumer's responsibility.
- **Fail-closed false positives kept deliberately.** `http://evil.test\@127.0.0.1/` (CG-09), fragment-embedded hosts (CG-11) and Unicode-homoglyph filenames (CG-13) deny even though careful parsers would resolve them safely. For a capability firewall, over-holding ambiguous inputs is the correct side to err on.
- **Env values that look like paths but are data.** `FOO=production`, `GIT_COMMITTER_NAME=x` style assignments stay allowed; only path-rooted values and known-dangerous names escalate.

## Self-score

Wave 2 scored 9.3. Wave 3 closes 29 additional defect classes found by fresh probing plus all 37 Hydra cross-model probes (34 verified closed or already covered, 3 documented as inherent/consumer-side). The engine now covers IPv6 embedding, WHATWG control-character stripping, env-channel execution and resolution redirects, pager/editor injection, a much wider wrapper and builtin surface, interpreter preload/module channels, npm context and passthrough, git remote/config/hook surface, ssh options, non-HTTP schemes, sed script execution, and a hardened receipt verifier. Benchmarks and the full suite stay perfect.

Remaining deductions: script-file bodies, filesystem TOCTOU and DNS-rebinding races are inherent to a static pre-execution gate and can only be mitigated, not eliminated; a few conservative false positives remain by design; and the corpus is still author-written, so real-world coverage beyond the probe set is unproven. That is a 9.6, up from 9.3: materially stronger verification surface and receipt integrity, with honest residual limits.
