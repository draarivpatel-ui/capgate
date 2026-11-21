/**
 * CapGate typed agent capability firewall, SSRF/IP normalizer, path traversal guard,
 * safe-rewrite synthesizer, SARIF 2.1.0 exporter, and comparator baselines.
 * Pure ES module (zero external dependencies).
 */

import { analyzeShellAst, SHELL_BINARIES, STDIN_INTERPRETERS } from './shell-ast.mjs';

const STDIN_INTERPRETERS_SET = STDIN_INTERPRETERS;

export const DEFAULT_POLICY = Object.freeze({
  workspaceRoot: '/workspace/app',
  allowedCommands: ['ls', 'cat', 'grep', 'rg', 'node', 'npm', 'python3', 'pytest', 'git', 'echo', 'head', 'tail', 'wc', 'sed', 'sort'],
  blockedCommands: ['rm', 'sudo', 'su', 'mkfs', 'dd', 'shutdown', 'reboot', 'kill', 'pkill', 'chmod', 'chown', 'nc', 'ncat', 'socat'],
  networkCommands: ['curl', 'wget', 'fetch', 'ssh', 'scp', 'rsync', 'dig', 'nslookup'],
  allowNetwork: false,
  allowedDomains: ['registry.npmjs.org', 'api.github.com'],
  blockPrivateIps: true,
  allowEnvSecrets: false,
  allowInlineCode: false,
  maxShellNestingDepth: 2,
});

const SENSITIVE_PATH_PATTERNS = [
  /(^|\/)\.env(\.|$)/i,
  /(^|\/)\.envrc$/i,
  /(^|\/)\.ssh(\/|$)/i,
  /(^|\/)\.aws(\/|$)/i,
  /(^|\/)\.gnupg(\/|$)/i,
  /(^|\/)\.docker\/config\.json/i,
  /(^|\/)\.kube\/config/i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.pypirc$/i,
  /(^|\/)\.netrc$/i,
  /id_rsa|id_ed25519|id_ecdsa|id_dsa/i,
  /(^|\/)[^/]*\.(?:key|p12|pfx|keystore|jks|kdbx|asc|gpg|pgp|ppk)$/i,
  /^\/etc\/(passwd|shadow|gshadow|sudoers|sudoers\.d)/i,
  /^\/etc\/(pki|ssl\/private|ssh\/ssh_host)/i,
  /credentials\.json/i,
  /^\/proc\/self\/environ/i,
  /^\/var\/run\/secrets(\/|$)/i,
  /(^|\/)secrets?\//i,
  // Filenames that name a secret or env dump without a standard extension:
  // `secret.txt`, `my-secret-file.txt`, `secrets.yaml`, `mysecret.txt`,
  // `topsecret.env`. `secretar*` (`secretary.txt`, `secretariat.md`) stays out.
  /(^|\/)[^/]*secret(?!ar)[^/]*$/i,
  // Basenames ending in `.env` (`prod.env`, `app.env`) or starting a `.env.*`
  // chain are env-file secrets; the `.env`-dotfile rules above only cover
  // dot-prefixed names.
  /(^|\/)[^/]*\.env(?:\.[\w.-]*)?$/i,
  // Credential/token/secrets suffixes and the usual cloud/DB client stores:
  // `x.credentials`, `x.token`, `.pgpass`, `.my.cnf`, `.boto`, `.s3cfg`,
  // `.dockercfg`, `.azure/*`, gh CLI hosts.yml, wallet.dat, mail archives.
  /(^|\/)[^/]*credentials?[^/]*$/i,
  /(^|\/)[^/]*\.(?:token|secrets?)$/i,
  /(^|\/)\.(?:pgpass|my\.cnf|pg_service\.conf|s3cfg|boto|dockercfg)$/i,
  /(^|\/)\.azure\//i,
  /(^|\/)(?:\.config\/)?gh\/hosts\.yml$/i,
  /(^|\/)[^/]*\.pst$/i,
  /(^|\/)wallet\.dat$/i,
  /(^|\/)database\.(?:yml|yaml|json)$/i,
  // `env`-family filenames with a suffix (`env.list`, `environment`,
  // `.envrc`-style). A bare `env` word is the wrapper command itself and must
  // not match, so the suffix is required.
  /(^|\/)\.?env(?:[._-][\w.-]*|ironment)$/i,
  /(^|\/)\.(?:bash|zsh|python|node_repl|mysql|psql|sqlite|irb|fsi|ghci|julia|r)_(?:history|history\.)/i,
  /(^|\/)authorized_keys$/i,
  /(^|\/)known_hosts$/i,
  /(^|\/)\.git-credentials/i,
  /(^|\/)\.git\/hooks\//i,
  /(^|\/)\.git\/config(\.|$)/i,
  /(^|\/)\.gitattributes$/i,
  /windows\/system32\/config\/(sam|system|software|security)/i,
  /windows\/repair\//i,
  /windows\/system32\/drivers\/etc\//i,
  /(^|\/)ntds\.dit$/i,
  // Shell startup files execute on every login or interactive shell: writing
  // one is persistent code execution, reading one leaks configuration.
  /(^|\/)\.(zshenv|zprofile|zshrc|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|profile|gitconfig|condarc|wgetrc|curlrc|inputrc|editrc|tmux\.conf)$/i,
];

const SECRET_ENV_NAMES = /(API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|DATABASE_URL|DSN|CREDENTIAL|AUTH|(?:^|_)(?:KEY|PAT|PASS|CREDS|JWT|PASSPHRASE|SIGNING)(?:$|_))/i;

/**
 * Shell builtins that only inspect or mutate shell state. They are not in
 * allowedCommands by default but carry no execution surface of their own, so
 * they must not be escalated as "unlisted command".
 */
const SAFE_BUILTINS = new Set([
  'echo', 'printf', 'true', 'false', 'test', '[', 'pwd', 'cd', 'umask',
  'shift', 'trap', 'ulimit', 'wait', 'jobs', 'fg', 'bg', 'disown',
  'export', 'readonly', 'declare', 'typeset', 'local', 'let', 'getopts',
  'type', 'history', 'dirs', 'pushd', 'popd', 'exit', 'return', 'break',
  'continue', 'times', 'caller', 'suspend', 'logout', 'set', 'unset',
  'read', 'mapfile', 'readarray', 'shopt', 'compopt', 'unalias', 'disable',
  'help', 'hash', 'enable', 'alias', 'fc', 'bind', 'complete', 'compgen',
  'command', 'builtin',
]);

/**
 * Shell builtins whose arguments can name or embed executable code. Each is
 * also in SAFE_BUILTINS for its benign forms; this set selects the args that
 * need a second look.
 */
const BUILTIN_EXEC_ARG_CHECKS = new Set([
  'trap', 'bind', 'complete', 'compgen', 'mapfile', 'readarray',
  'enable', 'hash', 'alias', 'fc',
]);

/**
 * Inspect the dangerous argument shapes of shell builtins. Returns findings
 * via addFinding; benign forms (`trap -p`, `bind -p`, `complete -p`,
 * `enable -n`, `hash -r`, `fc -l`, `alias ll="ls -la"`) produce nothing.
 */
function checkBuiltinExecArgs(rec, addFinding, { blockedSet, allowedSet, netCmdSet, policy }) {
  const cmd = rec.command;
  const args = rec.args || [];
  const trail = rec.trail;

  const argRunsBlocked = (text) => {
    if (!text) return null;
    for (const sub of analyzeShellAst(String(text), 3).records) {
      if (sub.command === '__max_depth_exceeded__' || sub.command === '__pipe_stdin_shell__') continue;
      const hit = (sub.trail || []).find((c) => blockedSet.has(c)) ||
        (blockedSet.has(sub.command) ? sub.command : null);
      if (hit) return hit;
    }
    return null;
  };

  /**
   * Full policy scan of a command string (trap action, remote helper
   * payload): blocked commands, network egress, and sensitive or
   * outside-workspace paths inside it are all deferred execution the
   * argument scans never see. Returns the worst reason found, or a medium
   * marker when the payload is a command at all.
   */
  const deepScanPayload = (text) => {
    if (!text) return null;
    const subs = analyzeShellAst(String(text), 3).records;
    let worst = null;
    for (const r of subs) {
      if (r.command === '__max_depth_exceeded__' || r.command === '__pipe_stdin_shell__') {
        return { sev: 'high', why: 'nested shell channel' };
      }
      const b = (r.trail || []).find((c) => blockedSet.has(c)) ||
        (blockedSet.has(r.command) ? r.command : null);
      if (b) return { sev: 'critical', why: `blocked command "${b}"` };
      if (netCmdSet && netCmdSet.has(r.command)) return { sev: 'high', why: `network command "${r.command}"` };
      for (const w of [...(r.args || []), ...(r.rawWords || []), ...(r.redirectTargets || [])]) {
        for (const c of pathLikeCandidates(w)) {
          if (isSensitivePath(c)) return { sev: 'high', why: `sensitive path "${c.slice(0, 40)}"` };
          if ((hasTraversalSegment(c) || !isWithinWorkspace(c, policy.workspaceRoot)) &&
              !c.startsWith('-') && !c.startsWith('/dev/null')) {
            return { sev: 'high', why: `outside-workspace path "${c.slice(0, 40)}"` };
          }
        }
      }
      if (!worst) worst = { sev: 'medium', why: `deferred command "${r.command}"` };
    }
    return worst;
  };

  if (cmd === 'trap') {
    // `trap ACTION [CONDITION...]`; `trap -p`/`trap -l` are queries.
    if (args.some((a) => a === '-p' || a === '-l' || a === '--print' || a === '--list')) return;
    const action = args.find((a) => !a.startsWith('-'));
    if (!action) return;
    // `trap EXIT`/`trap 0` with no action resets the handler; a lone signal
    // name is not code.
    if (/^(?:[A-Za-z][A-Za-z0-9]*|\d+)$/.test(action) && args.filter((a) => !a.startsWith('-')).length === 1) return;
    const hit = argRunsBlocked(action);
    if (hit) {
      addFinding('CAP-CMD-09', 'critical', `trap action runs blocked command "${hit}"`,
        `trap action "${String(action).slice(0, 60)}" at [${trail.join(' -> ')}] executes on a shell signal.`,
        trail, 'Remove command-bearing trap actions; traps should only record state.');
      return;
    }
    const deep = deepScanPayload(action);
    if (deep) {
      addFinding('CAP-CMD-09', deep.sev, `trap action embeds executable code in ${rec.command}`,
        `trap action "${String(action).slice(0, 60)}" at [${trail.join(' -> ')}] runs ${deep.why} on a shell signal.`,
        trail, 'Remove command-bearing trap actions; traps should only record state.');
      return;
    }
    if (SHELL_META_RE.test(action)) {
      addFinding('CAP-CMD-09', 'high', `trap action embeds executable code in ${rec.command}`,
        `trap action "${String(action).slice(0, 60)}" at [${trail.join(' -> ')}] runs on a shell signal.`,
        trail, 'Remove command-bearing trap actions; traps should only record state.');
    }
    return;
  }

  if (cmd === 'bind') {
    // `bind [-x] [keyseq:command]`; `bind -p`/`-P`/`-l` list. Any key:command
    // pair or -x flag wires a keystroke to shell execution.
    if (args.some((a) => a === '-p' || a === '-P' || a === '-l')) return;
    const pairs = args.filter((a) => /^[^\s:]*:[^\s]/.test(a) && !a.startsWith('-'));
    if (args.includes('-x') || pairs.length > 0) {
      addFinding('CAP-CMD-09', 'medium', `bind maps a key to executable code in ${rec.command}`,
        `bind arguments at [${trail.join(' -> ')}] attach commands to keystrokes.`,
        trail, 'Do not bind shell commands to keys from tool calls.');
    }
    return;
  }

  if (cmd === 'complete' || cmd === 'compgen') {
    // `-C command` / `--command command` names a program run for completion.
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-C' || a === '--command' || a.startsWith('--command=')) {
        const val = a.includes('=') ? a.slice(a.indexOf('=') + 1) : (args[i + 1] || '');
        addFinding('CAP-CMD-09', 'high', `${cmd} -C names an executable completion command`,
          `${cmd} -C "${String(val).slice(0, 60)}" at [${trail.join(' -> ')}] runs a program per completion.`,
          trail, 'Do not wire completion to external commands from tool calls.');
        return;
      }
    }
    return;
  }

  if (cmd === 'mapfile' || cmd === 'readarray') {
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-C' || a === '--callback' || a.startsWith('--callback=')) {
        const val = a.includes('=') ? a.slice(a.indexOf('=') + 1) : (args[i + 1] || '');
        addFinding('CAP-CMD-09', 'high', `${cmd} -C names a per-line callback command`,
          `${cmd} -C "${String(val).slice(0, 60)}" at [${trail.join(' -> ')}] runs a command for each input line.`,
          trail, 'Do not attach command callbacks to array readers.');
        return;
      }
    }
    return;
  }

  if (cmd === 'enable') {
    // `enable -f file name` dlopens a shared object: arbitrary native code.
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-f' || a === '--load' || a.startsWith('--load=')) {
        const val = a.includes('=') ? a.slice(a.indexOf('=') + 1) : (args[i + 1] || '');
        addFinding('CAP-CMD-09', 'critical', `enable -f loads shared object "${String(val).slice(0, 60)}"`,
          `enable -f at [${trail.join(' -> ')}] dlopens native code into the shell.`,
          trail, 'Never load shared objects into the shell from tool calls.');
        return;
      }
    }
    return;
  }

  if (cmd === 'hash') {
    // `hash -p /path name` repoints a command name at an arbitrary binary.
    const pIdx = args.findIndex((a) => a === '-p' || a === '-d' || a === '--delete');
    if (pIdx >= 0 && args[pIdx] === '-p') {
      const target = args[pIdx + 1] || '';
      addFinding('CAP-CMD-09', 'high', `hash -p repoints command resolution to "${target}"`,
        `hash -p at [${trail.join(' -> ')}] substitutes an arbitrary binary for a command name.`,
        trail, 'Do not remap command names with hash -p.');
    }
    return;
  }

  if (cmd === 'alias') {
    // `alias name='cmd'` redefines a command; flag when the value runs a
    // blocked command or embeds shell metacharacters.
    for (const a of args) {
      const eq = a.indexOf('=');
      if (eq < 0) continue;
      const value = a.slice(eq + 1);
      const hit = argRunsBlocked(value);
      if (hit || SHELL_META_RE.test(value)) {
        addFinding('CAP-CMD-09', 'high', `alias "${a.slice(0, eq)}" redefines a command with executable code`,
          `alias value "${value.slice(0, 60)}" at [${trail.join(' -> ')}] can shadow an allowlisted command.`,
          trail, 'Do not define aliases that wrap blocked commands or shell metacharacters.');
        return;
      }
    }
    return;
  }

  if (cmd === 'fc') {
    // Bare `fc`, `fc -s`, `fc -e`, `fc -r` re-execute or edit-and-run history;
    // only `fc -l`/`--list` forms are read-only.
    const first = args[0] || '';
    const listOnly = /^-l/.test(first) || args.includes('--list');
    if (!listOnly) {
      addFinding('CAP-CMD-09', 'high', `fc re-executes shell history at [${trail.join(' -> ')}]`,
        `fc ${args.join(' ')} re-runs a prior command line outside static inspection.`,
        trail, 'Use explicit commands; do not re-run history from tool calls.');
    }
    return;
  }
}

/**
 * Inspect `sed` script arguments for hidden execution. sed's `e` command and
 * the `s///e` substitution flag run their text through the shell, `r`/`w`
 * commands read or write arbitrary files, and `-f`/`--file` loads script
 * text the firewall never sees. Script text arrives as ordinary word
 * arguments, so the path and command scans cannot see inside it.
 */
function checkSedArgs(rec, addFinding) {
  const args = rec.args || [];
  const trail = rec.trail;
  const scriptTexts = [];
  let scriptFile = null;

  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === '-f' || a === '--file') { scriptFile = args[i + 1] || ''; continue; }
    if (a.startsWith('--file=')) { scriptFile = a.slice('--file='.length); continue; }
    if (a === '-e' || a === '-l' || a === '--expression') {
      if (args[i + 1] !== undefined) scriptTexts.push(String(args[i + 1]));
      i += 1;
      continue;
    }
    if (a.startsWith('-e') && a.length > 2) { scriptTexts.push(a.slice(2)); continue; }
    if (a.startsWith('--expression=')) { scriptTexts.push(a.slice('--expression='.length)); continue; }
    // First non-flag argument is the inline script (sed SCRIPT [FILE...]).
    if (!a.startsWith('-')) scriptTexts.push(a);
  }

  if (scriptFile) {
    addFinding('CAP-CMD-11', 'medium', `sed -f loads unverifiable script file "${String(scriptFile).slice(0, 60)}"`,
      `sed reads its program from a file at [${trail.join(' -> ')}]; script contents bypass argument inspection.`,
      trail, 'Inline reviewed sed expressions, or move the script into an audited file.');
  }

  for (const script of scriptTexts) {
    // `e` command: `[addr]e [command]` executes text through the shell. `$e`
    // (last-line address) and `!e` (negated address) run it too.
    if (/(?:^|[;{},\n$!]|\d)\s*e(?:\s|$)/.test(script)) {
      addFinding('CAP-CMD-11', 'high', `sed script contains "e" command executing shell text`,
        `sed script "${script.slice(0, 60)}" at [${trail.join(' -> ')}] runs commands through the shell.`,
        trail, 'Remove e commands from sed scripts; they are arbitrary command execution.');
      return;
    }
    // `s<delim>...<delim>...<delim>flags` with the e flag executes the
    // replacement. Backreference keeps the delimiter honest.
    const sub = /s(.)[^\n]*?\1[^\n]*?\1([a-zA-Z0-9]*)/g;
    let m;
    while ((m = sub.exec(script))) {
      if (/e/i.test(m[2])) {
        addFinding('CAP-CMD-11', 'high', `sed s///e flag executes replacement text as shell`,
          `sed script "${script.slice(0, 60)}" at [${trail.join(' -> ')}] evaluates replacement output.`,
          trail, 'Remove the e flag from sed substitutions.');
        return;
      }
    }
    // `r file` / `w file` (and GNU `R`/`W`) commands read or write paths
    // invisible to the argument-level path scan inside the script string.
    const rw = /(?:^|[;{},\n]|\d|\s)[rRwW]\s+(\/|~|\$)/.exec(script);
    if (rw) {
      addFinding('CAP-PATH-02', 'high', `sed script ${/w/i.test(rw[0].trim()) ? 'writes' : 'reads'} an outside path`,
        `sed script "${script.slice(0, 60)}" at [${trail.join(' -> ')}] references a path outside the workspace.`,
        trail, 'Keep sed r/w targets inside the workspace.');
      return;
    }
  }
}

/**
 * Environment variables that cause code to load or execute: dynamic-loader
 * hooks, interpreter startup/module paths, shell startup files, command
 * resolvers, and config-file redirects. Assigning one is an execution channel,
 * not a benign knob.
 */
const EXEC_CHANNEL_ENV = /^(?:BASH_ENV|ENV|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|LD_PROFILE|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|DYLD_FALLBACK_LIBRARY_PATH|NODE_OPTIONS|NODE_PATH|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|LUA_PATH|LUA_CPATH|PHP_INI_SCAN_DIR|GIT_SSH_COMMAND|GIT_SSH|GIT_ASKPASS|GIT_ASK_YESNO|SSH_ASKPASS|SUDO_ASKPASS|GIT_EXEC_PATH|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_CONFIG_PARAMETERS|GIT_EXTERNAL_DIFF|GIT_TEMPLATE_DIR|GIT_PROXY_COMMAND|HOSTALIASES|RESOLV_HOST_CONF|NLSPATH|LOCPATH|GCONV_PATH|TEXTDOMAINDIR|INPUTRC|LESSOPEN|LESSCLOSE|WGETRC|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|CLASSPATH|GOFLAGS|PROMPT_COMMAND|NPM_CONFIG_SCRIPT_SHELL|npm_config_script_shell|BASH_FUNC_[A-Za-z0-9_]+|NSS_WRAPPER_[A-Za-z0-9_]+|GIT_CONFIG_(?:COUNT|KEY_[0-9]+|VALUE_[0-9]+)|PYTHONEXECUTABLE|PYTHONNOUSERSITE|PYTHONSAFEPATH|NODE_REPL_EXTERNAL_MODULE|PERL_MM_OPT|ZDOTDIR|FPATH|PYTEST_PLUGINS|PYTEST_ADDOPTS|OPENSSL_CONF)$/i;

/**
 * Environment variables that redirect resolution, config, credentials, or
 * network egress without directly executing code. Held for review rather than
 * denied outright because some (proxies, HOME) appear in legitimate setups.
 */
const REDIRECT_ENV = /^(?:PATH|HOME|TMPDIR|TMP|TEMP|XDG_CONFIG_HOME|XDG_DATA_HOME|XDG_CONFIG_DIRS|XDG_DATA_DIRS|XDG_CACHE_HOME|XDG_STATE_HOME|XDG_RUNTIME_DIR|IFS|CDPATH|GLOBIGNORE|FIGNORE|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|GIT_SSL_NO_VERIFY|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|FTP_PROXY|SOCKS_PROXY|http_proxy|https_proxy|all_proxy|ftp_proxy|socks_proxy|no_proxy|NO_PROXY|NPM_CONFIG_[A-Za-z0-9_]+|npm_config_[a-z0-9_]+|GIT_DIR|GIT_WORK_TREE|GIT_NAMESPACE|GIT_TRACE|GIT_TRACE_PACKET|GIT_TRACE_SETUP|GIT_TRACE_PERFORMANCE|GIT_CEILING_DIRECTORIES|GOPROXY|GOSUMDB|GONOSUMDB|GONOSUMCHECK|GOINSECURE|GOPRIVATE|GONOPROXY|GOTOOLCHAIN|GODEBUG|GOENV|GOEXPERIMENT|GOFIPS140|GOVCS|LOCALDOMAIN|RES_OPTIONS|PS0|PS1|PS2|PS4|PYTHONBREAKPOINT|NODE_REPL_HISTORY|NODE_COMPILE_CACHE|SHELL|DBUS_SESSION_BUS_ADDRESS|LESS|GIT_DIFF_OPTS|GIT_SSH_VARIANT|GIT_CONFIG_NOSYSTEM)$/i;

/** Pager/editor family members get a value check: safe pager names pass. */
const PAGER_SAFE_VALUES = /^(?:cat|less|more|most|pg|lv)$/i;
// Plain binary names pass the pager check only when they are not themselves
// destructive or network-capable: `PAGER=rm git log` would pipe the log into
// rm, and `PAGER=curl` would exfiltrate it. PATH resolution is gated
// separately, so an unknown benign name still passes.
const PAGER_DANGEROUS_BIN = /^(?:rm|mv|cp|dd|dcfldd|chmod|chown|chgrp|chattr|setfacl|kill|pkill|killall|curl|wget|nc|ncat|netcat|socat|ftp|tftp|telnet|ssh|scp|sftp|rsync|rclone|aria2c|git|npm|npx|yarn|pnpm|node|deno|bun|perl|ruby|php|lua|python\d*(?:\.\d+)?|sh|bash|zsh|dash|ash|ksh|mksh|fish|csh|tcsh|eval|exec|env|xargs|find|tee|install|make|cmake|ninja|go|rustc|cargo|gcc|g\+\+|clang|openssl|gpg|ssh-keygen|ssh-add|nmap|masscan|hping3|dig|host|nslookup|whois|awk|gawk|mawk|ed|tmux|screen|at|batch|crontab|systemctl|service|launchctl|osascript|docker|podman|nerdctl|kubectl|helm|terraform|tofu|ansible|vagrant|mysql|psql|sqlite3|redis-cli|mongosh|consul|nomad|vault|packer|aws|gcloud|az|doctl|flyctl|wrangler|firebase|s3cmd|mc|jq|yq|vi|vim|nvim|nano|emacs|http|https)$/i;
// Editor-family variables legitimately name editors, not pagers.
const PAGER_EDITOR_NAMES = /^(?:SUDO_EDITOR|GIT_EDITOR|GIT_SEQUENCE_EDITOR|EDITOR|VISUAL|FCEDIT)$/i;
const EDITOR_SAFE_VALUES = /^(?:vi|vim|nvim|nano|emacs|emacsclient|gedit|kate|code|codium|micro|hx|helix|joe|pico|mcedit|ne|se|te|ee|leafpad|mousepad|xed|pluma|geany|notepad\+\+|subl|sublime_text|atom|brackets|nova)$/i;
const PAGER_ENV_NAMES = /^(?:PAGER|GIT_PAGER|MANPAGER|SYSTEMD_PAGER|DELTA_PAGER|LESSKEY|FCEDIT|SUDO_EDITOR|GIT_EDITOR|GIT_SEQUENCE_EDITOR|EDITOR|VISUAL|BROWSER|GIT_MERGE_AUTOEDIT|GIT_PAGER)$/i;

/**
 * Recover the ASCII character hidden in an overlong UTF-8 byte sequence.
 * Overlong encodings (e.g. `%c0%af` for `/`, `%c0%ae` for `.`) decode to Latin-1
 * characters U+0080-U+00FF. When we see such a run, we re-pack those chars as
 * raw bytes and check whether they form an overlong encoding of an ASCII byte;
 * if so we collapse them to that byte so downstream checks see the real `..` or `/`.
 */
function collapseOverlongAscii(s) {
  return s.replace(/[\u0080-ÿ]+/g, (run) => {
    const bytes = [...run].map((c) => c.charCodeAt(0));
    let out = '';
    // Try to decode runs of high bytes as UTF-8, then as Latin-1 passthrough.
    for (let i = 0; i < bytes.length; ) {
      const b = bytes[i];
      // 2-byte sequence C0-DF 80-BF (covers overlong C0/C1 leads)
      if (b >= 0xc0 && b <= 0xdf && i + 1 < bytes.length) {
        const b2 = bytes[i + 1];
        if (b2 >= 0x80 && b2 <= 0xbf) {
          const cp = ((b & 0x1f) << 6) | (b2 & 0x3f);
          out += String.fromCharCode(cp);
          i += 2;
          continue;
        }
      }
      // 3-byte E0-EF (overlong 3-byte for ASCII is E0 80-9F 80-BF)
      if (b >= 0xe0 && b <= 0xef && i + 2 < bytes.length) {
        const b2 = bytes[i + 1];
        const b3 = bytes[i + 2];
        if (b2 >= 0x80 && b2 <= 0xbf && b3 >= 0x80 && b3 <= 0xbf) {
          const cp = ((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
          out += String.fromCharCode(cp);
          i += 3;
          continue;
        }
      }
      out += String.fromCharCode(b);
      i += 1;
    }
    return out;
  });
}

/**
 * Fully normalize a raw path or URL token for security inspection.
 * Defeats percent-encoding (repeatedly), overlong / non-UTF8 byte sequences,
 * NUL and control-byte smuggling, fullwidth and Unicode slash/dot variants,
 * backslash separators, and the classic `....//` and `..;/` collapse tricks.
 * Returns a lowercase string that uses `/` as the only separator.
 */
export function normalizeForInspection(raw) {
  let s = String(raw ?? '');
  // Strip NUL, C0/C1 control bytes, zero-width format characters, and lone
  // UTF-16 surrogates outright: none have a legitimate role in a path token
  // and each is a classic smuggling trick (`..%e2%80%8b/etc` decodes to
  // `..<ZWSP>/etc`, which filesystems do not treat as `..`).
  s = s.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\ud800-\udfff]/g, '');
  // Map fullwidth and Unicode lookalike separators/dots to ASCII before decoding
  // so `%ef%bc%8f` (fullwidth solidus) and friends cannot smuggle a separator.
  s = s
    .replace(/[／∕⁄]/g, '/')
    .replace(/[．․‥…﹒｡。]/g, '.')
    .replace(/[＼∖]/g, '\\');
  // Percent-decode repeatedly, with a lenient byte-wise fallback so an invalid
  // UTF-8 sequence (e.g. `%c0%af`, the overlong `/`) is decoded rather than
  // silently dropped. decodeURIComponent throws on those; we repair by
  // decoding each %XX byte independently as Latin-1 when the strict pass fails.
  for (let i = 0; i < 4; i++) {
    let next = s;
    try {
      next = decodeURIComponent(s);
    } catch {
      next = s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    }
    if (next === s) break;
    s = next;
  }
  // Collapse overlong UTF-8 encodings (C0/C1 leads, E0 overlong) back to the
  // ASCII byte they were meant to represent, so `..%c0%af` becomes `../`.
  s = collapseOverlongAscii(s);
  // Re-apply Unicode lookalike mapping after decoding, because `%ef%bc%8f`
  // (fullwidth solidus U+FF0F) only appears once percent-decoded.
  s = s
    .replace(/[／∕⁄]/g, '/')
    .replace(/[．․‥…﹒｡。]/g, '.')
    .replace(/[＼∖]/g, '\\');
  // Strip any control/NUL bytes that arrived via percent-decoding (e.g. `%00`),
  // plus zero-width and lone-surrogate decodes for the same reason as above.
  s = s.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\ud800-\udfff]/g, '');
  // Backslashes are path separators on Windows and are used to break naive
  // forward-slash checks; fold them to forward slashes.
  // A backslash escaping a dot (`.\\.`) is a shell quoting trick that still
  // resolves to `..` for any filesystem. Fold it before separator handling.
  // Only collapse the backslash when it sits between two literal dots, so a
  // plain `..\\` separator is left intact for the next rule.
  s = s.replace(/\.\\\./g, '..');
  s = s.replace(/\\/g, '/');
  // Collapse `....//` -> `../` and `..;/` -> `../` style tricks by collapsing
  // runs of dots around separators into a canonical `..` segment marker.
  s = s.replace(/\.{2,}\//g, '../');
  s = s.replace(/\.{1,2}\;/g, '../');
  return s;
}

/** True if the path contains any `..` parent segment after full normalization. */
export function hasTraversalSegment(rawPath) {
  const clean = normalizeForInspection(rawPath);
  if (!clean) return false;
  // A literal `..` segment anywhere, including trailing (`a/..`) and leading (`../a`).
  // Padded forms (`.. `, `..`, `.. .`) also count: filesystems strip trailing
  // spaces and dots from path segments, so they resolve as parent traversal.
  // Two dots are required: `.` and `...` are ordinary names, not traversal.
  return clean.split('/').some((p) => /^\.{2,}[\s.]*$/.test(p));
}

/**
 * Percent-encode-decode a path so that encoded secrets (`%2e%2e`, `%2f`) are
 * visible to the sensitive-path matcher. Returns the normalized form.
 */
function fullyDecodeForSensitive(rawPath) {
  return normalizeForInspection(rawPath);
}

export function isSensitivePath(rawPath) {
  const clean = fullyDecodeForSensitive(rawPath).trim();
  if (!clean) return false;
  return SENSITIVE_PATH_PATTERNS.some((re) => re.test(clean));
}

export function isWithinWorkspace(rawPath, workspaceRoot) {
  const clean = normalizeForInspection(rawPath).trim();
  if (!clean) return true;
  if (hasTraversalSegment(clean)) return false;
  // `~` and `~user` expand to a home directory outside the workspace; treat
  // them as escapes rather than relative paths.
  if (clean.startsWith('~')) return false;
  // A Windows drive letter or UNC device path is always absolute and never
  // inside a POSIX workspace root (`C:\Windows\...` folds to `c:/windows/...`,
  // which a naive relative-path check would wrongly treat as relative).
  if (/^[a-z]:\//.test(clean) || clean.startsWith('//')) return false;
  if (!clean.startsWith('/')) return true;
  const root = String(workspaceRoot || '').replace(/\\/g, '/').replace(/\/+$/, '');
  if (!root) return true;
  const normRoot = root.startsWith('/') ? root : `/${root}`;
  return clean === normRoot || clean.startsWith(`${normRoot}/`);
}

/**
 * Candidate host strings inside a single command argument: bare IPs, DNS
 * names, `user@host`, `host:path`/`host:port` (scp/rsync/ssh), `@server`
 * (dig), and bracketed IPv6 literals.
 */
export function hostCandidatesFromArg(arg) {
  const out = [];
  let s = String(arg || '').trim();
  if (!s || s.startsWith('-')) return out;
  s = s.replace(/^@/, '');
  // Strip a leading user@ or user:pass@ prefix; keep what follows.
  const at = s.lastIndexOf('@');
  if (at > 0 && !s.slice(0, at).includes('/')) s = s.slice(at + 1);
  // scp/rsync/ssh remote syntax host:path or host:port. A leading slash or
  // drive letter means this is a local path, not a remote spec. A `scheme://`
  // prefix or a known URI scheme means the colon introduces a URL, not a
  // remote spec: `https://host/path` must not yield "https" as a host.
  const isUrl = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s) ||
    /^(?:https?|ssh|git|ftp|sftp|telnet|gopher|dict|ldap|ldaps|smb|nfs|file|data|javascript|vbscript|ws|wss|nntp|imap|imaps|pop3|pop3s|smtp|smtps|rtsp|svn|irc|news|prospero|chrome|edge|about|mqtt|tftp|afs):/i.test(s);
  if (!isUrl && !/^[a-zA-Z]:[\\/]/.test(s) && !s.startsWith('/')) {
    const colon = s.indexOf(':');
    if (colon > 0) {
      const head = s.slice(0, colon);
      const tail = s.slice(colon + 1);
      if (/^[0-9]+$/.test(tail) || tail.startsWith('/') || !tail.includes(':')) {
        // host:port, host:/path, or host:path (single colon only)
        if (!head.includes('/') && !head.includes(' ')) out.push(head);
      }
    }
  }
  // Bracketed IPv6 literal, possibly with port or path.
  const v6 = /^\[([0-9a-fA-F:.%]+)\]/.exec(s);
  if (v6) { out.push(`[${v6[1]}]`); return out; }
  // Bare dotted IPv4 or DNS name: take up to the first '/', whitespace, or port.
  const bare = /^[^\s/?#]+/.exec(s)?.[0] || '';
  if (bare && !bare.startsWith('.')) {
    const noPort = bare.replace(/:\d+$/, '');
    if (parseIpv4Literal(noPort) || /^[a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9]$/.test(noPort) || /^[a-zA-Z0-9]$/.test(noPort)) {
      out.push(noPort);
    }
  }
  return out;
}

/**
 * Host candidates inside a git remote argument. Handles https://, ssh://,
 * git://, scp-like `git@host:path`, and bare `host:path` forms while
 * ignoring local filesystem paths.
 */
export function gitRemoteHostCandidates(arg) {
  const s = String(arg || '').trim();
  if (!s || s.startsWith('-') || s.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(s) || s.startsWith('.')) return [];
  const m = /^(?:[a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]+)/.exec(s);
  if (m) {
    let auth = m[1];
    const at = auth.lastIndexOf('@');
    if (at >= 0) auth = auth.slice(at + 1);
    return [auth.replace(/:\d+$/, '')];
  }
  // scp-like syntax: [user@]host:path (exactly one colon, path not absolute-windows)
  const scp = /^(?:[^@\s/]+@)?([^\s/:]+):(?!\/)([^\s]*)$/.exec(s);
  if (scp && !s.includes('://')) return [scp[1]];
  return [];
}

/**
 * Brace expansion produces a small set of alternates: `{a,b}` -> a b,
 * `{1..4}` -> 1 2 3 4, `{a..d}` -> a b c d. Nested and repeated braces
 * combine multiplicatively; expansion is bounded so a hostile `{1..1000000}`
 * range cannot blow up the candidate list. Anything over budget keeps its
 * literal form so the suspicious text still reaches inspection.
 */
export function expandBraceAlternates(s, limit = 64) {
  const results = [];
  const work = [String(s || '')];
  while (work.length > 0) {
    const item = work.pop();
    const start = item.indexOf('{');
    let end = -1;
    if (start >= 0) {
      let depth = 0;
      for (let i = start; i < item.length; i++) {
        if (item[i] === '{') depth += 1;
        else if (item[i] === '}') { depth -= 1; if (depth === 0) { end = i; break; } }
      }
    }
    let variants = null;
    if (start >= 0 && end > start) {
      const body = item.slice(start + 1, end);
      const seq = /^(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?$/.exec(body);
      const aSeq = /^([a-zA-Z])\.\.([a-zA-Z])(?:\.\.(-?\d+))?$/.exec(body);
      if (seq || aSeq) {
        const src = seq || aSeq;
        const step = src[3] ? Math.abs(Number(src[3])) || 1 : 1;
        const a = seq ? Number(src[1]) : src[1].charCodeAt(0);
        const b = seq ? Number(src[2]) : src[2].charCodeAt(0);
        const dir = a <= b ? step : -step;
        variants = [];
        for (let n = a; a <= b ? n <= b : n >= b; n += dir) {
          variants.push(seq ? String(n) : String.fromCharCode(n));
        }
      } else {
        // Comma alternates; `{a}` alone stays literal in POSIX.
        const parts = [];
        let d = 0, last = 0, hasComma = false;
        for (let k = 0; k <= body.length; k++) {
          const c = body[k];
          if (c === '{') d += 1;
          else if (c === '}') d -= 1;
          if ((c === ',' && d === 0) || k === body.length) {
            if (c === ',' && d === 0) hasComma = true;
            parts.push(body.slice(last, k));
            last = k + 1;
          }
        }
        if (hasComma) variants = parts;
      }
    }
    if (variants === null || results.length + work.length + variants.length > limit) {
      results.push(item);
      continue;
    }
    const prefix = item.slice(0, start);
    const suffix = item.slice(end + 1);
    for (const v of variants) work.push(`${prefix}${v}${suffix}`);
  }
  return results;
}

/**
 * Sensitive-path samples a wildcard argument can expand to. `*` and `?` never
 * match a leading dot, so a glob only reaches dotfiles when its first pattern
 * character is literal (or a class containing `.`).
 */
const GLOB_SENSITIVE_SAMPLES = [
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'environment', 'env.list',
  'credentials.json', '.env', '.env.local', '.envrc', '.npmrc', '.pypirc',
  '.netrc', '.git-credentials', '.bash_history', '.zsh_history', '.ssh/config',
  '.ssh/id_rsa', '.ssh/id_ed25519', '.aws/credentials', '.aws/config',
  '.gnupg/secring.gpg', '.git/config', '.gitconfig', '.bashrc', '.zshrc',
  '.profile', '.zshenv', 'authorized_keys', 'known_hosts', 'server.key',
  'private.pem', 'client.p12', 'database.yml', 'secrets.yaml',
  'api.token', 'app.env', 'prod.env', 'aws.credentials', '.pgpass',
  '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/proc/self/environ',
];

/** Commands whose glob arguments read file contents (not just metadata). */
const CONTENT_READER_COMMANDS = new Set([
  'cat', 'head', 'tail', 'sed', 'grep', 'rg', 'sort', 'wc', 'cut', 'awk',
  'gawk', 'mawk', 'nawk', 'perl', 'ruby', 'python', 'python3', 'xxd', 'od',
  'strings', 'file', 'less', 'more', 'base64', 'tee', 'dd', 'tar', 'zip',
  'openssl', 'diff', 'patch', 'sha1sum', 'sha256sum', 'sha512sum', 'md5sum',
  'source', '.',
]);

/** Convert one glob segment to a RegExp source (`*`/`?` never match `.`). */
function globSegmentToRegex(seg) {
  let out = '';
  let first = true;
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (c === '*') out += first ? '[^./]*' : '[^/]*';
    else if (c === '?') out += first ? '[^./]' : '[^/]';
    else if (c === '[') {
      const close = seg.indexOf(']', i + 1);
      if (close < 0) { out += '\\['; continue; }
      let cls = seg.slice(i + 1, close);
      cls = cls.startsWith('!') ? `^${cls.slice(1)}` : cls;
      out += `[${cls.replace(/\\/g, '\\\\')}]`;
      i = close;
    } else {
      out += c.replace(/[.+^$(){}|\\]/g, '\\$&');
    }
    first = false;
  }
  return out;
}

export function globMayMatchSensitive(pattern) {
  const p = String(pattern || '');
  if (!/[*?\[]/.test(p)) return false;
  const segs = p.split('/');
  const src = segs.map(globSegmentToRegex).join('/');
  let rx;
  try { rx = new RegExp(`^${src}$`); } catch { return true; }
  for (const sample of GLOB_SENSITIVE_SAMPLES) {
    if (rx.test(sample)) return true;
    const tail = sample.split('/').slice(-segs.length).join('/');
    if (rx.test(tail)) return true;
  }
  return false;
}

/**
 * Path-like substrings hidden inside a flag-attached argument: `-o/etc/x`,
 * `--output=/etc/x`, `-F file=@/etc/passwd`, `--data @/etc/passwd`,
 * `--rsh="ssh -i /key"`. Returns the candidate path tokens.
 */
export function pathLikeCandidates(arg) {
  const out = [];
  const s = String(arg || '');
  if (!s) return out;
  const seen = new Set();
  const push = (v) => {
    // Brace alternates (`{a,b}`) each become their own candidate so a
    // sensitive path cannot hide inside an expansion list.
    for (const cand of expandBraceAlternates(v)) {
      const t = String(cand || '').trim().replace(/^["']+|["']+$/g, '');
      if (t && !seen.has(t)) { seen.add(t); out.push(t); }
      if (out.length >= 96) return;
    }
  };
  // Whole argument is the common case.
  push(s);
  // --opt=value: check the value and each whitespace token inside it.
  const eq = s.indexOf('=');
  if (eq > 0) {
    for (const t of s.slice(eq + 1).split(/\s+/)) push(t);
  }
  // Short glued flag: -o/path, -I~/x, -f./rel (single letter then path char).
  const glued = /^-[A-Za-z]([\/~.]).*$/.exec(s);
  if (glued) {
    const i = s.search(/[\/~]/);
    if (i > 0) push(s.slice(i));
  }
  // @/path upload syntax (curl -F file=@/etc/passwd, --data @/etc/passwd).
  const at = s.indexOf('@/');
  if (at >= 0) push(s.slice(at + 1));
  // Parameter-expansion payloads: `${x:-/p}` substitutes /p when unset,
  // `${x/p/r}` substitutes r, `${x:=d}`/`${x:?m}`/`${x:+a}`/`${x#p}`/`${x%p}`
  // all embed a word the raw argument hides. `${x}` carries no path value.
  // The two-character `:`-forms must match before the bare `:` alternative.
  for (const m of s.matchAll(/\$\{[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?(?::-|:\+|:=|:\?|:|\/|#|%|-|\+|=|\?)([^}]*)\}/g)) {
    for (const t of String(m[1] || '').split(/\s+/)) {
      push(t);
      // `${x/pat/repl}`: the path lives after the pattern's first `/`.
      const sl = t.indexOf('/');
      if (sl >= 0) push(t.slice(sl));
    }
  }
  // Embedded whitespace: only flag/`=` arguments get tokenized
  // (`--rsh="ssh -i /key"`, `-c "cmd /path"`). A plain word with spaces is
  // prose or data (`echo "see /etc/passwd"`, `history -s "rm -rf /tmp/x"`),
  // not a path list, so it stays whole and cannot false-positive.
  if ((s.startsWith('-') || eq > 0) && /\s/.test(s)) {
    for (const t of s.split(/\s+/)) push(t);
  }
  return out;
}

function parseIpv4Part(part) {
  if (/^0x[0-9a-f]+$/.test(part)) return Number.parseInt(part, 16);
  if (/^0[0-7]*$/.test(part)) return Number.parseInt(part, 8);
  if (/^[0-9]+$/.test(part)) return Number(part);
  return null;
}

export function parseIpv4Literal(host) {
  const raw = String(host || '').trim().toLowerCase();
  if (!raw) return null;

  const parts = raw.split('.');
  if (parts.length < 1 || parts.length > 4 || parts.some((p) => !p)) return null;
  const nums = parts.map(parseIpv4Part);
  if (nums.some((n) => n === null || !Number.isInteger(n) || n < 0)) return null;

  if (nums.length === 1) {
    return nums[0] <= 0xffffffff ? intToOctets(nums[0]) : null;
  }
  if (nums.length === 2) {
    if (nums[0] > 255 || nums[1] > 0xffffff) return null;
    return [nums[0], (nums[1] >>> 16) & 255, (nums[1] >>> 8) & 255, nums[1] & 255];
  }
  if (nums.length === 3) {
    if (nums[0] > 255 || nums[1] > 255 || nums[2] > 0xffff) return null;
    return [nums[0], nums[1], (nums[2] >>> 8) & 255, nums[2] & 255];
  }
  if (nums.some((n) => n > 255)) return null;
  return nums;
}

function intToOctets(val) {
  return [(val >>> 24) & 255, (val >>> 16) & 255, (val >>> 8) & 255, val & 255];
}

/**
 * Normalize a URL host for IP/internal checks. Defeats the IDNA and URL-parser
 * lookalikes: ideographic (U+3002), fullwidth (U+FF0E) and halfwidth (U+FF61)
 * dots that WHATWG URL parsing treats as `.`; fullwidth digits that IDNA maps
 * to ASCII; percent-encoded bytes in the host; NUL/control suffixes; and IPv6
 * zone-id suffixes (`::1%25eth0`).
 */
export function normalizeHostForInspection(hostInput) {
  let host = String(hostInput ?? '');
  // Control and zero-width characters have no role in a resolvable hostname.
  host = host.replace(/[\u0000-\u001f\u007f-\u009f​‌‍⁠﻿]/g, '');
  // Strip the IPv6 zone-id (%eth0 or percent-encoded %25eth0).
  if (host.includes('[')) {
    host = host.replace(/%[0-9a-zA-Z~.\-]+(?=\]$)/, '');
  }
  // Percent-decode leniently (hosts may carry %2e dots).
  host = host.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(Number.parseInt(h, 16)));
  // Percent-decoded control bytes (%00 NUL, %09 tab) must be stripped too:
  // `127.0.0.1%00.evil.com` otherwise keeps a smuggled separator.
  host = host.replace(/[\u0000-\u001f\u007f-\u009f]/g, '');
  // NFKC folds fullwidth digits (１６９ -> 169); explicit map for the three
  // non-ASCII dot characters a URL parser accepts inside a host.
  host = host.normalize('NFKC').replace(/[。．｡]/g, '.').replace(/[⁄∕]/g, '/');
  // A host never legitimately contains a path, query, or fragment separator.
  // `127.0.0.1%2f.evil.com` decodes to `127.0.0.1/.evil.com`; cutting at the
  // first separator fails closed on the loopback prefix instead of treating
  // the whole string as an unverifiable DNS name.
  host = host.split(/[/?#]/)[0];
  host = host.trim().toLowerCase();
  return host;
}

/** Internal-only names: cloud metadata hosts and wildcard-DNS loopback/rebinding services. */
const INTERNAL_HOST_NAMES = /(?:^|\.)(?:nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me|traefik\.me|vcap\.me|fip\.io|1u\.ms|rebind\.network|ip6\.name|localdomain|home\.arpa|corp|lan|home|intranet|private|test|example|invalid)$|^(?:instance-data|metadata)$/i;

/**
 * Parse an IPv6 literal into its eight 16-bit hextets, expanding `::` and an
 * embedded dotted-quad tail (`::ffff:127.0.0.1`). Returns null on failure.
 */
function parseIpv6Hextets(host) {
  let s = String(host || '').trim().toLowerCase();
  if (!s.includes(':')) return null;
  // Embedded IPv4 tail: replace the last dotted quad with two hextets.
  const v4Match = /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/.exec(s);
  if (v4Match) {
    const octets = parseIpv4Literal(v4Match[1]);
    if (!octets) return null;
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    s = `${s.slice(0, v4Match.index)}${hi}:${lo}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parseSide = (part) => {
    if (part === '') return [];
    const pieces = part.split(':');
    const out = [];
    for (const p of pieces) {
      if (/^[0-9a-f]{1,4}$/.test(p)) { out.push(Number.parseInt(p, 16)); continue; }
      // Non-standard but seen in the wild: a 32-bit tail written as one
      // 8-hex-digit group (`::ffff:7f000001` = ::ffff:127.0.0.1). Split it
      // into its two hextets so embedded-IPv4 detection still applies.
      if (/^[0-9a-f]{8}$/.test(p)) {
        out.push(Number.parseInt(p.slice(0, 4), 16), Number.parseInt(p.slice(4), 16));
        continue;
      }
      return null;
    }
    return out;
  };
  const left = parseSide(halves[0]);
  const right = halves.length === 2 ? parseSide(halves[1]) : [];
  if (!left || !right) return null;
  if (halves.length === 1) {
    return left.length === 8 ? left : null;
  }
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return [...left, ...Array(missing).fill(0), ...right];
}

/** IPv6 prefixes that embed or translate an IPv4 address into a routable v6 literal. */
function ipv6EmbeddedIpv4Octets(hextets) {
  const h = hextets;
  // ::/96 IPv4-compatible (deprecated but still routed by some stacks)
  if (h.slice(0, 6).every((x) => x === 0)) {
    return [(h[6] >> 8) & 255, h[6] & 255, (h[7] >> 8) & 255, h[7] & 255];
  }
  // ::ffff:a.b.c.d IPv4-mapped and ::ffff:0:a.b.c.d IPv4-translated: the
  // 0xffff marker sits at hextet 4 or 5 depending on the form.
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 &&
      ((h[4] === 0 && h[5] === 0xffff) || (h[4] === 0xffff && h[5] === 0))) {
    return [(h[6] >> 8) & 255, h[6] & 255, (h[7] >> 8) & 255, h[7] & 255];
  }
  // 64:ff9b::/96 NAT64 well-known prefix embeds the IPv4 in the last 32 bits
  if (h[0] === 0x64 && h[1] === 0xff9b && h.slice(2, 6).every((x) => x === 0)) {
    return [(h[6] >> 8) & 255, h[6] & 255, (h[7] >> 8) & 255, h[7] & 255];
  }
  // 2002::/16 6to4 embeds the IPv4 in hextets 1-2
  if (h[0] === 0x2002) {
    return [(h[1] >> 8) & 255, h[1] & 255, (h[2] >> 8) & 255, h[2] & 255];
  }
  return null;
}

export function isPrivateOrInternalHost(hostInput) {
  let host = normalizeHostForInspection(hostInput);
  if (!host) return false;
  if (host.includes('@')) host = host.slice(host.lastIndexOf('@') + 1);
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  host = host.replace(/\.+$/, '');
  if (!host) return false;

  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return true;
  }
  // Wildcard-DNS rebinding services resolve subdomains to loopback/RFC1918
  // addresses (127.0.0.1.nip.io, 10-0-0-5.sslip.io, make-1-2-3-4-rr.1u.ms),
  // and bare cloud metadata names are internal by construction.
  if (INTERNAL_HOST_NAMES.test(host)) {
    return true;
  }

  // A single-label hostname (no dot, no colon) can only resolve through
  // local search domains or mDNS: it is internal by construction. Public DNS
  // names always contain at least one dot.
  if (!host.includes('.') && !host.includes(':')) {
    return true;
  }

  // IPv6 loopback / unspecified / link-local (fe80::/10) / unique local (fc00::/7)
  // / site-local (fec0::/10, deprecated but still routed internally)
  if (
    host === '::' ||
    host === '::1' ||
    /^(?:0+:){7}0*[01]$/.test(host) ||
    /^(?:0+:){1,6}:0*1$/.test(host) ||
    /^(?:fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:|fe[c-f][0-9a-f]:)/.test(host)
  ) {
    return true;
  }

  // Full hextet parse catches every IPv6 form that embeds an IPv4 address:
  // IPv4-compatible (::127.0.0.1), IPv4-mapped/translated (::ffff:0:127.0.0.1),
  // NAT64 (64:ff9b::7f00:1), and 6to4 (2002:7f00:1::).
  const hextets = parseIpv6Hextets(host);
  if (hextets) {
    const embedded = ipv6EmbeddedIpv4Octets(hextets);
    if (embedded) return isPrivateIpv4Octets(embedded);
  }

  const octets = parseIpv4Literal(host);
  if (octets) return isPrivateIpv4Octets(octets);
  // Dotted hosts made only of digits, dots, and IPv4 radix markers that failed
  // parsing (`127.0.0.257`, `999.1.1.1`) are either invalid literals or
  // wildcard-DNS names; neither can be proven public, so fail closed.
  if (host.includes('.') && /^[0-9a-fx.]+$/.test(host) && /[0-9]/.test(host)) return true;
  return false;
}

function isPrivateIpv4Octets([a, b]) {
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, and 255.255.255.255 broadcast
  // never leave the local network segment.
  if (a >= 224) return true;
  return false;
}

export function extractUrlsAndHosts(text) {
  const hosts = [];
  // WHATWG URL parsing removes ASCII tab/LF/CR anywhere in the input, so
  // `http\t://127.0.0.1/` still resolves to loopback for a real fetcher.
  // Strip them before matching or the scheme regex sees a gap and misses
  // the host entirely. Backslashes fold to `/` for the same reason.
  const folded = String(text || '').replace(/[\t\n\r]/g, '').replace(/\\/g, '/');
  const urlRe = /https?:\/{0,}([^\s/?#"']+)/gi;
  for (const m of folded.matchAll(urlRe)) {
    let auth = m[1];
    const atIdx = auth.lastIndexOf('@');
    if (atIdx >= 0) auth = auth.slice(atIdx + 1);
    let host = auth;
    if (auth.startsWith('[')) {
      const endBracket = auth.indexOf(']');
      host = endBracket > 0 ? auth.slice(0, endBracket + 1) : auth;
    } else {
      host = auth.replace(/:\d+$/, '');
    }
    // Normalization may fold a fullwidth solidus into a real `/`; the host
    // ends there. Also catch a raw `／` inside the captured authority.
    host = host.split('/')[0];
    hosts.push({ url: m[0], host: normalizeHostForInspection(host) });
  }
  return hosts;
}

/**
 * Sanitize a caller-supplied policy so a malformed value degrades to the safe
 * default instead of silently disabling a rule (a string where an array belongs
 * would otherwise become a character set, and a non-numeric depth would break
 * nesting checks).
 */
function sanitizePolicy(merged) {
  const asStringArray = (v, fallback) => {
    if (Array.isArray(v)) return v.map((x) => String(x)).filter(Boolean);
    if (typeof v === 'string' && v.trim()) return [v.trim()];
    return fallback;
  };
  const depth = Number(merged.maxShellNestingDepth);
  return {
    ...merged,
    allowedCommands: asStringArray(merged.allowedCommands, DEFAULT_POLICY.allowedCommands),
    blockedCommands: asStringArray(merged.blockedCommands, DEFAULT_POLICY.blockedCommands),
    networkCommands: asStringArray(merged.networkCommands, DEFAULT_POLICY.networkCommands),
    allowedDomains: asStringArray(merged.allowedDomains, DEFAULT_POLICY.allowedDomains),
    maxShellNestingDepth: Number.isFinite(depth) && depth >= 0 ? Math.min(depth, 12) : DEFAULT_POLICY.maxShellNestingDepth,
  };
}

/**
 * Evaluate a single agent tool-call trace against a capability policy.
 */
export function evaluateToolCall(toolCall, policyInput = DEFAULT_POLICY) {
  const policy = sanitizePolicy({ ...DEFAULT_POLICY, ...policyInput });
  const allowedSet = new Set(policy.allowedCommands);
  const blockedSet = new Set(policy.blockedCommands);
  const netCmdSet = new Set(policy.networkCommands);
  const allowedDomains = new Set(policy.allowedDomains.map((d) => d.toLowerCase()));

  const findings = [];
  let ast = { records: [], heredocScripts: [], maxObservedDepth: 0 };

  const addFinding = (ruleId, severity, title, detail, trail = [], suggestion = '') => {
    findings.push({ ruleId, severity, title, detail, trail, suggestion });
  };

  const KNOWN_TOOLS = new Set(['fs_read', 'fs_write', 'http_fetch', 'env_read', 'shell_exec']);
  const tool = String(toolCall?.tool || '');
  const args = toolCall?.args || {};

  // Deny-by-default: a tool call the firewall does not recognise is never ALLOW.
  if (!tool) {
    addFinding('CAP-POLICY-00', 'high', 'Missing tool name in tool call',
      'The call has no tool field, so it cannot be matched to a capability rule.', ['?'],
      'Every agent tool call must name a tool the firewall knows.');
  } else if (!KNOWN_TOOLS.has(tool)) {
    addFinding('CAP-POLICY-00', 'critical', `Unrecognised tool "${tool}" blocked by deny-by-default`,
      `Tool "${tool}" is not one of the guarded tools (${[...KNOWN_TOOLS].join(', ')}).`,
      [tool], 'Register the tool with a capability policy or remove it from the agent toolset.');
  } else {
    // Required argument present? An empty required arg is an escalation, never a silent ALLOW.
    const required = { fs_read: 'path', fs_write: 'path', http_fetch: 'url', env_read: 'name', shell_exec: 'command' }[tool];
    const missingArg = required && String(args[required] ?? '').trim() === '';
    if (missingArg) {
      addFinding('CAP-POLICY-01', 'medium', `Empty ${required} in ${tool} call`,
        `The ${tool} call carries no ${required}, so it cannot be inspected.`,
        [tool], `Populate ${required} before dispatching the tool call.`);
    }
  }

  if (tool === 'fs_read' || tool === 'fs_write') {
    const targetPath = String(args.path || '');
    if (hasTraversalSegment(targetPath)) {
      addFinding('CAP-PATH-01', 'critical', 'Directory traversal component in file tool argument',
        `Path "${targetPath}" contains a ".." escape segment.`, [tool],
        'Resolve paths canonically under the workspace root without ".." segments.');
    } else if (!isWithinWorkspace(targetPath, policy.workspaceRoot)) {
      addFinding('CAP-PATH-02', 'high', 'File access outside workspace capability root',
        `Path "${targetPath}" escapes workspace root "${policy.workspaceRoot}".`, [tool],
        `Confine ${tool} operations within ${policy.workspaceRoot}.`);
    }
    if (isSensitivePath(targetPath)) {
      addFinding('CAP-SECRET-01', 'critical', 'Sensitive credential or system path accessed',
        `Target "${targetPath}" matches a protected credential/system pattern.`, [tool],
        'Remove secret files from agent tool access.');
    }
  } else if (tool === 'http_fetch') {
    const rawUrl = String(args.url || '');
    const extracted = extractUrlsAndHosts(rawUrl);
    const host = extracted[0]?.host || String(args.host || '');
    if (policy.blockPrivateIps && isPrivateOrInternalHost(host)) {
      addFinding('CAP-SSRF-01', 'critical', 'Internal or metadata SSRF target blocked',
        `Host "${host}" resolves to loopback, private RFC1918, or cloud metadata range.`, [tool],
        'Block all RFC1918, loopback, link-local, and encoded IP literals.');
    } else if (!policy.allowNetwork && !allowedDomains.has(host.toLowerCase())) {
      addFinding('CAP-NET-01', 'high', 'Outbound network request not permitted by policy',
        `Host "${host || rawUrl}" is outside policy allowlist.`, [tool],
        'Enable allowNetwork or add the exact domain to allowedDomains.');
    }
  } else if (tool === 'env_read') {
    const key = String(args.name || '');
    if (!policy.allowEnvSecrets && SECRET_ENV_NAMES.test(key)) {
      addFinding('CAP-SECRET-02', 'critical', 'Secret environment variable read blocked',
        `Attempted read of secret variable "${key}".`, [tool],
        'Inject scoped mock fixtures instead of reading raw environment secrets.');
    }
  } else if (tool === 'shell_exec') {
    const commandStr = String(args.command || '');
    ast = analyzeShellAst(commandStr, policy.maxShellNestingDepth + 2);

    // Braced expansions like `${API_KEY}` are split by the tokenizer into `$`
    // and `{API_KEY}` nodes before arg inspection. Scan the raw command too so
    // a secret expansion can never hide behind brace syntax.
    if (!policy.allowEnvSecrets) {
      for (const m of commandStr.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)) {
        if (SECRET_ENV_NAMES.test(m[1])) {
          addFinding('CAP-SECRET-02', 'critical', `Secret env expansion "${m[0]}" in shell command`,
            `Command interpolates secret environment variable ${m[1]}.`, ['shell_exec'],
            'Avoid expanding secret variables in shell arguments.');
          break;
        }
      }
    }

    if (ast.maxObservedDepth > policy.maxShellNestingDepth) {
      addFinding('CAP-AST-01', 'high', 'Excessive shell nesting depth',
        `Observed nesting depth ${ast.maxObservedDepth} exceeds maxShellNestingDepth (${policy.maxShellNestingDepth}).`,
        ['shell_exec'], 'Flatten nested subshells into an explicit, auditable command.');
    }

    for (const rec of ast.records) {
      if (rec.command === '__max_depth_exceeded__') {
        addFinding('CAP-AST-01', 'critical', 'Recursive shell depth limit exceeded',
          'Execution halted because nested script depth exceeded firewall safety limit.',
          rec.trail, 'Remove deeply nested subshells.');
        continue;
      }
      if (rec.command === '__pipe_stdin_shell__') {
        addFinding('CAP-CMD-02', 'high', 'Piped dynamic stdin execution into shell blocked',
          `Piped input from [${rec.trail.join(' -> ')}] executes unchecked stdin code in a shell.`,
          rec.trail, 'Inspect or replace piped shell execution with an explicit static script or allowlisted command.');
        continue;
      }
      if (rec.command === '__find_delete__') {
        addFinding('CAP-CMD-01', 'high', 'find -delete removes every matched file',
          `find -delete at [${rec.trail.join(' -> ')}] deletes matched paths without a prompt.`,
          rec.trail, 'List the matches first and remove them with an explicit reviewed command.');
        continue;
      }
      // `bash --rcfile file` / `--init-file=file`: the named file runs as
      // shell code at startup, so it is an execution channel, not an inert
      // option value.
      if (rec.startupScriptFile) {
        const sf = String(rec.startupScriptFile);
        const sensitive = isSensitivePath(sf) || hasTraversalSegment(sf);
        addFinding('CAP-CMD-05', sensitive ? 'critical' : 'high',
          `Shell startup script "${sf}" executes as code`,
          `"${rec.command}" runs "${sf}" as code at startup at [${rec.trail.join(' -> ')}].`,
          rec.trail, 'Run an explicit reviewed script file instead of shell rc/init-file injection.');
      }
      // Program text fed to an interpreter through stdin (heredoc body, piped
      // echo/printf, `< file`): the payload is Python/Node/Ruby code, not
      // shell, so flag the channel itself for human review regardless of what
      // the shell-approximation of the payload parsed into. Shell consumers
      // are excluded: their payload really is shell, so the walked records
      // below give precise per-command findings instead.
      const stdinChannel = rec.trail.findIndex((t) => /^(heredoc\(|pipe-|herestring|<)/.test(t));
      if (stdinChannel >= 0) {
        const consumer = rec.trail[stdinChannel - 1] || '';
        if (STDIN_INTERPRETERS_SET.has(consumer)) {
          addFinding('CAP-CMD-05', 'high', `Program text fed to "${consumer}" through stdin`,
            `A heredoc or pipe supplies the program for "${consumer}" at [${rec.trail.slice(0, stdinChannel + 1).join(' -> ')}]; stdin code bypasses argument inspection.`,
            rec.trail.slice(0, stdinChannel + 1), 'Run an explicit script file that is itself reviewed, or pipe data (not code) into the interpreter.');
          continue;
        }
      }
      if (rec.command === '__stdin_redirect__') {
        const target = rec.args[0] || '';
        // The consumer is the command name preceding the `<target` trail entry.
        const consumer = rec.trail[rec.trail.length - 2] || '';
        const codeConsumer = SHELL_BINARIES.has(consumer) || STDIN_INTERPRETERS_SET.has(consumer);
        if (codeConsumer) {
          // `sh < script.sh`, `python3 < evil.py`: the file IS the program.
          const sensitive = isSensitivePath(target) || hasTraversalSegment(target);
          addFinding('CAP-CMD-05', sensitive ? 'critical' : 'high',
            `Redirected stdin script execution via "< ${target}"`,
            `"${consumer}" consumes program text from "< ${target}" at [${rec.trail.slice(0, -1).join(' -> ')}].`,
            rec.trail, 'Inspect the script content, or run an explicit allowlisted command instead of redirecting code into an interpreter.');
        } else {
          // `cat < file` is data input, not code: still inspect the target as
          // a path so `cat < /etc/passwd` cannot smuggle a sensitive read.
          if (hasTraversalSegment(target)) {
            addFinding('CAP-PATH-01', 'critical', `Path traversal ".." in redirect target`,
              `Redirect target "${target}" at [${rec.trail.join(' -> ')}] contains "..".`,
              rec.trail, 'Use canonical workspace-relative paths without traversal.');
          } else if (target && !isWithinWorkspace(target, policy.workspaceRoot) && target !== '/dev/null') {
            addFinding('CAP-PATH-02', 'high', `Redirect target "${target}" outside workspace`,
              `"< ${target}" at [${rec.trail.join(' -> ')}] reads outside "${policy.workspaceRoot}".`,
              rec.trail, `Keep redirect targets inside ${policy.workspaceRoot}.`);
          }
          if (isSensitivePath(target)) {
            addFinding('CAP-SECRET-01', 'critical', `Sensitive file path "${target}" via stdin redirect`,
              `Credential/system target at [${rec.trail.join(' -> ')}].`,
              rec.trail, 'Do not redirect secret or system files into commands.');
          }
        }
        continue;
      }
      // `> file` alone: no command, but the write target still needs the
      // same path checks an argument would get (truncate `> /etc/passwd`).
      if (rec.command === '__redirect_only__') {
        for (const target of rec.args || []) {
          if (hasTraversalSegment(target)) {
            addFinding('CAP-PATH-01', 'critical', `Path traversal ".." in redirect target`,
              `Redirect target "${target}" at [${rec.trail.join(' -> ')}] contains "..".`,
              rec.trail, 'Use canonical workspace-relative paths without traversal.');
          } else if (target && !isWithinWorkspace(target, policy.workspaceRoot) && !target.startsWith('/dev/null')) {
            addFinding('CAP-PATH-02', 'high', `Redirect target "${target}" outside workspace`,
              `Redirect target "${target}" at [${rec.trail.join(' -> ')}] escapes "${policy.workspaceRoot}".`,
              rec.trail, `Keep redirect targets inside ${policy.workspaceRoot}.`);
          }
          if (isSensitivePath(target)) {
            addFinding('CAP-SECRET-01', 'critical', `Sensitive file path "${target}" as redirect target`,
              `Credential/system target at [${rec.trail.join(' -> ')}].`,
              rec.trail, 'Do not redirect secret or system files.');
          }
        }
        continue;
      }
      // Redirect targets (`cmd > out`, `cat x < in`) are no longer part of
      // argv, but they still need the same path checks: `cat x > /etc/cron.d/j`
      // must not pass because the target left the argument list. Run before
      // any `continue` below so fd-setup records (`exec > /etc/passwd`) are
      // still judged.
      for (const target of rec.redirectTargets || []) {
        if (hasTraversalSegment(target)) {
          addFinding('CAP-PATH-01', 'critical', `Path traversal ".." in redirect target`,
            `Redirect target "${target}" at [${rec.trail.join(' -> ')}] contains "..".`,
            rec.trail, 'Use canonical workspace-relative paths without traversal.');
        } else if (target && !isWithinWorkspace(target, policy.workspaceRoot) && !target.startsWith('/dev/null')) {
          addFinding('CAP-PATH-02', 'high', `Redirect target "${target}" outside workspace`,
            `Redirect target "${target}" at [${rec.trail.join(' -> ')}] escapes "${policy.workspaceRoot}".`,
            rec.trail, `Keep redirect targets inside ${policy.workspaceRoot}.`);
        }
        if (isSensitivePath(target)) {
          addFinding('CAP-SECRET-01', 'critical', `Sensitive file path "${target}" as redirect target`,
            `Credential/system target at [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Do not redirect secret or system files.');
        }
      }

      // `env --version` / `env --help` answered and exited at parse time.
      if (rec.command === '__env_query__') continue;
      // Bare wrapper (`env`, `xargs`, `sudo`, `timeout`, ... consuming the
      // whole line): still a real command with real side effects. `exec`,
      // `command`, and `builtin` with no operand are no-ops or fd setup.
      const bareMatch = /^__bare_(.+?)__$/.exec(rec.command);
      if (bareMatch) {
        const bare = bareMatch[1];
        if (bare === 'exec' || bare === 'command' || bare === 'builtin') continue;
        if (bare === 'env') {
          addFinding('CAP-SECRET-02', 'critical', 'Bare "env" dumps the process environment',
            'A bare env call prints every environment variable, including secrets the policy never meant to expose.',
            rec.trail, 'Name the variables you need instead of dumping the environment.');
        } else if (blockedSet.has(bare)) {
          addFinding('CAP-CMD-01', 'critical', `Blocked command "${bare}" with no arguments`,
            `A bare "${bare}" invocation at [${rec.trail.join(' -> ')}] is still the blocked command.`,
            rec.trail, `Remove "${bare}" or request explicit human elevation.`);
        } else if (!allowedSet.has(bare) && !SHELL_BINARIES.has(bare)) {
          addFinding('CAP-CMD-02', 'medium', `Unlisted wrapper command "${bare}" with no target`,
            `A bare "${bare}" invocation consumes buffered input or mutates state outside the allowlist.`,
            rec.trail, `Either add "${bare}" to allowedCommands or replace it with an explicit allowlisted command.`);
        } else {
          addFinding('CAP-CMD-02', 'medium', `Bare "${bare}" wrapper with no target command`,
            `A bare "${bare}" call has no inspectable payload, so the firewall cannot verify what it would run.`,
            rec.trail, 'Run an explicit allowlisted command instead of a bare wrapper invocation.');
        }
        continue;
      }

      // Environment assignments only apply where the shell would treat them
      // as env writes: the leading `NAME=value cmd` prefix and words consumed
      // by env-family wrappers. `sudo`/`doas`/`pkexec`/`setpriv` also take
      // NAME=value arguments for the child, so their raw words stay in scope;
      // for everything else an arg like `npm pkg set browser=x` is data, not
      // an environment assignment.
      const envArgCarrier = (rec.trail || []).some((t) => ['env', 'sudo', 'doas', 'pkexec', 'setpriv'].includes(t));
      const envWords = envArgCarrier ? (rec.rawWords || []) : (rec.envAssignments || []);

      // Secret assignments passed to wrapper binaries (env -i, env FOO=,
      // timeout, command) are consumed by the unwrapper and never reach arg
      // inspection. Check the assignment words for `NAME=secret` assignments.
      if (!policy.allowEnvSecrets) {
        for (const w of envWords) {
          const m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(w);
          if (m && SECRET_ENV_NAMES.test(m[1])) {
            addFinding('CAP-SECRET-02', 'critical', `Secret env assignment "${m[1]}" in ${rec.command}`,
              `Wrapper call injects secret environment variable ${m[1]}.`, rec.trail,
              'Inject scoped mock fixtures instead of passing raw environment secrets.');
            break;
          }
        }
      }

      // Environment-channel injection: `NAME=value cmd` and `env NAME=value cmd`
      // prefix a command with variables that load code (LD_PRELOAD, BASH_ENV,
      // NODE_OPTIONS), redirect resolution (PATH, HOME, proxies), or point
      // config/credential files at attacker-controlled locations. These are
      // never benign enough to allow silently.
      for (const w of envWords) {
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(w);
        if (!m) continue;
        const name = m[1];
        const value = m[2] || '';
        // `ENV=production` is a common benign app setting; only a path-like
        // value turns POSIX sh's startup file into an execution channel.
        if (name === 'ENV' && !/[\/\\]/.test(value)) continue;
        if (EXEC_CHANNEL_ENV.test(name)) {
          addFinding('CAP-ENV-01', 'high', `Execution-channel env assignment "${name}" in ${rec.command}`,
            `"${name}=${value.slice(0, 60)}" loads code, hijacks command resolution, or redirects a trusted config file.`,
            rec.trail, 'Do not set loader, interpreter, shell-startup, or resolver variables from tool calls.');
          break;
        }
        if (PAGER_ENV_NAMES.test(name)) {
          // Pager/editor values are commands: safe pager (or editor) names
          // pass, paths, shells, interpreters, and destructive/network
          // binaries are held for review.
          const v = value.trim();
          const firstTok = v.split(/\s+/)[0] || '';
          const base = firstTok.split(/[\\/]/).filter(Boolean).pop() || '';
          const isEditor = PAGER_EDITOR_NAMES.test(name);
          const benignName = PAGER_SAFE_VALUES.test(base) || (isEditor && EDITOR_SAFE_VALUES.test(base));
          const dangerous =
            /[\/\\;|&`$(){}<>\n]/.test(v) ||
            (!benignName && PAGER_DANGEROUS_BIN.test(base)) ||
            /^(?:sh|bash|zsh|dash|ash|ksh|mksh|fish|csh|tcsh)(?:\s|$)/i.test(v);
          // A safe name only clears the check when the value IS the binary:
          // `PAGER='cat /etc/passwd'` runs cat with a path argument.
          if (!(benignName && v === base) && dangerous) {
            addFinding('CAP-ENV-02', 'medium', `Executable pager/editor env "${name}" in ${rec.command}`,
              `"${name}=${value.slice(0, 60)}" can run an arbitrary program when the tool pages output.`,
              rec.trail, 'Leave pager and editor variables unset or point them at reviewed binaries.');
            break;
          }
          continue;
        }
        if (REDIRECT_ENV.test(name)) {
          addFinding('CAP-ENV-02', 'medium', `Resolution-redirect env assignment "${name}" in ${rec.command}`,
            `"${name}=${value.slice(0, 60)}" reroutes command, config, credential, or network resolution.`,
            rec.trail, 'Keep environment assignments inside the reviewed baseline.');
          break;
        }
      }

      // A segment that was only `VAR=value` assignments carries no command to
      // dispatch on; the secret and env-channel scans above already judged it.
      if (rec.command === '__env_only__') continue;

      // A command name built from expansion (`$(echo rm)`, '`id`', `$x`, `${x}`)
      // cannot be statically verified: the real binary is decided at runtime.
      if (/[$`]/.test(rec.command)) {
        addFinding('CAP-CMD-07', 'high', `Dynamic command name "${rec.command}" cannot be verified`,
          `Command position interpolates a variable or substitution at [${rec.trail.join(' -> ')}].`,
          rec.trail, 'Use a literal allowlisted command name.');
      }

      // `xargs` feeds stdin words back as argv. Against a shell or interpreter
      // that argv can become program text (`xargs -I{} sh -c {}`,
      // `printf 'rm -rf /\\0' | xargs -0 sh -c`), and against a network tool it
      // becomes an uninspected URL. Flag the channel for those consumers.
      if (rec.trail.includes('xargs') &&
          (SHELL_BINARIES.has(rec.command) || STDIN_INTERPRETERS_SET.has(rec.command) || netCmdSet.has(rec.command))) {
        addFinding('CAP-CMD-08', 'high', `xargs feeds stdin words as argv to "${rec.command}"`,
          `Arguments for "${rec.command}" at [${rec.trail.join(' -> ')}] come from piped input, not the inspected command line.`,
          rec.trail, 'Replace xargs-fed shells and network tools with an explicit static command.');
      }

      // `xargs -a file` / `--arg-file=file` builds the child argv from file
      // contents the firewall never inspected.
      if (rec.trail.includes('xargs') &&
          [...(rec.args || []), ...(rec.rawWords || [])].some((a) => a === '-a' || a === '--arg-file' || a.startsWith('--arg-file='))) {
        addFinding('CAP-CMD-08', 'medium', 'xargs reads child argv from an uninspected file',
          `xargs -a/--arg-file at [${rec.trail.join(' -> ')}] builds argv from file contents outside the inspected command line.`,
          rec.trail, 'List the arguments explicitly instead of reading argv from a file.');
      }

      const blockedInTrail = rec.trail.find((cmdName) => blockedSet.has(cmdName));
      if (blockedInTrail) {
        addFinding('CAP-CMD-01', 'critical', `Blocked command "${blockedInTrail}" detected via AST unwrap`,
          `Blocked command "${blockedInTrail}" found in chain [${rec.trail.join(' -> ')}].`,
          rec.trail, `Remove "${blockedInTrail}" or request explicit human elevation.`);
      } else if (netCmdSet.has(rec.command)) {
        // Inspect URLs / hosts in args. Candidates come from explicit URLs,
        // bare host args, `user@host`, `host:path`/`host:port` (scp/rsync/ssh),
        // `@server` (dig), and non-http scheme authorities.
        const joinedArgs = rec.args.join(' ');
        const urlHits = extractUrlsAndHosts(joinedArgs);
        const hostCandidates = [];
        for (const a of rec.args) {
          if (a.startsWith('-')) continue;
          hostCandidates.push(...hostCandidatesFromArg(a));
        }
        // curl connect-override channels: --resolve/--connect-to pin a name to
        // an arbitrary IP, and proxy flags without a scheme hide the target.
        for (let i = 0; i < rec.args.length; i++) {
          const a = rec.args[i];
          const ov = /^(?:--resolve|--connect-to)(?:=(.*))?$/.exec(a);
          if (ov) {
            const val = ov[1] ?? rec.args[i + 1] ?? '';
            for (const seg of String(val).split(':')) {
              const t = seg.trim().replace(/^\[|\]$/g, '');
              if (t && !/^\d+$/.test(t)) hostCandidates.push(t);
            }
          }
          if (a === '--unix-socket' || a === '--abstract-unix-socket' || a.startsWith('--unix-socket=') || a.startsWith('--abstract-unix-socket=')) {
            addFinding('CAP-SSRF-04', 'high', `Unix socket channel via "${rec.command}"`,
              `${rec.command} can be pointed at a local socket (docker.sock, dbus) that bypasses all host checks.`,
              rec.trail, 'Do not let network tools open unix sockets from tool calls.');
          }
        }
        const privateHit = urlHits.some((u) => isPrivateOrInternalHost(u.host)) ||
          hostCandidates.some((c) => isPrivateOrInternalHost(c));
        if (policy.blockPrivateIps && privateHit) {
          addFinding('CAP-SSRF-01', 'critical', `SSRF internal/metadata probe via "${rec.command}"`,
            `Internal or encoded IP target in [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Disallow outbound requests to internal/metadata addresses.');
        }
        // Non-HTTP schemes (file://, gopher://, dict://, ...) bypass the URL
        // host extraction entirely and reach local files or odd services.
        const schemeHits = new Set();
        for (const m of joinedArgs.matchAll(/\b([a-zA-Z][a-zA-Z0-9+.-]*):\/\//g)) {
          const sch = m[1].toLowerCase();
          if (sch !== 'http' && sch !== 'https') schemeHits.add(sch);
        }
        for (const m of joinedArgs.matchAll(/\b(?:file|gopher|dict|ldap|smb|telnet|tftp|mqtt|data|javascript|vbscript|about|ws|wss|chrome|edge|nntp|imap|pop3|smtp|rtsp|svn|irc|news|nfs|afs|prospero):\//gi)) {
          schemeHits.add(m[0].slice(0, m[0].indexOf(':')).toLowerCase());
        }
        if (schemeHits.size > 0) {
          addFinding('CAP-SSRF-02', 'high', `Non-HTTP(S) URL scheme via "${rec.command}"`,
            `Scheme(s) ${[...schemeHits].join(', ')} in [${rec.trail.join(' -> ')}] bypass host inspection.`,
            rec.trail, 'Restrict network tools to http/https URLs.');
        }
        // ssh-family options that execute a local program. `-o KEY=VAL` takes
        // the option as a separate argument; `-oKEY=VAL` glues it on.
        for (let i = 0; i < rec.args.length; i++) {
          const a = rec.args[i];
          let optVal = null;
          if (a === '-o' || a === '--option') optVal = rec.args[i + 1] || '';
          else if (/^-o[^\s]/.test(a) && a.length > 2) optVal = a.slice(2);
          else if (a.startsWith('--option=')) optVal = a.slice('--option='.length);
          if (optVal !== null && /^(?:ProxyCommand|LocalCommand|PermitLocalCommand|RemoteCommand|KnownHostsCommand|SecurityKeyProvider|PKCS11Provider)\b/i.test(optVal)) {
            addFinding('CAP-CMD-03', 'high', `ssh option executes local program via "${rec.command}"`,
              `Option "${optVal.slice(0, 60)}" in [${rec.trail.join(' -> ')}] runs a command on the client.`,
              rec.trail, 'Do not pass ProxyCommand/LocalCommand style options to remote tools.');
          }
          // scp/sftp/rsync remote-shell selectors run a caller-chosen program.
          if (/^(?:-S|--rsh|-e|--rsync-path|--remote-option)(?:=|$)/.test(a) ||
              (['-S', '-e', '--rsh', '--rsync-path', '--remote-option'].includes(a) && i + 1 < rec.args.length)) {
            const val = a.includes('=') ? a.slice(a.indexOf('=') + 1) : (rec.args[i + 1] || '');
            if (!/^(?:ssh|ssh -[^\s]+\s*)*$/.test(val.trim()) || SHELL_META_RE.test(val)) {
              addFinding('CAP-CMD-03', 'medium', `Remote-shell selector "${String(val).slice(0, 50)}" via "${rec.command}"`,
                `${rec.command} option at [${rec.trail.join(' -> ')}] names the program used for the remote transport.`,
                rec.trail, 'Keep remote-shell selectors pinned to plain ssh.');
            }
          }
          // Config-file flags merge attacker-chosen options into the parsed
          // argv: `curl -K`, `wget --config`/`-i`, `ssh -F` can inject
          // proxy/exec/URL settings the inspected command line never showed.
          const cfgFlag =
            (rec.command === 'curl' && (a === '-K' || a === '--config' || /^-K\S/.test(a) || a.startsWith('--config='))) ||
            (rec.command === 'wget' && (a === '--config' || a === '-i' || a === '--input-file' || a.startsWith('--config=') || a.startsWith('--input-file=') || /^-i\S/.test(a))) ||
            (/^(?:ssh|scp|sftp)$/.test(rec.command) && (a === '-F' || /^-F\S/.test(a)));
          if (cfgFlag) {
            const val = a.includes('=') ? a.slice(a.indexOf('=') + 1)
              : (/^-[A-Za-z]\S/.test(a) && !a.startsWith('--') ? a.slice(2) : (rec.args[i + 1] || ''));
            addFinding('CAP-CMD-03', 'high', `Config-file channel via "${rec.command}"`,
              `"${rec.command}" merges options from "${String(val).slice(0, 60)}" at [${rec.trail.join(' -> ')}]; the file can inject proxy, exec, or URL settings.`,
              rec.trail, 'Pass the exact flags on the command line instead of loading a config file.');
          }
        }
        if (!policy.allowNetwork) {
          const allAllowed = urlHits.length > 0 && urlHits.every((u) => allowedDomains.has(u.host.toLowerCase()));
          if (!allAllowed) {
            addFinding('CAP-NET-01', 'high', `Network utility "${rec.command}" blocked by offline capability policy`,
              `Command [${rec.trail.join(' -> ')}] attempts network egress without allowNetwork.`,
              rec.trail, 'Run offline or add explicit domain allowlist entry.');
          }
        }
      } else if (!allowedSet.has(rec.command) && !SHELL_BINARIES.has(rec.command) && !SAFE_BUILTINS.has(rec.command) &&
                 rec.command !== '__control_spec__' &&
                 !((rec.args || []).length === 0 && /^[A-Za-z_][A-Za-z0-9_]*(?:\+\+|--|[-+*/%&|^]?=.*)$/.test(rec.command))) {
        // `__control_spec__` is a compound-statement spec (`for x in ...`),
        // not a command; a bare `x++`/`x+=1` word is arithmetic, not exec.
        addFinding('CAP-CMD-02', 'medium', `Unlisted command "${rec.command}" outside capability allowlist`,
          `Command "${rec.command}" at [${rec.trail.join(' -> ')}] is not in allowedCommands.`,
          rec.trail, `Either add "${rec.command}" to allowedCommands or replace with an allowed tool.`);
      }

      // Inspect path arguments & redirection targets (including for `echo`
      // redirects and secret expansion). `rawWords` catches flag-attached
      // paths (`-o/etc/x`) and env-prefix words the arg list drops; each word
      // is expanded through pathLikeCandidates so glued values surface.
      const pathWords = new Set([...(rec.args || []), ...(rec.rawWords || [])]);
      for (const word of pathWords) {
        // Env assignments are data for the child process, not file arguments;
        // the env-channel scan above already judges their names. A value that
        // is itself path-rooted still gets checked: `curl -F file=@/etc/x`
        // tokenizes as NAME=value but the value is a real path reference.
        const envAssign = /^([A-Za-z_][A-Za-z0-9_%]*)=(.*)$/.exec(word);
        if (envAssign) {
          const val = envAssign[2] || '';
          if (!/^[/~$.@]/.test(val) && !val.includes('@/')) continue;
          for (const arg of pathLikeCandidates(val)) {
            if (hasTraversalSegment(arg)) {
              addFinding('CAP-PATH-01', 'critical', `Path traversal ".." detected in ${rec.command} env value`,
                `Normalized token "${arg}" in [${rec.trail.join(' -> ')}] contains "..".`,
                rec.trail, 'Use canonical workspace-relative paths without traversal.');
            } else if (!isWithinWorkspace(arg, policy.workspaceRoot) && !arg.startsWith('/dev/null')) {
              addFinding('CAP-PATH-02', 'high', `Outside-workspace path "${arg}" in ${rec.command} env value`,
                `Path "${arg}" escapes "${policy.workspaceRoot}" at [${rec.trail.join(' -> ')}].`,
                rec.trail, `Keep file arguments inside ${policy.workspaceRoot}.`);
            }
            if (isSensitivePath(arg)) {
              addFinding('CAP-SECRET-01', 'critical', `Sensitive file path "${arg}" in ${rec.command} env value`,
                `Credential/system target at [${rec.trail.join(' -> ')}].`,
                rec.trail, 'Do not pass secret or system credential files to shell commands.');
            } else if (CONTENT_READER_COMMANDS.has(rec.command) && globMayMatchSensitive(arg)) {
              addFinding('CAP-SECRET-01', 'critical', `Glob "${arg}" can expand to credential material`,
                `Wildcard env value in [${rec.trail.join(' -> ')}] can match sensitive files at runtime.`,
                rec.trail, 'Name the exact file instead of a wildcard that can reach secrets.');
            }
          }
          continue;
        }
        for (const arg of pathLikeCandidates(word)) {
          if (arg.startsWith('-') && !arg.startsWith('/')) continue;
          // `cat ${x}` / `cat $file`: the real path is chosen at runtime and
          // cannot be verified against the workspace. Only path-consuming
          // commands get held (`echo $HOME` prints text, `$((1+2))` is
          // arithmetic; neither reads a file). Literal defaults inside
          // `${x:-/etc/passwd}` are extracted by pathLikeCandidates and stay
          // covered for every command.
          const dynamicPathArg = /^\$\{?[A-Za-z_]/.test(arg) || (arg.startsWith('$(') && !arg.startsWith('$(('));
          if (dynamicPathArg &&
              (CONTENT_READER_COMMANDS.has(rec.command) || SHELL_BINARIES.has(rec.command) || STDIN_INTERPRETERS_SET.has(rec.command))) {
            addFinding('CAP-PATH-03', 'medium', `Dynamic path expansion "${arg.slice(0, 40)}" in ${rec.command} cannot be verified`,
              `Path "${arg.slice(0, 60)}" at [${rec.trail.join(' -> ')}] resolves at runtime.`,
              rec.trail, `Keep file arguments inside ${policy.workspaceRoot} with literal paths.`);
          }
          if (hasTraversalSegment(arg)) {
            addFinding('CAP-PATH-01', 'critical', `Path traversal ".." detected in ${rec.command} argument`,
              `Normalized token "${arg}" in [${rec.trail.join(' -> ')}] contains "..".`,
              rec.trail, 'Use canonical workspace-relative paths without traversal.');
          } else if (!isWithinWorkspace(arg, policy.workspaceRoot) && !arg.startsWith('/dev/null')) {
            // `~`/`~user` home paths and `$VAR`-rooted paths resolve outside
            // the workspace (or cannot be verified) at runtime.
            const dynamic = /^(?:~|\$|\$\{|\$\()/.test(arg) || /[\/~]\$(?:\{|[A-Za-z_])/.test(arg);
            addFinding(dynamic ? 'CAP-PATH-03' : 'CAP-PATH-02', dynamic ? 'medium' : 'high',
              dynamic ? `Dynamic or home path "${arg}" in ${rec.command} cannot be verified inside workspace`
                      : `Outside-workspace path "${arg}" in ${rec.command}`,
              `Path "${arg}" escapes "${policy.workspaceRoot}" or resolves dynamically at [${rec.trail.join(' -> ')}].`,
              rec.trail, `Keep file arguments inside ${policy.workspaceRoot}.`);
          }
          if (isSensitivePath(arg)) {
            addFinding('CAP-SECRET-01', 'critical', `Sensitive file path "${arg}" referenced by ${rec.command}`,
              `Credential/system target at [${rec.trail.join(' -> ')}].`,
              rec.trail, 'Do not pass secret or system credential files to shell commands.');
          } else if (CONTENT_READER_COMMANDS.has(rec.command) && globMayMatchSensitive(arg)) {
            // `cat .env*` reads credential files at glob time: a wildcard
            // that can reach secret basenames is as dangerous as naming them.
            addFinding('CAP-SECRET-01', 'critical', `Glob "${arg}" can expand to credential material`,
              `Wildcard argument in [${rec.trail.join(' -> ')}] can match sensitive files at runtime.`,
              rec.trail, 'Name the exact file instead of a wildcard that can reach secrets.');
          }
          if (!policy.allowEnvSecrets && /\$\{?([A-Z0-9_]+)\}?/.test(arg) && SECRET_ENV_NAMES.test(arg)) {
            addFinding('CAP-SECRET-02', 'critical', `Secret env expansion "${arg}" in ${rec.command}`,
              `Command interpolates a secret environment variable.`,
              rec.trail, 'Avoid expanding secret variables in shell arguments.');
          }
        }
      }

      // Shell builtins that smuggle a command string or callback inside an
      // otherwise-safe builtin: trap's first arg is code, bind maps keys to
      // commands, complete/compgen -C and mapfile/readarray -C name a command
      // run per completion/line, enable -f loads a shared object, hash -p
      // repoints a command name at an arbitrary binary, alias redefines a
      // command name, and bare fc/fc -s re-executes history.
      if (BUILTIN_EXEC_ARG_CHECKS.has(rec.command)) {
        checkBuiltinExecArgs(rec, addFinding, { blockedSet, allowedSet, netCmdSet, policy });
      }

      // `sed` hides execution inside a single script argument: the `e`
      // command and the `s///e` flag run shell, `r`/`w` commands read or
      // write files, and `-f` loads script text the firewall never sees.
      if (rec.command === 'sed') {
        checkSedArgs(rec, addFinding);
      }

      // awk-family programs hide execution inside the script text argument:
      // system(), @include/@load, and `cmd | getline` / `print | "cmd"` all
      // run or load code the command line never names.
      if (/^(?:awk|gawk|mawk|nawk)$/.test(rec.command)) {
        checkAwkArgs(rec, addFinding);
      }

      // Program-loader flags on allowlisted tools: `rg --pre sh` runs a
      // named binary per file, `sort --compress-program` runs it on
      // intermediate output, `pytest -p` imports an arbitrary plugin module,
      // and `pytest -c`/`--import-mode` redirect the test harness config.
      if (rec.command === 'rg') {
        for (const a of rec.args) {
          if (a === '--pre' || a.startsWith('--pre=') || a === '--hostname-bin' || a.startsWith('--hostname-bin=')) {
            addFinding('CAP-CMD-03', 'high', `rg exec channel "${a.slice(0, 40)}"`,
              `${a} at [${rec.trail.join(' -> ')}] runs a named program inside rg; the command line hides which binary executes.`,
              rec.trail, 'Do not use rg --pre/--hostname-bin from tool calls.');
            break;
          }
        }
      }
      if (rec.command === 'sort') {
        for (const a of rec.args) {
          if (a === '--compress-program' || a.startsWith('--compress-program=')) {
            addFinding('CAP-CMD-03', 'high', `sort --compress-program runs a named binary`,
              `--compress-program at [${rec.trail.join(' -> ')}] execs a compressor program the command line never names.`,
              rec.trail, 'Do not use sort --compress-program from tool calls.');
            break;
          }
        }
      }
      if (rec.command === 'pytest') {
        for (const a of rec.args) {
          if (a === '-p' || /^-p[^\d\s]/.test(a)) {
            addFinding('CAP-CMD-03', 'high', `pytest -p imports an arbitrary plugin module`,
              `pytest -p at [${rec.trail.join(' -> ')}] loads the named module at startup; arbitrary code executes.`,
              rec.trail, 'Do not load pytest plugins from tool calls; run the suite with reviewed conftest.');
            break;
          }
          if (a === '-c' || a === '--import-mode' || a.startsWith('--import-mode=') || a === '--confcutdir' || a.startsWith('--confcutdir=')) {
            addFinding('CAP-CMD-05', 'medium', `pytest option "${a.slice(0, 40)}" redirects the test harness`,
              `${a} at [${rec.trail.join(' -> ')}] points pytest at a different config or import path than reviewed.`,
              rec.trail, 'Run pytest with the repository config the review covered.');
            break;
          }
        }
      }
      if (rec.command === 'node') {
        for (let i = 0; i < rec.args.length; i++) {
          const a = rec.args[i];
          if (a === '--run' || a.startsWith('--run=')) {
            addFinding('CAP-CMD-04', 'medium', `node --run executes a package.json script`,
              `node --run at [${rec.trail.join(' -> ')}] runs a named package script; the script body is outside the command line.`,
              rec.trail, 'Audit the package script or run the steps as explicit commands.');
            break;
          }
          if (a === '--test-reporter' || a.startsWith('--test-reporter=')) {
            addFinding('CAP-CMD-03', 'high', `node --test-reporter loads a reporter module`,
              `--test-reporter at [${rec.trail.join(' -> ')}] resolves and executes an arbitrary module.`,
              rec.trail, 'Use the built-in reporters from tool calls.');
            break;
          }
          if (/^--inspect/.test(a)) {
            addFinding('CAP-CMD-05', 'medium', `node "${a.slice(0, 40)}" opens the V8 inspector`,
              `--inspect flags at [${rec.trail.join(' -> ')}] expose a debug port outside the reviewed surface.`,
              rec.trail, 'Run node without --inspect flags from tool calls.');
            break;
          }
          if (a === '--openssl-config' || a.startsWith('--openssl-config=')) {
            addFinding('CAP-CMD-05', 'medium', `node --openssl-config points at an unreviewed config`,
              `--openssl-config at [${rec.trail.join(' -> ')}] loads an OpenSSL config file that can register engines.`,
              rec.trail, 'Do not redirect the OpenSSL config from tool calls.');
            break;
          }
        }
      }

      // An interpreter whose program text arrives through a process
      // substitution (`python3 <(gen.py)`, `bash <(echo 'rm -rf /')`) or an
      // fd path runs code generated at runtime: the inner command is
      // inspected, but its output-as-program is not.
      if ((SHELL_BINARIES.has(rec.command) || STDIN_INTERPRETERS_SET.has(rec.command)) &&
          [...(rec.args || []), ...(rec.rawWords || [])].some((a) => /<\(|>\(|\/dev\/(?:fd|stdin|stdout)/.test(String(a)))) {
        addFinding('CAP-CMD-10', 'medium', `Runtime-generated program text into "${rec.command}"`,
          `"${rec.command}" at [${rec.trail.join(' -> ')}] consumes a process substitution or fd path as its program; the executed text is produced at runtime and cannot be inspected.`,
          rec.trail, 'Write the program to a reviewed script file and pass its path explicitly.');
      }

      // Inline interpreter code (python3 -c, node -e, npm run, ...) is arbitrary
      // code execution hidden inside an allowlisted command. Escalate and, when
      // the payload is shell-shaped, recurse so blocked commands inside it fire.
      const inline = extractInlineCode(rec);
      if (inline && !policy.allowInlineCode) {
        const severity = inline.kind === 'npm-script' ? 'medium' : 'high';
        const ruleId = inline.kind === 'npm-script' ? 'CAP-CMD-04' : 'CAP-CMD-03';
        addFinding(ruleId, severity, `Inline code execution in "${rec.command}"`,
          `${rec.command} carries inline ${inline.kind === 'npm-script' ? 'package script' : 'code'} that runs without inspection (${inline.code.slice(0, 60)}).`,
          rec.trail, inline.kind === 'npm-script'
            ? 'Audit the package script, or inline the safe steps as explicit allowlisted commands.'
            : 'Move the logic into an audited script file, or set allowInlineCode only for trusted one-offs.');
        if (inline.code && inline.kind === 'inline' && /[;&|`$(){}<>\n]/.test(inline.code)) {
          // The payload looks like shell; recurse so a hidden `rm`/`sudo`/`curl`
          // inside it is caught with its own trail.
          for (const sub of analyzeShellAst(inline.code, 1).records) {
            if (sub.command === '__max_depth_exceeded__' || sub.command === '__pipe_stdin_shell__') continue;
            const subBlocked = sub.trail.find((c) => blockedSet.has(c));
            if (subBlocked) {
              addFinding('CAP-CMD-01', 'critical', `Blocked command "${subBlocked}" inside inline ${rec.command} code`,
                `Hidden command "${subBlocked}" found inside inline payload [${[...rec.trail, 'inline'].join(' -> ')}].`,
                [...rec.trail, 'inline'], 'Do not run interpreters on inline code that wraps blocked commands.');
            }
            const subUrl = extractUrlsAndHosts(sub.args.join(' '));
            if (policy.blockPrivateIps && subUrl.some((u) => isPrivateOrInternalHost(u.host))) {
              addFinding('CAP-SSRF-01', 'critical', `SSRF inside inline ${rec.command} code`,
                'Inline payload references an internal host.', [...rec.trail, 'inline'],
                'Disallow outbound requests to internal/metadata addresses.');
            }
          }
        }
      }

      // Module-import execution (`python3 -m pkg`, `perl -MEvil`): importing an
      // unvetted module runs its top-level code. Escalate for human review.
      const modImport = extractModuleImport(rec);
      if (modImport && !policy.allowInlineCode) {
        addFinding('CAP-CMD-06', 'medium', `Module import execution in "${rec.command}"`,
          `${rec.command} -m imports and runs module code that is not in the policy (${modImport.module || 'unnamed'}).`,
          rec.trail, 'Import only audited modules, or add the specific module to an explicit allowlist.');
      }

      // Special check: git push / send-pack / dangerous git config manipulation
      if (rec.command === 'git') {
        const { subcommand, rest } = findGitSubcommand(rec.args);
        // Remote URLs in clone/fetch/pull/push/submodule args are never passed
        // through the network-tool URL checks: inspect their hosts directly.
        for (const a of rec.args) {
          for (const cand of gitRemoteHostCandidates(a)) {
            if (policy.blockPrivateIps && isPrivateOrInternalHost(cand)) {
              addFinding('CAP-SSRF-01', 'critical', `SSRF internal/metadata target via git remote`,
                `git remote "${a.slice(0, 60)}" resolves to an internal or metadata address.`,
                rec.trail, 'Do not fetch from internal or metadata hosts.');
            }
          }
        }
        // `--upload-pack`/`-u` on clone/fetch-pack names the local program
        // git execs to speak the protocol; `ext::` transports run a shell
        // command outright. `-u` on other subcommands (`branch -u`,
        // `push -u`, `fetch -u`) is an unrelated option.
        const packSub = subcommand === 'clone' || subcommand === 'fetch-pack';
        for (let i = 0; i < rec.args.length; i++) {
          const a = rec.args[i];
          if (packSub && (/^(?:--upload-pack|-u)(?:=|$)/.test(a) || /^(?:--exec|-e)(?:=|$)/.test(a))) {
            const val = a.includes('=') ? a.slice(a.indexOf('=') + 1) : (rec.args[i + 1] || '');
            addFinding('CAP-GIT-03', 'high', 'git upload-pack selector runs a local program',
              `"${String(val).slice(0, 60)}" in [${rec.trail.join(' -> ')}] is executed by git as the remote protocol program.`,
              rec.trail, 'Do not override upload-pack/receive-pack programs from tool calls.');
          }
          if (a.startsWith('ext::')) {
            addFinding('CAP-GIT-03', 'critical', 'git ext:: transport runs a shell command',
              `Remote "${a.slice(0, 60)}" at [${rec.trail.join(' -> ')}] executes its transport string as a shell command.`,
              rec.trail, 'Do not use ext:: git transports; they execute arbitrary commands.');
          }
        }
        // `git archive --remote=` contacts a remote daemon outside the URL
        // checks; inspect the host and hold the remote channel itself.
        if (subcommand === 'archive') {
          for (let i = 0; i < rec.args.length; i++) {
            const a = rec.args[i];
            if (a === '--remote' || a.startsWith('--remote=')) {
              const val = a.includes('=') ? a.slice(a.indexOf('=') + 1) : (rec.args[i + 1] || '');
              addFinding('CAP-NET-01', 'high', 'git archive reaches a remote daemon',
                `git archive --remote "${String(val).slice(0, 60)}" at [${rec.trail.join(' -> ')}] contacts a remote git daemon outside the network checks.`,
                rec.trail, 'Archive from local refs instead of remote daemons.');
              for (const cand of gitRemoteHostCandidates(val)) {
                if (policy.blockPrivateIps && isPrivateOrInternalHost(cand)) {
                  addFinding('CAP-SSRF-01', 'critical', 'SSRF via git archive --remote host',
                    `git archive --remote "${String(val).slice(0, 60)}" resolves to an internal or metadata address.`,
                    rec.trail, 'Do not reach remote git archives from tool calls.');
                }
              }
            }
          }
        }
        if ((subcommand === 'push' || subcommand === 'send-pack') && !rest.includes('--dry-run') && !rest.includes('-n')) {
          addFinding('CAP-GIT-01', 'high', `Remote git ${subcommand} requires human review`,
            `${subcommand} detected in [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Stage commits locally and request human approval before pushing.');
        } else if (subcommand === 'config' && rest.some((a) => GIT_DANGEROUS_CONFIG_KEYS.test(a))) {
          addFinding('CAP-GIT-01', 'high', 'Git execution hook/alias configuration requires human review',
            `git config modification detected in [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Do not mutate executable git hooks, aliases, pagers, or credential helpers dynamically.');
        } else if (subcommand === 'worktree' && rest[0] && rest[0] !== 'list') {
          // worktree add/remove/move check out trees and run post-checkout hooks.
          addFinding('CAP-GIT-02', 'medium', `git worktree ${rest[0]} executes repository hooks`,
            `git worktree ${rest[0]} runs checkout hooks that may execute repo code.`,
            rec.trail, 'Run hook-executing git subcommands only after the hook scripts are reviewed.');
        } else if (subcommand === 'submodule' && rest[0] === 'foreach') {
          // `submodule foreach '<shell>'` runs the string in every submodule:
          // a command channel invisible to the wrapper unwrap.
          const payload = rest.slice(1).filter((a) => !a.startsWith('-')).join(' ');
          addFinding('CAP-GIT-03', 'high', 'git submodule foreach runs a shell command per submodule',
            `git submodule foreach at [${rec.trail.join(' -> ')}] executes the given shell string inside each submodule.`,
            rec.trail, 'Do not run git submodule foreach from tool calls.');
          for (const sub of analyzeShellAst(payload, 2).records) {
            const payloadHit = (sub.trail || []).find((c) => blockedSet.has(c)) ||
              (blockedSet.has(sub.command) ? sub.command : null);
            if (payloadHit) {
              addFinding('CAP-GIT-03', 'critical', `git submodule foreach payload runs "${payloadHit}"`,
                `foreach shell at [${rec.trail.join(' -> ')}] contains blocked command "${payloadHit}".`,
                rec.trail, 'Do not run git submodule foreach from tool calls.');
              break;
            }
          }
        } else if (subcommand === 'submodule' && ['update', 'add'].includes(rest[0])) {
          addFinding('CAP-GIT-02', 'medium', `git submodule ${rest[0]} checks out hook-running trees`,
            `git submodule ${rest[0]} runs checkout hooks inside submodules.`,
            rec.trail, 'Review submodule hook scripts before updating.');
        } else if (subcommand === 'remote') {
          // `remote add/set-url` rewrites where objects come from (future
          // egress), `remote update/prune/show` contacts remotes now; bare
          // `remote`/`get-url`/`list` only read config.
          const verb = rest.find((a) => !a.startsWith('-')) || '';
          if (['add', 'set-url', 'set-branches', 'set-head', 'remove', 'rename', 'update', 'prune', 'show'].includes(verb)) {
            addFinding('CAP-GIT-02', 'medium', `git remote ${verb} mutates or contacts remotes`,
              `git remote ${verb} at [${rec.trail.join(' -> ')}] changes remote URLs or performs network egress.`,
              rec.trail, 'Keep remote configuration inside the reviewed baseline.');
          }
        } else if (GIT_EGRESS_SUBCOMMANDS.has(subcommand)) {
          // fetch/fetch-pack/ls-remote pull objects or ref advertisements
          // from a remote: network egress the generic URL scan cannot see.
          addFinding('CAP-NET-01', 'medium', `git ${subcommand} performs remote egress`,
            `git ${subcommand} at [${rec.trail.join(' -> ')}] contacts a remote; allowNetwork is off.`,
            rec.trail, 'Keep the tree offline or add the host to allowedDomains.');
        } else if (subcommand === 'clean') {
          addFinding('CAP-GIT-02', 'medium', `git clean deletes untracked files`,
            `git clean at [${rec.trail.join(' -> ')}] removes untracked paths permanently.`,
            rec.trail, 'List the paths and remove them with an explicit reviewed command.');
        } else if (subcommand === 'hook' && rest[0] === 'run') {
          addFinding('CAP-GIT-03', 'high', `git hook run executes a repository hook`,
            `git hook run at [${rec.trail.join(' -> ')}] executes the named hook directly.`,
            rec.trail, 'Do not run repository hooks from tool calls.');
        } else if (subcommand === 'grep' && rest.some((a) => a === '-O' || a.startsWith('--open-files-in-pager'))) {
          addFinding('CAP-GIT-02', 'medium', `git grep -O pipes matches into the pager`,
            `git grep -O at [${rec.trail.join(' -> ')}] runs the configured pager on every match.`,
            rec.trail, 'Do not open pager channels from tool calls.');
        } else if (subcommand === 'apply' && rest.includes('--unsafe-paths')) {
          addFinding('CAP-GIT-02', 'medium', `git apply --unsafe-paths bypasses the worktree check`,
            `--unsafe-paths at [${rec.trail.join(' -> ')}] lets a patch write outside the worktree.`,
            rec.trail, 'Apply only patches that stay inside the worktree.');
        } else if (subcommand === 'bisect' && rest.includes('run')) {
          // `git bisect run <cmd>` executes an arbitrary command at every step.
          addFinding('CAP-GIT-03', 'high', 'git bisect run executes an arbitrary command per step',
            `git bisect run at [${rec.trail.join(' -> ')}] shells out to a caller-supplied command.`,
            rec.trail, 'Do not run scripted bisects from tool calls.');
        } else if (subcommand === 'stash' && rest[0] && GIT_STASH_MUTATING.has(rest[0])) {
          addFinding('CAP-GIT-02', 'medium', `git stash ${rest[0]} runs merge machinery`,
            `git stash ${rest[0]} merges trees and can run hooks.`,
            rec.trail, 'Review stash hook scripts before applying.');
        } else if (subcommand && GIT_PROGRAM_SUBCOMMANDS.has(subcommand)) {
          // shell/fast-import/svn/p4/imap-send and the protocol daemons run
          // helper programs or command channels outside the inspected line.
          addFinding('CAP-GIT-03', 'high', `git ${subcommand} runs a helper program or command channel`,
            `git ${subcommand} at [${rec.trail.join(' -> ')}] executes helper/protocol code outside the inspected command line.`,
            rec.trail, 'Do not run git helper daemons or command-string subcommands from tool calls.');
        } else if (subcommand && GIT_HOOK_SUBCOMMANDS.has(subcommand)) {
          // commit/merge/rebase/pull/am/checkout/clone all execute repo hooks
          // and can run attacker-controlled code if hooks were tampered with.
          addFinding('CAP-GIT-02', 'medium', `git ${subcommand} executes repository hooks`,
            `git ${subcommand} runs commit/merge/checkout hooks that may execute arbitrary repo code.`,
            rec.trail, 'Run hook-executing git subcommands only after the hook scripts are reviewed.');
        }

        // `git -c key=value ...` (and `-c=key=value`, `--config-env=key=VAR`)
        // can set core.pager / alias to a shell command.
        for (let i = 0; i < rec.args.length; i++) {
          const a = rec.args[i];
          if (a === '-c' || a.startsWith('-c')) {
            let assignment = a === '-c' ? rec.args[i + 1] || '' : a.slice(2);
            if (assignment.startsWith('=')) assignment = assignment.slice(1);
            const key = assignment.split('=')[0];
            if (GIT_DANGEROUS_CONFIG_KEYS.test(key)) {
              addFinding('CAP-GIT-01', 'high', `git -c ${key} overrides executable config`,
                `git -c assignment [${rec.trail.join(' -> ')}] sets a hook/pager/alias key.`,
                rec.trail, 'Avoid -c overrides of pager, editor, alias, or credential keys.');
            }
          }
          if (a === '--config-env') {
            const key = (rec.args[i + 1] || '').split('=')[0];
            if (GIT_DANGEROUS_CONFIG_KEYS.test(key)) {
              addFinding('CAP-GIT-01', 'high', `git --config-env ${key} overrides executable config`,
                `git --config-env [${rec.trail.join(' -> ')}] sets a hook/pager/alias key.`,
                rec.trail, 'Avoid config-env overrides of pager, editor, alias, or credential keys.');
            }
          }
          if (a.startsWith('--config-env=')) {
            const key = a.slice('--config-env='.length).split('=')[0];
            if (GIT_DANGEROUS_CONFIG_KEYS.test(key)) {
              addFinding('CAP-GIT-01', 'high', `git --config-env ${key} overrides executable config`,
                `git --config-env [${rec.trail.join(' -> ')}] sets a hook/pager/alias key.`,
                rec.trail, 'Avoid config-env overrides of pager, editor, alias, or credential keys.');
            }
          }
          // --exec-path redirects where git finds its subcommands: an
          // attacker-controlled directory there runs arbitrary "git-*" tools.
          if (/^--exec-path/.test(a)) {
            addFinding('CAP-GIT-03', 'high', 'git --exec-path redirects subcommand resolution',
              `git --exec-path in [${rec.trail.join(' -> ')}] can substitute attacker-controlled git-* binaries.`,
              rec.trail, 'Do not override git exec-path from tool calls.');
          }
          // Also flag values that carry shell metacharacters into a pager/alias.
          if (/^core\.pager=|^alias\./i.test(a) && SHELL_META_RE.test(a)) {
            addFinding('CAP-GIT-01', 'high', 'Git pager/alias value contains shell metacharacters',
              `Config value "${a}" in [${rec.trail.join(' -> ')}] can execute shell code.`,
              rec.trail, 'Keep pager and alias values free of ; | & ` $ and parentheses.');
          }
        }
      }
    }
  }

  // Deduplicate identical ruleId + trail findings
  const seenKey = new Set();
  const deduped = [];
  for (const f of findings) {
    const k = `${f.ruleId}|${f.trail.join('>')}|${f.title}`;
    if (!seenKey.has(k)) {
      seenKey.add(k);
      deduped.push(f);
    }
  }

  const hasCritical = deduped.some((f) => f.severity === 'critical');
  const hasHigh = deduped.some((f) => f.severity === 'high');
  const hasMedium = deduped.some((f) => f.severity === 'medium');

  let decision = 'ALLOW';
  if (hasCritical || hasHigh) decision = 'DENY';
  else if (hasMedium) decision = 'ESCALATE';

  const riskScore = Math.min(100, deduped.reduce((sum, f) => (
    sum + (f.severity === 'critical' ? 45 : f.severity === 'high' ? 30 : 15)
  ), 0));

  return {
    tool,
    decision,
    blocked: decision !== 'ALLOW',
    riskScore,
    findingCount: deduped.length,
    findings: deduped,
    ast,
    safeRewrite: synthesizeSafeRewrite(toolCall, deduped, policy),
  };
}

/**
 * awk program text that runs or loads code: system(), @include/@load
 * directives, `cmd | getline` reads, and `print > "cmd"` / `print | "cmd"`
 * writes are all execution channels inside an otherwise-plain arg.
 */
const AWK_EXEC_SCRIPT_RE = /(?:\bsystem\s*\(|@include\b|@load\b|\bgetline\b[^;\n]*[|<]|\b(?:print|printf)\b[^;\n]*[|>])/;

const AWK_FILE_FLAGS = new Set(['-f', '--file', '-i', '--include', '--exec']);
const AWK_SKIP_VALUE_FLAGS = new Set(['-e', '--source', '-v', '--assign', '-F', '--field-separator', '-W', '-d', '--dump-variables']);

function checkAwkArgs(rec, addFinding) {
  const scriptParts = [];
  let loadsFile = false;
  for (let i = 0; i < rec.args.length; i++) {
    const a = rec.args[i];
    if (a === '--') break;
    if (AWK_FILE_FLAGS.has(a)) {
      loadsFile = true;
      i += 1;
      continue;
    }
    if (/^-(?:f|i)\S/.test(a) || a.startsWith('--file=') || a.startsWith('--include=') || a.startsWith('--exec=')) {
      loadsFile = true;
      continue;
    }
    if (AWK_SKIP_VALUE_FLAGS.has(a)) {
      i += 1;
      continue;
    }
    if (a.startsWith('-')) continue;
    scriptParts.push(a);
  }
  const scriptText = scriptParts.join(' ');
  if (loadsFile) {
    addFinding('CAP-CMD-03', 'high', `awk loads program text from a file flag`,
      `awk at [${rec.trail.join(' -> ')}] runs script or library contents from an uninspected file.`,
      rec.trail, 'Inline a reviewed awk program or use an explicit allowlisted command.');
    return;
  }
  if (AWK_EXEC_SCRIPT_RE.test(scriptText)) {
    addFinding('CAP-CMD-03', 'high', `awk program text contains an execution channel`,
      `awk script at [${rec.trail.join(' -> ')}] uses system(), @include/@load, or a pipe redirect that runs uninspected code.`,
      rec.trail, 'Replace awk system()/pipe calls with an explicit allowlisted command.');
  }
}

const GIT_GLOBAL_VALUE_FLAGS = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env']);

/** Keys whose git config value can execute code or redirect a hook. */
const GIT_DANGEROUS_CONFIG_KEYS = /^(?:alias\.|core\.(?:sshcommand|sshvariant|fsmonitor|pager|editor|askpass|excludesfile|attributesfile|hookspath|hooksdir|browser|gitproxy)|credential\.|pager\.|diff\.(?:external|[^.\s]+\.(?:command|textconv|cachetextconv))|textconv\.|filter\.|merge\.(?:driver|tool|[^.\s]+\.(?:driver|recursive))|sendemail\.|http\.(?:proxy|sslverify|sslcainfo|sslcapath)|url\.|include\.?|includeif\.|protocol\.|init\.templatedir|maintenance\.|tar\.[^.\s]+\.command|interactive\.|lfs\.|submodule\.[^.\s]+\.(?:update|command)|remote\.[^.\s]+\.(?:proxy|helper|uploadpack|receivepack|pushproxy)|gpg\.(?:program|ssh\.|openpgp\.|x509\.)|help\.manviewer|instaweb\.|browser\.|web\.browser|man\.viewer|difftool\.|mergetool\.|diff\.tool|sequence\.editor|imap\.|sendmail\.)/i;

/** Git subcommands that execute hooks, merge machinery, external tools, or patch scripts. */
const GIT_HOOK_SUBCOMMANDS = new Set([
  'commit', 'merge', 'rebase', 'pull', 'am', 'rebase--interactive',
  'filter-branch', 'checkout', 'switch', 'clone', 'restore',
  'cherry-pick', 'revert', 'difftool', 'mergetool', 'instaweb',
  'send-email', 'notes', 'replace', 'bundle', 'daemon', 'credential',
  'credential-cache', 'credential-store', 'credential-cache--daemon',
]);

/** git stash verbs that run merge machinery and hooks. */
const GIT_STASH_MUTATING = new Set(['pop', 'apply', 'drop', 'clear', 'save', 'branch', 'create', 'store', 'push']);

/**
 * Git subcommands that execute helper programs or command channels directly:
 * `git shell -c` runs protocol commands, fast-import consumes a scripted
 * stream, svn/p4/imap-send exec helper programs, and the *-pack/archive
 * daemons expose repo protocol endpoints.
 */
const GIT_PROGRAM_SUBCOMMANDS = new Set([
  'shell', 'fast-import', 'imap-send', 'http-backend', 'cvsserver',
  'upload-pack', 'receive-pack', 'upload-archive', 'svn', 'p4',
  'index-pack', 'pack-objects',
  // The remote-<scheme> helpers are protocol transports git execs; nobody
  // types them directly, and `remote-ext`/`remote-fd`/`remote-testgit` run
  // command strings passed as arguments.
  'remote-https', 'remote-http', 'remote-ftp', 'remote-ftps',
  'remote-fd', 'remote-ext', 'remote-testgit',
]);

/** Git subcommands that contact remotes: egress outside the URL host scan. */
const GIT_EGRESS_SUBCOMMANDS = new Set(['fetch', 'fetch-pack', 'ls-remote']);

/**
 * Interpreters that can run arbitrary inline code from a flag argument.
 * Each entry lists the flags that carry executable code or a module/script name.
 * `inlineFlag` means "the next argument is code"; `moduleFlag` means "the next
 * argument is a module name whose import executes".
 */
const INLINE_INTERPRETERS = new Map([
  ['python', ['-c', '--command']],
  ['python3', ['-c', '--command']],
  ['node', ['-e', '--eval', '-p', '--print']],
  ['ruby', ['-e']],
  ['perl', ['-e', '-E']],
  ['php', ['-r', '-f']],
  ['lua', ['-e']],
  ['Rscript', ['-e']],
  ['deno', ['eval', 'run']],
  ['bun', ['-e', 'run']],
]);

/** Flags whose `--flag=value` attached form also carries code/module. */
const INLINE_INTERPRETER_EQ_FLAGS = new Map([
  ['python', ['--command=']],
  ['python3', ['--command=']],
  ['node', ['--eval=', '--print=']],
  ['php', ['-r=']],
]);

/** Module-import flags: the argument names a module whose import executes code. */
const MODULE_IMPORT_FLAGS = new Map([
  ['python', ['-m', '--module']],
  ['python3', ['-m', '--module']],
  ['perl', ['-M']],
  ['ruby', ['-r']],
  ['lua', ['-l']],
  // node preloads run arbitrary local modules before the main script:
  // `-r`/`--require`, `--import`, `--loader`, `--experimental-loader`.
  ['node', ['-r', '--require', '--import', '--loader', '--experimental-loader']],
]);

/** npm flags that redirect the package context being inspected. */
const NPM_CONTEXT_FLAGS = new Set(['--prefix', '--userconfig', '--globalconfig', '--cache', '--registry']);

/** npm subcommands that run dependency or package-defined code. */
const NPM_CODE_SUBCOMMANDS = new Set([
  'install', 'i', 'add', 'ci', 'create', 'init', 'exec', 'x', 'link',
  'rebuild', 'update', 'stop', 'restart', 'version', 'pack', 'publish',
  'explore', 'edit', 'hook', 'uninstall', 'unlink', 'un', 'prune', 'dedupe',
  'audit', 'fund', 'bugs', 'docs', 'repo', 'star', 'unstar', 'access',
  'adduser', 'login', 'logout', 'token', 'profile', 'team', 'org',
  'deprecate', 'dist-tag', 'ping', 'shrinkwrap', 'sbom', 'explain', 'dlx',
  // `unpublish` yanks published package versions; read-only-looking
  // subcommands still hit the registry: they are network egress the offline
  // policy never authorized.
  'unpublish', 'view', 'v', 'info', 'show', 'search', 's', 'outdated', 'ls-remote',
]);

/** npm subcommands that mutate config or open an editor/browser. */
const NPM_MUTATING_SUBS = new Set(['config', 'c', 'edit', 'explore', 'hook', 'pkg']);

/** Flags forwarded after `npm <script> --` that load code into the runner. */
const NPM_PASSTHROUGH_DANGER = /^(?:-r|--require|--import|--loader|--experimental-loader|--eval|-e|--print|--inspect)/;

/**
 * If a command is an interpreter carrying inline code (or an `npm run`/`npx`
 * script), return the code payload and a human label. Otherwise null.
 */
function extractInlineCode(rec) {
  if (!rec || !rec.command) return null;
  const cmd = rec.command;
  const args = rec.args || [];

  if (cmd === 'npm' || cmd === 'npx' || cmd === 'pnpm' || cmd === 'yarn') {
    // `npm <script> -- <args>` forwards the tail to the underlying runner:
    // `npm test -- --require=/tmp/evil` becomes `node --test --require=...`
    // and preloads arbitrary code even though `npm test` itself is exempt.
    const ddIdx = args.indexOf('--');
    if (ddIdx >= 0) {
      const bad = args.slice(ddIdx + 1).find((a) => NPM_PASSTHROUGH_DANGER.test(String(a)));
      if (bad) {
        return { kind: 'npm-script', code: `runner passthrough flag ${bad}`, command: cmd };
      }
    }
    // `npm run <script>`, `npm test`, `npx <pkg>` execute package-defined code.
    // `npm test` and `npm start` are conventional safe entrypoints; an arbitrary
    // `npm run <name>` or `npx <pkg>` runs unknown code and must escalate.
    const runIdx = args.findIndex((a) => a === 'run' || a === 'run-script');
    if (runIdx >= 0) {
      const scriptName = args[runIdx + 1] || '';
      if (['test', 'start'].includes(scriptName)) return null;
      return { kind: 'npm-script', code: `package script: ${scriptName || 'default'}`, command: cmd };
    }
    // Context redirects: --prefix/--userconfig/--cache/--registry point npm
    // at a different package tree, config file, or registry than reviewed.
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      const eq = a.indexOf('=');
      const name = eq > 0 ? a.slice(0, eq) : a;
      if (NPM_CONTEXT_FLAGS.has(name)) {
        const val = eq > 0 ? a.slice(eq + 1) : (args[i + 1] || '');
        return { kind: 'npm-script', code: `redirected npm context via ${name} ${String(val).slice(0, 40)}`, command: cmd };
      }
    }
    // `npm install`, `npm ci`, `npm create`, `npm exec`, ... run dependency
    // lifecycle scripts: the standard supply-chain code-execution vector.
    const subIdx = args.findIndex((a) => !a.startsWith('-'));
    if (subIdx >= 0) {
      const sub = args[subIdx];
      if (NPM_MUTATING_SUBS.has(sub)) {
        // `npm config get x` is a read; set/delete/edit mutate execution config.
        const verb = args[subIdx + 1] || '';
        if (sub === 'config' || sub === 'c') {
          if (['set', 'delete', 'edit', 'rm'].includes(verb)) {
            return { kind: 'npm-script', code: `npm config ${verb} mutates execution settings`, command: cmd };
          }
        } else if (sub === 'pkg') {
          // `pkg set|fix|delete` rewrites package.json (scripts, bin, deps);
          // `pkg get` only reads.
          if (['set', 'fix', 'delete'].includes(verb)) {
            return { kind: 'npm-script', code: `npm pkg ${verb} mutates package.json`, command: cmd };
          }
        } else {
          return { kind: 'npm-script', code: `npm ${sub} runs package-defined code or opens an editor`, command: cmd };
        }
      }
      if (NPM_CODE_SUBCOMMANDS.has(sub)) {
        const target = args[subIdx + 1] || 'dependencies';
        return { kind: 'npm-script', code: `lifecycle scripts for ${target}`, command: cmd };
      }
    }
    if (cmd === 'npx' || cmd === 'pnpm' || cmd === 'yarn') {
      const firstNonFlag = args.find((a) => !a.startsWith('-'));
      if (firstNonFlag && !['test', 'start'].includes(firstNonFlag)) {
        return { kind: 'npm-script', code: `package: ${firstNonFlag}`, command: cmd };
      }
    }
    if (args.includes('test') || args.includes('start')) return null;
  }

  const flags = INLINE_INTERPRETERS.get(cmd);
  if (!flags) return null;
  const eqFlags = INLINE_INTERPRETER_EQ_FLAGS.get(cmd) || [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (flags.includes(a)) {
      const code = args[i + 1] || '';
      return { kind: 'inline', code, command: cmd };
    }
    for (const ef of eqFlags) {
      if (a.startsWith(ef)) {
        return { kind: 'inline', code: a.slice(ef.length), command: cmd };
      }
    }
    // Combined short flag like `-cCODE` (python3 -c"code")
    for (const f of flags) {
      if (f.startsWith('-') && !f.startsWith('--') && a.startsWith(f) && a.length > f.length) {
        return { kind: 'inline', code: a.slice(f.length), command: cmd };
      }
    }
  }
  // php `-d key=value` ini injection: auto_prepend_file loads a PHP file
  // before the main script, extension= loads a shared object.
  if (cmd === 'php') {
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-d' || a === '--define') {
        const val = args[i + 1] || '';
        if (/auto_(?:prepend|append)_file|^extension\s*=|^include_path\s*=/i.test(val)) {
          return { kind: 'inline', code: `php ini injection: ${val}`, command: cmd };
        }
      }
      if (a.startsWith('-d') && a.length > 2) {
        const val = a.slice(2);
        if (/auto_(?:prepend|append)_file|^extension\s*=|^include_path\s*=/i.test(val)) {
          return { kind: 'inline', code: `php ini injection: ${val}`, command: cmd };
        }
      }
    }
  }
  return null;
}

/**
 * Module-import execution (`python3 -m pkg`, `perl -MEvil`, `ruby -revil`).
 * Importing a module runs its top-level code, so an unvetted module name is an
 * escalation, never a silent allow.
 */
function extractModuleImport(rec) {
  const cmd = rec?.command;
  const flags = MODULE_IMPORT_FLAGS.get(cmd);
  if (!flags) return null;
  const args = rec.args || [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (flags.includes(a)) return { module: args[i + 1] || '', command: cmd };
    // `--require=/path`, `--import=./mod.js`, `-r./mod` attached forms.
    for (const f of flags) {
      if (f.startsWith('--') && a.startsWith(`${f}=`)) {
        return { module: a.slice(f.length + 1), command: cmd };
      }
      if (f.startsWith('-') && !f.startsWith('--') && a.startsWith(f) && a.length > f.length) {
        return { module: a.slice(f.length), command: cmd };
      }
    }
  }
  return null;
}

/** Shell metacharacters that indicate a git config value would execute code. */
const SHELL_META_RE = /[;&|`$()<>{}()\n]/;

function findGitSubcommand(args) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') break;
    if (GIT_GLOBAL_VALUE_FLAGS.has(a)) {
      i += 1;
      continue;
    }
    if (a.startsWith('-')) continue;
    return { subcommand: a, rest: args.slice(i + 1) };
  }
  return { subcommand: null, rest: [] };
}

function synthesizeSafeRewrite(toolCall, findings, policy) {
  if (findings.length === 0) return null;
  if (toolCall.tool === 'fs_read' || toolCall.tool === 'fs_write') {
    return {
      tool: toolCall.tool,
      args: { path: `${policy.workspaceRoot}/src/index.js` },
      note: 'Scoped safely inside workspaceRoot without traversal or secret targets.',
    };
  }
  if (toolCall.tool === 'http_fetch') {
    return {
      tool: 'http_fetch',
      args: { url: `https://${policy.allowedDomains[0]}/status` },
      note: 'Restricted to allowlisted public HTTPS domain.',
    };
  }
  return {
    tool: 'shell_exec',
    args: { command: `ls -la ${policy.workspaceRoot} && npm test` },
    note: 'Replaced wrapped/unsafe command with flat, allowlisted workspace verification.',
  };
}

/**
 * Comparator Baseline 1: Naive raw substring/regex blocklist.
 */
export function evaluateNaiveRegex(toolCall) {
  const raw = JSON.stringify(toolCall || {});
  const hits = [];
  if (/\brm\s+-rf\b/i.test(raw)) hits.push('naive-rm-rf');
  if (/\bsudo\b/i.test(raw)) hits.push('naive-sudo');
  if (/169\.254\.169\.254|127\.0\.0\.1|localhost/i.test(raw)) hits.push('naive-ip');
  if (/\/etc\/passwd|\/etc\/shadow|\.ssh\/id_rsa/i.test(raw)) hits.push('naive-secret-path');
  if (/\.\.\//.test(raw)) hits.push('naive-dotdot');
  return {
    blocked: hits.length > 0,
    hits,
  };
}

/**
 * Comparator Baseline 2: Flat first-token command check (no wrapper/heredoc unwrapping, no IP encoding decode).
 */
export function evaluateFlatGate(toolCall, policyInput = DEFAULT_POLICY) {
  const policy = { ...DEFAULT_POLICY, ...policyInput };
  const blocked = new Set(policy.blockedCommands);
  if (toolCall?.tool === 'fs_read' || toolCall?.tool === 'fs_write') {
    const p = String(toolCall.args?.path || '');
    return { blocked: p.includes('..') || isSensitivePath(p) };
  }
  if (toolCall?.tool === 'http_fetch') {
    const u = String(toolCall.args?.url || '');
    return { blocked: /127\.0\.0\.1|169\.254\.169\.254|localhost/i.test(u) };
  }
  const cmd = String(toolCall?.args?.command || '').trim();
  const first = cmd.split(/\s+/)[0]?.split('/').pop() || '';
  return { blocked: blocked.has(first) };
}

export function buildSarifReport(caseEvaluations) {
  const rules = [];
  const ruleIndexById = new Map();
  const results = [];
  for (const item of caseEvaluations) {
    for (const f of item.capgate.findings) {
      const level = f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning';
      if (!ruleIndexById.has(f.ruleId)) {
        ruleIndexById.set(f.ruleId, rules.length);
        rules.push({
          id: f.ruleId,
          shortDescription: { text: f.title },
          defaultConfiguration: { level },
        });
      }
      results.push({
        ruleId: f.ruleId,
        ruleIndex: ruleIndexById.get(f.ruleId),
        level,
        message: { text: `${item.id}: ${f.title} - ${f.detail}` },
        properties: {
          decision: item.capgate.decision,
          trail: f.trail,
          suggestion: f.suggestion,
        },
      });
    }
  }
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'CapGate',
          version: '1.1.0',
          informationUri: 'https://github.com/draarivpatel-ui/capgate',
          rules,
        },
      },
      results,
    }],
  };
}
