/**
 * CapGate recursive POSIX-like shell tokenizer, wrapper unwrapper,
 * heredoc collector, and embedded script extractor.
 * Pure ES module (browser and Node compatible, zero external deps).
 */

export const SHELL_BINARIES = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash']);

/**
 * Interpreters that compile and run program text fed on stdin (heredoc, pipe,
 * or `< file` redirect) or named by `-`. Like `bash -s`, an interpreter with
 * no script argument reads its program from stdin. (The awk family and java
 * read *data* from stdin, so they are deliberately absent.)
 */
export const STDIN_INTERPRETERS = new Set([
  'python', 'python2', 'python3', 'node', 'ruby', 'perl', 'php', 'lua', 'Rscript',
  'deno', 'bun', 'jshell', 'ghci', 'fish', 'yash', 'osh', 'oil', 'elvish',
]);

export const WRAPPER_VALUE_FLAGS = new Map([
  ['env', new Set(['-u', '--unset', '-C', '--chdir'])],
  ['timeout', new Set(['-k', '--kill-after', '-s', '--signal'])],
  ['nice', new Set(['-n', '--adjustment'])],
  ['ionice', new Set(['-c', '--class', '-n', '--classdata', '-p', '--pid', '-P', '--pgid', '-u', '--uid'])],
  ['stdbuf', new Set(['-i', '--input', '-o', '--output', '-e', '--error'])],
  ['xargs', new Set(['-n', '--max-args', '-L', '--max-lines', '-P', '--max-procs', '-I', '--replace', '-d', '--delimiter', '-s', '--max-chars', '-a', '--arg-file', '-E', '--eof'])],
  ['exec', new Set(['-a'])],
  ['sudo', new Set(['-u', '--user', '-g', '--group', '-C', '--close-from', '-h', '--host', '-p', '--prompt', '-r', '--role', '-t', '--type'])],
  ['unshare', new Set(['--map-user', '--setgroups'])],
  ['nsenter', new Set(['-t', '--target', '-S', '--setuid', '--setgid', '-r', '--root', '-w', '--wd'])],
  ['doas', new Set(['-u', '-C'])],
  ['pkexec', new Set()],
  ['run0', new Set(['--uid', '--gid'])],
  ['setpriv', new Set(['--reuid', '--regid', '--groups', '--inh-caps', '--bounding-set', '--selinux-label', '--apparmor-profile', '--ruid', '--euid', '--rgid', '--egid'])],
  ['proxychains', new Set(['-f', '--config'])],
  ['proxychains4', new Set(['-f', '--config'])],
  ['tsocks', new Set()],
  ['taskset', new Set(['-c', '--cpu-list', '-p', '--pid'])],
  ['numactl', new Set(['--cpunodebind', '--membind', '--physcpubind', '--preferred', '-C', '-m'])],
  ['chrt', new Set(['-p', '-P', '-T', '-D', '-N'])],
  ['cpulimit', new Set(['-l', '--limit', '-i', '--interval'])],
  ['watch', new Set(['-n', '--interval'])],
  ['script', new Set(['-c', '--command', '--log-in', '--log-out', '--log-timing', '-T', '--log-timing'])],
  ['flock', new Set(['-w', '--timeout', '-E', '--conflict-exit-code', '--fcntl'])],
  ['ssh-agent', new Set(['-a', '-t'])],
  ['firejail', new Set()],
  ['systemd-run', new Set(['--property', '-p', '--uid', '--gid', '--unit', '--description', '--slice', '--service-type', '--working-directory', '-d', '--setenv', '--pipe', '--expand-environment', '--file-system', '--namespace', '--machine', '-M', '--image', '--root-directory', '--root-prefix', '--image-policy', '--set-credential', '--set-credential-encrypted', '--ssh-key', '--ssh-authorized-keys', '--ssh-host-key', '--ssh-known-hosts', '--ssh-permit-root-login', '--ssh-permit-user-root-login', '--ssh-certificate', '--ssh-trusted-certificate-authority', '--ssh-revoke-certificate', '--selinux-apit-context', '--selinux-role', '--selinux-type', '--selinux-user', '--app-profile', '--apparmor-profile', '--smack-process-label', '--keyring-mode', '--timer-property', '--path-property', '--socket-property', '--mount-property', '--swap-property', '--device-property', '--automount-property', '--slice-property', '--scope-property', '--service-property', '--target', '--on-active', '--on-boot', '--on-startup', '--on-unit-active', '--on-unit-inactive', '--on-calendar', '--accuracy', '--randomized-delay', '--fixed-random-delay', '--nice', '--cpus-percentage', '--memory-max', '--tasks-max', '--timer-property'])],
  ['coproc', new Set()],
  ['chroot', new Set(['--userspec', '--users', '--groups', '-u'])],
]);

/** Wrappers that consume N leading operands (lock file, target dir, user) before the real command. */
export const WRAPPER_OPERAND_COUNT = new Map([
  ['chroot', 1],
  ['setuidgid', 1],
  ['envuidgid', 1],
  ['taskset', 1],
  ['flock', 1],
  ['repeat', 1],
]);

export const SIMPLE_WRAPPERS = new Set([
  'env', 'nohup', 'setsid', 'timeout', 'nice', 'ionice', 'stdbuf',
  'time', 'command', 'builtin', 'exec', 'xargs', 'sudo',
  'unshare', 'nsenter', 'doas', 'pkexec', 'run0', 'setpriv',
  'linux32', 'linux64', 'eatmydata', 'proxychains', 'proxychains4',
  'tsocks', 'daemon', 'chroot', 'setuidgid', 'envuidgid', 'taskset',
  'numactl', 'chrt', 'cpulimit', 'busybox', 'toybox',
  'flock', 'ssh-agent', 'firejail', 'systemd-run', 'coproc',
  'noglob', 'nocorrect', 'repeat',
]);

/** Commands whose trailing words form one command string run via a shell. */
const COMMAND_STRING_COMMANDS = new Set(['eval', 'watch']);

/** Flags on shell-like interpreters whose value is itself program text. */
const COMMAND_STRING_FLAGS = new Map([
  ['fish', new Set(['-c', '-C', '--command'])],
  ['yash', new Set(['-c'])],
  ['osh', new Set(['-c'])],
  ['oil', new Set(['-c'])],
  ['elvish', new Set(['-c'])],
]);

/**
 * Interpreters that take option values which must be skipped before the
 * script-file argument is identified. Without this, `python3 -W ignore app.py`
 * misreads `ignore` as the script and hides `app.py` from inspection.
 */
const INTERPRETER_VALUE_FLAGS = new Map([
  ['python', new Set(['-W', '-X'])],
  ['python2', new Set(['-W', '-X'])],
  ['python3', new Set(['-W', '-X', '--check-hash-based-pycs'])],
  ['node', new Set(['-r', '--require', '--import', '--loader', '--experimental-loader', '--conditions', '--title', '--report-filename', '--report-directory', '--redirect-warnings', '--heap-prof-dir', '--heap-prof-name', '--cpu-prof-dir', '--cpu-prof-name', '--diagnostic-dir', '--openssl-config', '--env-file', '--env-file-if-exists', '--test-reporter', '--test-reporter-destination', '--inspect-port', '--watch-path'])],
  ['ruby', new Set(['-I', '-r', '-E', '-T', '-W', '-X', '--encoding', '--debug', '--verbose'])],
  ['perl', new Set(['-I', '-M', '-D', '-F', '-x', '-X', '-C'])],
  ['php', new Set(['-c', '-d'])],
  ['lua', new Set()],
  ['Rscript', new Set(['-f', '--file', '--encoding'])],
  ['deno', new Set(['--cert', '--config', '--env', '--env-file', '--import-map', '--inspect', '--inspect-brk', '--inspect-wait', '--lock', '--log-level', '--reload', '--seed', '--v8-flags', '--watch', '--watch-fs', '--watch-hmr'])],
  ['bun', new Set(['--preload', '--bunfile', '--conditions', '--cwd', '--define', '--env-file', '--extension-order', '--filter', '--hot', '--import', '--jsx', '--jsx-factory', '--jsx-fragment', '--jsx-import-source', '--loader', '--main-fields', '--port', '--target', '--tsconfig-override', '--watch'])],
  ['jshell', new Set()],
  ['ghci', new Set()],
  ['fish', new Set(['--profile', '-p'])],
  ['yash', new Set()],
  ['osh', new Set()],
  ['oil', new Set()],
  ['elvish', new Set()],
]);

export const SHELL_VALUE_OPTIONS = new Set(['o', 'O']);
export const SHELL_LONG_VALUE_OPTIONS = new Set(['--rcfile', '--init-file']);

function decodeAnsiEscape(raw, startIdx) {
  const ch = raw[startIdx];
  if (ch === 'n') return ['\n', startIdx + 1];
  if (ch === 'r') return ['\r', startIdx + 1];
  if (ch === 't') return ['\t', startIdx + 1];
  if (ch === 'a') return ['\x07', startIdx + 1];
  if (ch === 'b') return ['\b', startIdx + 1];
  if (ch === 'f') return ['\f', startIdx + 1];
  if (ch === 'v') return ['\v', startIdx + 1];
  if (ch === 'e' || ch === 'E') return ['\x1b', startIdx + 1];
  if (ch === '\\' || ch === '\'' || ch === '"') return [ch, startIdx + 1];
  if (ch === 'x') {
    const m = /^[0-9a-fA-F]{1,2}/.exec(raw.slice(startIdx + 1));
    if (m) return [String.fromCharCode(Number.parseInt(m[0], 16)), startIdx + 1 + m[0].length];
  }
  if (ch === 'u' || ch === 'U') {
    const maxW = ch === 'u' ? 4 : 8;
    const m = new RegExp(`^[0-9a-fA-F]{1,${maxW}}`).exec(raw.slice(startIdx + 1));
    if (m) {
      const cp = Number.parseInt(m[0], 16);
      if (cp <= 0x10ffff) return [String.fromCodePoint(cp), startIdx + 1 + m[0].length];
    }
  }
  if (/^[0-7]/.test(ch)) {
    const m = /^[0-7]{1,3}/.exec(raw.slice(startIdx));
    if (m) return [String.fromCharCode(Number.parseInt(m[0], 8) & 0xff), startIdx + m[0].length];
  }
  return [`\\${ch}`, startIdx + 1];
}

export function decodeWord(raw) {
  let out = '';
  let quote = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote === "'") {
      if (ch === "'") quote = null;
      else out += ch;
    } else if (quote === '$') {
      if (ch === "'") {
        quote = null;
      } else if (ch === '\\' && i + 1 < raw.length) {
        const [decoded, nextIdx] = decodeAnsiEscape(raw, i + 1);
        out += decoded;
        i = nextIdx - 1;
      } else {
        out += ch;
      }
    } else if (quote === '"') {
      if (ch === '"') {
        quote = null;
      } else if (ch === '\\' && i + 1 < raw.length) {
        const nxt = raw[i + 1];
        if (nxt === '"' || nxt === '\\' || nxt === '$' || nxt === '`') {
          out += nxt;
          i += 1;
        } else {
          out += ch;
        }
      } else {
        out += ch;
      }
    } else {
      if (ch === '$' && raw[i + 1] === "'") {
        quote = '$';
        i += 1;
      } else if (ch === "'" || ch === '"') {
        quote = ch;
      } else if (ch === '\\' && i + 1 < raw.length) {
        out += raw[i + 1];
        i += 1;
      } else {
        out += ch;
      }
    }
  }
  return out;
}

/**
 * Decode the backslash escapes printf format strings and `echo -e` honor
 * (`\xHH`, `\ooo`/`\0ooo`, `\n` and friends, `\\`, `\c` to terminate) so a
 * payload piped into a shell can be analyzed as the code it becomes.
 */
function decodeFeederEscapes(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch !== '\\' || i + 1 >= s.length) {
      out += ch;
      continue;
    }
    const n = s[i + 1];
    if (n === 'x') {
      const m = /^[0-9a-fA-F]{1,2}/.exec(s.slice(i + 2));
      if (m) {
        out += String.fromCharCode(Number.parseInt(m[0], 16));
        i += 1 + m[0].length;
        continue;
      }
      out += 'x';
      i += 1;
      continue;
    }
    if (/[0-7]/.test(n)) {
      const m = /^[0-7]{1,3}/.exec(s.slice(i + 1));
      out += String.fromCharCode(Number.parseInt(m[0], 8) & 0xff);
      i += m[0].length;
      continue;
    }
    if (n === 'c') {
      // printf \c terminates output here.
      return out;
    }
    const simple = { n: '\n', t: '\t', r: '\r', b: '\b', a: '\x07', f: '\f', v: '\v', e: '\x1b', '\\': '\\' };
    if (simple[n] !== undefined) {
      out += simple[n];
      i += 1;
      continue;
    }
    out += n;
    i += 1;
  }
  return out;
}

/**
 * Tokenizes a shell command string into statements separated by pipes/control ops,
 * while also extracting heredoc bodies and command substitutions.
 */
export function tokenizeShellLines(script) {
  const tokens = [];
  const heredocQueue = [];
  const heredocBodies = [];
  const substitutions = [];

  const text = String(script || '');
  let i = 0;
  let current = '';
  let hasToken = false;

  const flush = () => {
    if (hasToken || current.length > 0) {
      tokens.push({ type: 'word', raw: current, value: decodeWord(current) });
      current = '';
      hasToken = false;
    }
  };

  while (i < text.length) {
    const ch = text[i];

    // Line break: resolve pending heredocs
    if (ch === '\n') {
      flush();
      tokens.push({ type: 'op', raw: '\n', value: '\n' });
      i += 1;
      while (heredocQueue.length > 0 && i <= text.length) {
        const spec = heredocQueue.shift();
        const bodyLines = [];
        while (i < text.length) {
          const nextNl = text.indexOf('\n', i);
          const line = nextNl === -1 ? text.slice(i) : text.slice(i, nextNl);
          const checkLine = spec.stripTabs ? line.replace(/^\t+/, '') : line;
          i = nextNl === -1 ? text.length : nextNl + 1;
          if (checkLine === spec.delim) break;
          bodyLines.push(spec.stripTabs ? line.replace(/^\t+/, '') : line);
        }
        heredocBodies.push({
          delim: spec.delim,
          quoted: spec.quoted,
          cmdIndexHint: spec.cmdTokenIdx,
          body: bodyLines.join('\n'),
        });
      }
      continue;
    }

    // Whitespace
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      flush();
      i += 1;
      continue;
    }

    // Comment at word boundary
    if (ch === '#' && !hasToken && current === '') {
      while (i < text.length && text[i] !== '\n') i += 1;
      continue;
    }

    // Backslash-newline line continuation
    if (ch === '\\' && text[i + 1] === '\n') {
      i += 2;
      continue;
    }

    // Unquoted `$IFS` / `${IFS}` expand to the field-splitting characters
    // (space, tab, newline), so they act as a word separator, not text.
    // Modeling them as separators puts `cat$IFS/etc/passwd`'s real argument
    // under the same inspection as the spaced form.
    if (ch === '$' && (text.startsWith('${IFS}', i) ||
        (text.startsWith('$IFS', i) && !/[A-Za-z0-9_]/.test(text[i + 4] || '')))) {
      flush();
      i += text.startsWith('${IFS}', i) ? 6 : 4;
      continue;
    }

    // Two/three-char operators, here-strings, heredocs, process substitutions
    const three = text.slice(i, i + 3);
    if (three === '<<<') {
      if (hasToken && /^[0-9]+$/.test(current)) {
        current = '';
        hasToken = false;
      } else {
        flush();
      }
      let j = i + 3;
      while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j += 1;
      let rawWord = '';
      let q = null;
      while (j < text.length) {
        const c = text[j];
        if (q === "'") {
          rawWord += c;
          j += 1;
          if (c === "'") q = null;
        } else if (q === '"') {
          if (c === '\\' && j + 1 < text.length) {
            rawWord += c + text[j + 1];
            j += 2;
          } else {
            rawWord += c;
            j += 1;
            if (c === '"') q = null;
          }
        } else {
          if (/[\s;|&<>()]/.test(c)) break;
          if (c === "'" || c === '"') q = c;
          else if (c === '\\' && j + 1 < text.length) {
            rawWord += c + text[j + 1];
            j += 2;
            continue;
          }
          rawWord += c;
          j += 1;
        }
      }
      tokens.push({ type: 'redir', raw: text.slice(i, j), value: '<<<', inlineBody: decodeWord(rawWord) });
      i = j;
      continue;
    }

    const two = text.slice(i, i + 2);
    if (two === '<<') {
      if (hasToken && /^[0-9]+$/.test(current)) {
        current = '';
        hasToken = false;
      } else {
        flush();
      }
      const stripTabs = text[i + 2] === '-';
      let j = i + (stripTabs ? 3 : 2);
      while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j += 1;
      let delimRaw = '';
      while (j < text.length && !/[\s;|&<>()]/.test(text[j])) {
        delimRaw += text[j];
        j += 1;
      }
      const quoted = /['"\\]/.test(delimRaw);
      const delim = decodeWord(delimRaw);
      if (delim) {
        heredocQueue.push({
          delim,
          stripTabs,
          quoted,
          cmdTokenIdx: tokens.length,
        });
      }
      tokens.push({ type: 'redir', raw: text.slice(i, j), value: '<<' });
      i = j;
      continue;
    }

    if (two === '<(' || two === '>(') {
      flush();
      const { segment, subBody, nextIdx } = readDollarParen(text, i);
      substitutions.push({ body: subBody });
      tokens.push({ type: 'word', raw: segment, value: segment });
      i = nextIdx;
      continue;
    }

    // Redirect operators that must not split the segment: `>&`, `<&`, `<>`,
    // `>|`, `&>`, `&>>`, `|&`. An fd number immediately before them (`2>&1`,
    // `0<file`) is part of the operator, not a command argument.
    if (['>&', '<&', '<>', '>|', '&>', '&>>', '|&'].includes(two)) {
      if (hasToken && /^[0-9]+$/.test(current)) {
        current = '';
        hasToken = false;
      } else {
        flush();
      }
      tokens.push({ type: 'op', raw: two, value: two });
      i += 2;
      continue;
    }

    if (two === '&&' || two === '||' || two === '>>') {
      if (hasToken && /^[0-9]+$/.test(current)) {
        current = '';
        hasToken = false;
      } else {
        flush();
      }
      tokens.push({ type: 'op', raw: two, value: two });
      i += 2;
      continue;
    }

    // `{` and `}` are reserved words only when they stand alone: a `{` glued
    // to a word char is brace expansion (`{a,b}` -> `a` `b`), and a mid-word
    // `}` is literal (`xargs -I{}`). Treating glued braces as operators would
    // silently move the expanded words out of the owning command's argument
    // list, so the path scan would never see them.
    if (ch === '{' || ch === '}') {
      const next = text[i + 1];
      // `{`/`}` must be complete words to group: `{}` (xargs -I{}) and
      // `{a,b}` expansions are literal, `{( ... )}` and `{ cmd;}` group.
      const standalone = next === undefined || /[\s;|&()<>\n]/.test(next);
      if (!standalone || hasToken || current !== '') {
        hasToken = true;
        current += ch;
        i += 1;
        continue;
      }
      flush();
      tokens.push({ type: 'op', raw: ch, value: ch });
      i += 1;
      continue;
    }

    if (ch === '|' || ch === ';' || ch === '&' || ch === '(' || ch === ')' || ch === '{' || ch === '}' || ch === '<' || ch === '>') {
      // A digit run immediately before a redirect char is an fd prefix
      // (`2>file`, `0<file`), not a command word.
      if ((ch === '<' || ch === '>') && hasToken && /^[0-9]+$/.test(current)) {
        current = '';
        hasToken = false;
      } else {
        flush();
      }
      tokens.push({ type: 'op', raw: ch, value: ch });
      i += 1;
      continue;
    }

    // ANSI-C single quotes ($'...')
    if (ch === '$' && text[i + 1] === "'") {
      hasToken = true;
      current += "$'";
      i += 2;
      while (i < text.length) {
        if (text[i] === '\\' && i + 1 < text.length) {
          current += text[i] + text[i + 1];
          i += 2;
          continue;
        }
        current += text[i];
        if (text[i] === "'") { i += 1; break; }
        i += 1;
      }
      continue;
    }

    // Single quotes
    if (ch === "'") {
      hasToken = true;
      current += ch;
      i += 1;
      while (i < text.length) {
        current += text[i];
        if (text[i] === "'") { i += 1; break; }
        i += 1;
      }
      continue;
    }

    // Double quotes (also scan $(...) and `...` substitutions)
    if (ch === '"') {
      hasToken = true;
      current += ch;
      i += 1;
      while (i < text.length) {
        const c = text[i];
        if (c === '\\' && text[i + 1] === '\n') {
          i += 2;
          continue;
        }
        if (c === '\\' && i + 1 < text.length) {
          current += c + text[i + 1];
          i += 2;
          continue;
        }
        if (c === '$' && text[i + 1] === '(') {
          const { segment, subBody, nextIdx, arith } = readDollarParen(text, i);
          current += segment;
          substitutions.push({ body: subBody, arith });
          i = nextIdx;
          continue;
        }
        if (c === '`') {
          const { segment, subBody, nextIdx } = readBacktick(text, i);
          current += segment;
          substitutions.push({ body: subBody });
          i = nextIdx;
          continue;
        }
        current += c;
        i += 1;
        if (c === '"') break;
      }
      continue;
    }

    // Unquoted $(...) or `...`
    if (ch === '$' && text[i + 1] === '(') {
      hasToken = true;
      const { segment, subBody, nextIdx, arith } = readDollarParen(text, i);
      current += segment;
      substitutions.push({ body: subBody, arith });
      i = nextIdx;
      continue;
    }
    if (ch === '`') {
      hasToken = true;
      const { segment, subBody, nextIdx } = readBacktick(text, i);
      current += segment;
      substitutions.push({ body: subBody });
      i = nextIdx;
      continue;
    }

    // Backslash escape outside quotes
    if (ch === '\\' && i + 1 < text.length) {
      hasToken = true;
      current += ch + text[i + 1];
      i += 2;
      continue;
    }

    hasToken = true;
    current += ch;
    i += 1;
  }

  flush();
  return { tokens, heredocBodies, substitutions };
}

function readDollarParen(text, startIdx) {
  let depth = 0;
  let i = startIdx + 2;
  let quote = null;
  const bodyStart = i;
  // `$((expr))` is arithmetic expansion, not command substitution. It is
  // still flagged when the body carries shell metacharacters, which is where
  // a nested `$(cmd)` could hide.
  const arith = text[startIdx + 2] === '(';
  while (i < text.length) {
    const c = text[i];
    if (quote === "'") {
      if (c === "'") quote = null;
    } else if (quote === '"') {
      if (c === '\\') i += 1;
      else if (c === '"') quote = null;
    } else {
      if (c === '\\') { i += 2; continue; }
      if (c === "'" || c === '"') quote = c;
      else if (c === '(') depth += 1;
      else if (c === ')') {
        if (depth === 0) {
          return {
            segment: text.slice(startIdx, i + 1),
            subBody: text.slice(bodyStart, i),
            nextIdx: i + 1,
            arith,
          };
        }
        depth -= 1;
      }
    }
    i += 1;
  }
  return {
    segment: text.slice(startIdx),
    subBody: text.slice(bodyStart),
    nextIdx: text.length,
    arith,
  };
}

function readBacktick(text, startIdx) {
  let i = startIdx + 1;
  let body = '';
  while (i < text.length) {
    const c = text[i];
    if (c === '\\' && i + 1 < text.length) {
      body += text[i + 1];
      i += 2;
      continue;
    }
    if (c === '`') {
      return {
        segment: text.slice(startIdx, i + 1),
        subBody: body,
        nextIdx: i + 1,
      };
    }
    body += c;
    i += 1;
  }
  return {
    segment: text.slice(startIdx),
    subBody: body,
    nextIdx: text.length,
  };
}

function splitPipelines(tokens) {
  const segments = [];
  let cur = [];
  for (const tok of tokens) {
    if (tok.type === 'op' && ['|', '|&', '&&', '||', ';', '\n', '&'].includes(tok.value)) {
      if (cur.length > 0) segments.push({ opAfter: tok.value, tokens: cur });
      cur = [];
    } else if (tok.type === 'op' && (tok.value === '(' || tok.value === ')' || tok.value === '{' || tok.value === '}')) {
      if (cur.length > 0) segments.push({ opAfter: tok.value, tokens: cur });
      cur = [];
    } else {
      cur.push(tok);
    }
  }
  if (cur.length > 0) segments.push({ opAfter: null, tokens: cur });
  return segments;
}

function baseCommandName(word) {
  const clean = String(word || '').trim();
  const slash = clean.lastIndexOf('/');
  return slash >= 0 ? clean.slice(slash + 1) : clean;
}

function isAssignmentWord(raw) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(raw);
}

/**
 * Keywords that open a compound statement or list: the words after them are
 * the real command (`if x` evaluates x, `then x` runs the body, `! x`
 * negates). Terminator words (`fi`, `done`, `esac`) strip to nothing; if
 * anything follows them it is still inspected (fail closed).
 */
const KEYWORD_PREFIXES = new Set([
  'if', 'elif', 'else', 'while', 'until', 'then', 'do',
  'fi', 'done', 'esac', '!',
]);

/**
 * Keywords whose segment is a spec, not a command: `for x in list`,
 * `select x in list`, `case word in`, `function name`, and `[[` tests. The
 * words stay as args so the gate can still path-scan the spec (`for i in
 * /etc/*` should not silently pass), but nothing in the segment executes.
 */
const CONTROL_SPEC_WORDS = new Set(['for', 'select', 'case', 'function', '[[']);

/**
 * Unwrap wrapper prefixes (`env`, `timeout`, `xargs`, `nohup`, etc.) and extract
 * inner command + shell `-c` script payload if present.
 */
function unwrapSegmentWords(words, segTokens) {
  let idx = 0;
  const chain = [];
  const extraScripts = [];
  const envAssignments = [];
  let envQuery = false;

  while (idx < words.length && isAssignmentWord(words[idx])) {
    envAssignments.push(words[idx]);
    idx += 1;
  }

  // Structural keywords (`then rm x`, `while x`) prefix the real command and
  // carry nothing themselves; without stripping them the keyword becomes a
  // phantom unlisted command and the payload hides behind it.
  while (idx < words.length && KEYWORD_PREFIXES.has(words[idx])) idx += 1;

  // A spec segment (`for x in ...`, `[[ ... ]]`, `function name`) contains no
  // command to dispatch on; its words still reach the gate as args so glob
  // and path scans can judge them.
  if (idx < words.length && (CONTROL_SPEC_WORDS.has(words[idx]) || words[words.length - 1] === ']]')) {
    return { chain, command: '__control_spec__', args: words.slice(idx), nestedScript: null, readsStdinAsCode: false, stdinRedirectTarget: null, scriptFile: null, extraScripts, envAssignments };
  }

  while (idx < words.length) {
    const cmd = baseCommandName(words[idx]);
    if (!SIMPLE_WRAPPERS.has(cmd)) break;
    chain.push(cmd);
    idx += 1;

    const valFlags = WRAPPER_VALUE_FLAGS.get(cmd) || new Set();
    let sawTimeFormat = false;
    let sawScriptFile = false;
    while (idx < words.length) {
      const w = words[idx];
      if (cmd === 'env' && isAssignmentWord(w)) {
        envAssignments.push(w);
        idx += 1;
        continue;
      }
      // `command -v rm` / `builtin -v x` are lookups, not dispatch: the word
      // after the query flag is queried, never executed. Clusters containing
      // v/V (`-pv`) count; `command -p rm` still dispatches rm.
      if ((cmd === 'command' || cmd === 'builtin') && /^-[^\s-]*[vV]/.test(w)) {
        return { chain, command: cmd, args: words.slice(idx + 1), nestedScript: null, readsStdinAsCode: false, stdinRedirectTarget: null, scriptFile: null, extraScripts, envAssignments };
      }
      if (cmd === 'env' && (w === '--version' || w === '--help')) {
        envQuery = true;
        idx += 1;
        continue;
      }
      if (cmd === 'env') {
        // `env -S 'cmd args'` / `--split-string` re-splits one word into a
        // full command line. Inside a short-option cluster, options that take
        // a value (-u, -C) consume the rest of the cluster, so an `S` after
        // them is their argument rather than the split flag.
        let splitVal = null;
        let consumed = 0;
        if (w === '--split-string') {
          splitVal = words[idx + 1] ?? '';
          consumed = 2;
        } else if (w.startsWith('--split-string=')) {
          splitVal = w.slice('--split-string='.length);
          consumed = 1;
        } else if (w.startsWith('-') && !w.startsWith('--') && w.length > 1) {
          let sPos = -1;
          for (let k = 1; k < w.length; k++) {
            const ch = w[k];
            if (ch === 'S') { sPos = k; break; }
            if (ch === 'u' || ch === 'C') break;
          }
          if (sPos > 0) {
            if (sPos < w.length - 1) {
              splitVal = w.slice(sPos + 1);
              consumed = 1;
            } else {
              splitVal = words[idx + 1] ?? '';
              consumed = 2;
            }
          }
        }
        if (splitVal !== null) {
          idx += consumed;
          if (splitVal) {
            const parsedSplit = tokenizeShellLines(splitVal);
            const splitSegs = splitPipelines(parsedSplit.tokens);
            if (splitSegs.length === 1 && parsedSplit.heredocBodies.length === 0 && parsedSplit.substitutions.length === 0) {
              const splitWords = splitSegs[0].tokens.filter((t) => t.type === 'word').map((t) => t.value);
              words = [...words.slice(0, idx), ...splitWords, ...words.slice(idx)];
            } else {
              extraScripts.push(splitVal);
            }
          }
          continue;
        }
      }
      if (w === '--') {
        idx += 1;
        break;
      }
      if (cmd === 'timeout' && !w.startsWith('-') && !sawTimeFormat && /^[0-9]+(\.[0-9]+)?[smhd]?$/.test(w)) {
        sawTimeFormat = true;
        idx += 1;
        continue;
      }
      if (w.startsWith('-')) {
        if (valFlags.has(w)) {
          idx += 2;
        } else {
          idx += 1;
        }
        continue;
      }
      break;
    }
    // Wrappers like `chroot /jail cmd` or `setuidgid user cmd` take leading
    // operands that are not the command.
    const operands = WRAPPER_OPERAND_COUNT.get(cmd) || 0;
    for (let k = 0; k < operands && idx < words.length; k++) idx += 1;
  }

  const remaining = words.slice(idx);
  // `env --version` / `env --help` answer and exit without running anything;
  // the flag was seen inside the wrapper scan above.
  if (envQuery) {
    return { chain, command: '__env_query__', args: [], nestedScript: null, readsStdinAsCode: false, stdinRedirectTarget: null, scriptFile: null, extraScripts, envAssignments };
  }
  if (remaining.length === 0) {
    // A wrapper that consumed the whole line is not a no-op: bare `env` dumps
    // every environment variable, bare `xargs` re-runs buffered stdin as a
    // command, bare `sudo` is still sudo. Surface a marker so the gate can
    // rule on it instead of silently allowing.
    const bareCmd = chain.length > 0 ? chain[chain.length - 1] : null;
    if (bareCmd) {
      return { chain, command: `__bare_${bareCmd}__`, args: [], nestedScript: null, readsStdinAsCode: false, stdinRedirectTarget: null, scriptFile: null, extraScripts, envAssignments };
    }
    // Words were consumed as pure VAR=value assignments with no command
    // (`PATH=/tmp/evil` alone still mutates the environment the next call
    // inherits). Surface a marker so the gate audits the env channel instead
    // of silently dropping the segment.
    if (idx > 0) {
      return { chain, command: '__env_only__', args: [], nestedScript: null, readsStdinAsCode: false, stdinRedirectTarget: null, scriptFile: null, extraScripts, envAssignments };
    }
    return { chain, command: null, args: [], nestedScript: null, readsStdinAsCode: false, stdinRedirectTarget: null, scriptFile: null, extraScripts, envAssignments };
  }

  const command = baseCommandName(remaining[0]);
  const args = remaining.slice(1);
  let nestedScript = null;
  let readsStdinAsCode = false;
  let stdinRedirectTarget = null;
  let scriptFile = null;
  let startupScriptFile = null;

  // A `< file` redirect feeding program text to a shell or interpreter makes
  // that file the executed program regardless of other arguments.
  if (segTokens) {
    for (let j = 0; j < segTokens.length - 1; j++) {
      const t = segTokens[j];
      if (t.type === 'op' && t.value === '<' && segTokens[j + 1]?.type === 'word') {
        stdinRedirectTarget = segTokens[j + 1].value || null;
        break;
      }
    }
  }

  if (COMMAND_STRING_COMMANDS.has(command)) {
    // `eval 'a; b'` and `watch cmd args`: the trailing words are re-joined
    // into one command line so blocked commands inside still fire.
    const valFlags = WRAPPER_VALUE_FLAGS.get(command) || new Set();
    const payload = [];
    for (let j = 0; j < args.length; j++) {
      const a = args[j];
      if (a === '--') { payload.push(...args.slice(j + 1)); break; }
      if (a.startsWith('-')) {
        if (valFlags.has(a)) j += 1;
        continue;
      }
      payload.push(a);
    }
    if (payload.length > 0) nestedScript = payload.join(' ');
  } else if (command === 'script') {
    // `script -c 'cmd' file` runs cmd under a typescript wrapper; without -c
    // it spawns an interactive shell that reads the caller's stdin.
    const valFlags = WRAPPER_VALUE_FLAGS.get('script') || new Set();
    for (let j = 0; j < args.length; j++) {
      const a = args[j];
      if (a === '-c' || a === '--command') {
        if (j + 1 < args.length) nestedScript = args[j + 1];
        break;
      }
      if (a.startsWith('--command=')) {
        nestedScript = a.slice('--command='.length);
        break;
      }
      if (valFlags.has(a)) { j += 1; continue; }
      if (a.startsWith('-')) continue;
    }
    if (nestedScript === null) readsStdinAsCode = true;
  } else if (SHELL_BINARIES.has(command)) {
    let seenDashC = false;
    let seenScriptFile = false;
    for (let j = 0; j < args.length; j++) {
      const opt = args[j];
      if (opt === '--') {
        if (j + 1 < args.length) seenScriptFile = true;
        break;
      }
      if (SHELL_LONG_VALUE_OPTIONS.has(opt)) {
        // --rcfile/--init-file name a script the shell runs on startup:
        // it is a code channel, not an inert option value.
        if (j + 1 < args.length) startupScriptFile = args[j + 1];
        j += 1;
        continue;
      }
      if (opt.startsWith('--')) {
        const eq = opt.indexOf('=');
        if (eq > 0 && SHELL_LONG_VALUE_OPTIONS.has(opt.slice(0, eq))) {
          startupScriptFile = opt.slice(eq + 1);
        }
        continue;
      }
      // Glued `-c<payload>` (`bash -c'rm -rf /'` decodes to one word
      // `-crm -rf /`): GNU getopt reads the rest of the word as the command.
      if (opt.length > 2 && opt[0] === '-' && opt[1] === 'c') {
        if (nestedScript === null) nestedScript = opt.slice(2);
        seenDashC = true;
        break;
      }
      if (/^-[A-Za-z]+$/.test(opt) || /^\+[A-Za-z]+$/.test(opt)) {
        const flags = opt.slice(1);
        let stopCluster = false;
        for (let k = 0; k < flags.length; k++) {
          const f = flags[k];
          if (f === 'c' && opt.startsWith('-')) {
            seenDashC = true;
            // A `c` mid-cluster consumes the cluster rest as its argument
            // under GNU getopt (`bash -xcq` runs `q`); the first -c wins.
            if (k < flags.length - 1 && nestedScript === null) {
              nestedScript = flags.slice(k + 1);
              stopCluster = true;
            }
            break;
          } else if (f === 's' && opt.startsWith('-')) {
            readsStdinAsCode = true;
          } else if (SHELL_VALUE_OPTIONS.has(f)) {
            // o/O consume the rest of their own word (`-onounset`) or, at
            // cluster end, the next argv (`-o nounset`).
            if (k < flags.length - 1) stopCluster = true;
            else j += 1;
            break;
          }
        }
        if (stopCluster && nestedScript !== null) break;
        continue;
      }
      if (opt.startsWith('-') || opt.startsWith('+')) {
        continue;
      }
      if (seenDashC && nestedScript === null) {
        nestedScript = opt;
        break;
      }
      if (!seenDashC) {
        seenScriptFile = true;
        scriptFile = opt;
        break;
      }
      // Words after the -c payload are positional parameters ($0, $1...),
      // not options or commands.
      break;
    }
    if (!seenDashC && !seenScriptFile) {
      readsStdinAsCode = true;
    }
  } else if (STDIN_INTERPRETERS.has(command)) {
    // An interpreter consumes program text from stdin when it has no script
    // file argument: `python3 -`, `python3 <<EOF`, `cat x | python3`,
    // `python3 < script.py`. Option values must be skipped or a flag's
    // argument is mistaken for the script file and the real one is hidden.
    const valFlags = INTERPRETER_VALUE_FLAGS.get(command) || new Set();
    const cmdFlags = COMMAND_STRING_FLAGS.get(command) || new Set();
    let sawScriptFile = false;
    let endOfFlags = false;
    for (let j = 0; j < args.length; j++) {
      const opt = args[j];
      if (endOfFlags) {
        sawScriptFile = true;
        scriptFile = opt;
        break;
      }
      if (opt === '--') {
        endOfFlags = true;
        continue;
      }
      if (opt === '-') {
        readsStdinAsCode = true;
        break;
      }
      if (opt.startsWith('-')) {
        let isCmdFlag = false;
        for (const cf of cmdFlags) {
          if (opt === cf) {
            if (j + 1 < args.length) nestedScript = args[j + 1];
            isCmdFlag = true;
            break;
          }
          if (!cf.startsWith('--') && opt.startsWith(cf) && opt.length > cf.length) {
            nestedScript = opt.slice(cf.length);
            isCmdFlag = true;
            break;
          }
          // Long command flags also take `--flag=payload` (`fish --command=`).
          if (cf.startsWith('--') && opt.startsWith(`${cf}=`)) {
            nestedScript = opt.slice(cf.length + 1);
            isCmdFlag = true;
            break;
          }
        }
        if (isCmdFlag) break;
        if (valFlags.has(opt)) {
          j += 1;
          continue;
        }
        continue;
      }
      sawScriptFile = true;
      scriptFile = opt;
      break;
    }
    if (!sawScriptFile && nestedScript === null) readsStdinAsCode = true;
  }

  // A script-file argument that names the process's own stdin stream means
  // the program text arrives through the same channel as a bare interpreter.
  if (scriptFile && /^(?:\/dev\/stdin|\/dev\/fd\/0|\/proc\/self\/fd\/0)$/.test(scriptFile)) {
    readsStdinAsCode = true;
  }

  return { chain, command, args, nestedScript, readsStdinAsCode, stdinRedirectTarget, scriptFile, startupScriptFile, extraScripts, envAssignments };
}

/**
 * Redirect operators whose following word is a target path, not a command
 * argument. `|&` is a pipe, `<<`/`<<<` carry their own token, and `&&`/`||`/`;`
 * split segments: none belong here.
 */
const REDIRECT_TARGET_OPS = new Set(['<', '>', '>>', '>&', '<&', '<>', '>|', '&>', '&>>']);

/**
 * Split a pipeline segment into real argv words and redirect targets. The
 * token stream keeps redirect targets as ordinary words; leaving them in
 * argv lets `sh >o -c 'rm -rf /'` shift the payload past the -c flag parser.
 * Targets are preserved separately so the gate can still path-check writes.
 */
function segmentWords(seg) {
  const words = [];
  const redirectTargets = [];
  const toks = seg.tokens;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.type === 'op' && REDIRECT_TARGET_OPS.has(t.value)) {
      const nx = toks[i + 1];
      if (nx && nx.type === 'word') { redirectTargets.push(nx.value); i += 1; }
      continue;
    }
    if (t.type === 'word') words.push(t.value);
  }
  return { words, redirectTargets };
}

/**
 * Recursively analyze a shell script into flattened normalized command records,
 * preserving nesting depth and wrapper/shell provenance chains.
 */
export function analyzeShellAst(script, maxDepth = 6) {
  const records = [];
  const heredocScripts = [];

  function walk(code, depth, trail) {
    if (depth > maxDepth) {
      records.push({
        depth,
        trail,
        command: '__max_depth_exceeded__',
        args: [code.slice(0, 80)],
        rawWords: [],
      });
      return;
    }

    const { tokens, heredocBodies, substitutions } = tokenizeShellLines(code);
    const segments = splitPipelines(tokens);

    for (let sIdx = 0; sIdx < segments.length; sIdx++) {
      const seg = segments[sIdx];
      const { words, redirectTargets } = segmentWords(seg);
      // `f()` / `f ()` opens a function definition: the single word before
      // `(` is a name, not a command. Body segments still get inspected.
      if (words.length === 1 && seg.opAfter === '(' && redirectTargets.length === 0) continue;
      // `> file` alone is a redirect with no command: surface the targets so
      // the gate can path-check them (truncate `> /etc/passwd` is not benign).
      if (words.length === 0) {
        if (redirectTargets.length > 0) {
          records.push({
            depth,
            trail,
            command: '__redirect_only__',
            args: redirectTargets,
            rawWords: [],
            redirectTargets,
          });
        }
        continue;
      }

      const parsed = unwrapSegmentWords(words, seg.tokens);
      if (!parsed.command && parsed.extraScripts.length === 0) continue;

      const fullTrail = parsed.command
        ? [...trail, ...parsed.chain, parsed.command]
        : [...trail, ...parsed.chain];
      if (parsed.command) {
        records.push({
          depth,
          trail: fullTrail,
          command: parsed.command,
          args: parsed.args,
          rawWords: words,
          redirectTargets,
          envAssignments: parsed.envAssignments,
          startupScriptFile: parsed.startupScriptFile,
        });
      }

      // `find -exec cmd ... \;` (and -execdir/-ok/-okdir with `+`) hides a
      // full command inside find's argument list; `find -delete` removes
      // matched files outright. Both evade a plain command-name check.
      if (parsed.command === 'find') {
        const fargs = parsed.args || [];
        for (let fi = 0; fi < fargs.length; fi++) {
          const fa = fargs[fi];
          if (fa === '-delete') {
            records.push({
              depth: depth + 1,
              trail: [...fullTrail, '-delete'],
              command: '__find_delete__',
              args: [],
              rawWords: words,
            });
          }
          if (fa === '-exec' || fa === '-execdir' || fa === '-ok' || fa === '-okdir') {
            let end = fi + 1;
            const payload = [];
            while (end < fargs.length && fargs[end] !== ';' && fargs[end] !== '+') {
              payload.push(fargs[end]);
              end += 1;
            }
            if (payload.length > 0) {
              walk(payload.join(' '), depth + 1, [...fullTrail, fa]);
            }
            fi = end;
          }
        }
      }

      for (const extra of parsed.extraScripts) {
        walk(extra, depth + 1, [...trail, ...parsed.chain, '-S']);
      }

      if (parsed.nestedScript !== null) {
        walk(parsed.nestedScript, depth + 1, [...fullTrail, '-c']);
      }

      // Check here-string on stdin-reading shell (`bash <<< 'rm -rf /'`)
      if (parsed.readsStdinAsCode) {
        for (const tok of seg.tokens) {
          if (tok.type === 'redir' && tok.value === '<<<' && tok.inlineBody) {
            heredocScripts.push(tok.inlineBody);
            walk(tok.inlineBody, depth + 1, [...fullTrail, 'herestring']);
          }
        }
      }

      // Check pipeline feeder into stdin-reading shell (`cat <<EOF | bash`, `echo '...' | bash`, `cat script.sh | bash`, `|&`)
      if (sIdx > 0 && ['|', '|&'].includes(segments[sIdx - 1].opAfter) && parsed.readsStdinAsCode) {
        if (heredocBodies.length > 0) {
          for (const hd of heredocBodies) {
            heredocScripts.push(hd.body);
            walk(hd.body, depth + 1, [...fullTrail, `pipe-heredoc(${hd.delim})`]);
          }
        } else {
          const prevSeg = segments[sIdx - 1];
          const prevWords = segmentWords(prevSeg).words;
          const prevParsed = unwrapSegmentWords(prevWords, prevSeg.tokens);
          const feederCmd = prevParsed.command || prevWords[0] || '';
          if (feederCmd === 'echo' || feederCmd === 'printf') {
            const hasEchoEsc = feederCmd === 'echo' && prevParsed.args.some((a) => /^-[neE]*e/.test(a));
            const payloadArgs = feederCmd === 'echo'
              ? prevParsed.args.filter((a) => !/^-[neE]+$/.test(a))
              : prevParsed.args;
            let pipedScript = payloadArgs.join(' ');
            if (feederCmd === 'printf' || hasEchoEsc) {
              pipedScript = decodeFeederEscapes(pipedScript);
            }
            if (pipedScript.trim()) {
              heredocScripts.push(pipedScript);
              walk(pipedScript, depth + 1, [...fullTrail, `pipe-${feederCmd}`]);
            }
          } else if (feederCmd) {
            records.push({
              depth,
              trail: [...fullTrail, `pipe-from(${feederCmd})`],
              command: '__pipe_stdin_shell__',
              args: prevParsed.args,
              rawWords: words,
            });
          }
        }
      }

      // Check direct heredoc on stdin-reading shell (`bash <<EOF`)
      if (parsed.readsStdinAsCode && heredocBodies.length > 0 && seg.tokens.some((t) => t.type === 'redir' && t.value === '<<')) {
        for (const hd of heredocBodies) {
          heredocScripts.push(hd.body);
          walk(hd.body, depth + 1, [...fullTrail, `heredoc(${hd.delim})`]);
        }
      }

      // A `< file` redirect feeding program text to a shell or interpreter:
      // surface the redirect target as a pseudo-record so the gate can inspect
      // the file being executed (e.g. `sh < /workspace/app/payload.sh`).
      if (parsed.stdinRedirectTarget && parsed.stdinRedirectTarget !== '/dev/null') {
        records.push({
          depth,
          trail: [...fullTrail, `<${parsed.stdinRedirectTarget}`],
          command: '__stdin_redirect__',
          args: [parsed.stdinRedirectTarget],
          rawWords: words,
        });
        if (!parsed.readsStdinAsCode) {
          // Non-stdin consumers (`cat < f`) still get path inspection from the
          // record args; nothing more to do here.
        } else if (parsed.command && !parsed.command.startsWith('__')) {
          // Stdin-code consumers execute the file as a program: hold for review.
        }
      }
    }

    for (const sub of substitutions) {
      // `$((expr))` arithmetic expansion is not command execution; skip it
      // unless the body hides shell metacharacters (a nested `$(cmd)`).
      if (sub.arith && !/[$`;&|<>\n]/.test(sub.body)) continue;
      walk(sub.body || '', depth + 1, [...trail, '$()']);
    }
  }

  walk(String(script || ''), 0, []);
  return { records, heredocScripts, maxObservedDepth: records.reduce((m, r) => Math.max(m, r.depth), 0) };
}
