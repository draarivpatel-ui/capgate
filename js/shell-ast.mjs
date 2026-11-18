/**
 * CapGate recursive POSIX-like shell tokenizer, wrapper unwrapper,
 * heredoc collector, and embedded script extractor.
 * Pure ES module (browser and Node compatible, zero external deps).
 */

export const SHELL_BINARIES = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash']);

export const WRAPPER_VALUE_FLAGS = new Map([
  ['env', new Set(['-u', '--unset', '-C', '--chdir'])],
  ['timeout', new Set(['-k', '--kill-after', '-s', '--signal'])],
  ['nice', new Set(['-n', '--adjustment'])],
  ['ionice', new Set(['-c', '--class', '-n', '--classdata', '-p', '--pid', '-P', '--pgid', '-u', '--uid', '-t'])],
  ['stdbuf', new Set(['-i', '--input', '-o', '--output', '-e', '--error'])],
  ['xargs', new Set(['-n', '--max-args', '-L', '--max-lines', '-P', '--max-procs', '-I', '--replace', '-d', '--delimiter', '-s', '--max-chars'])],
  ['exec', new Set(['-a'])],
  ['sudo', new Set(['-u', '--user', '-g', '--group', '-C', '--close-from', '-h', '--host', '-p', '--prompt', '-r', '--role', '-t', '--type'])],
]);

export const SIMPLE_WRAPPERS = new Set([
  'env', 'nohup', 'setsid', 'timeout', 'nice', 'ionice', 'stdbuf',
  'time', 'command', 'builtin', 'exec', 'xargs', 'sudo',
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
      substitutions.push(subBody);
      tokens.push({ type: 'word', raw: segment, value: segment });
      i = nextIdx;
      continue;
    }

    if (two === '&&' || two === '||' || two === '>>' || two === '2>') {
      flush();
      tokens.push({ type: 'op', raw: two, value: two });
      i += 2;
      continue;
    }

    if (ch === '|' || ch === ';' || ch === '&' || ch === '(' || ch === ')' || ch === '{' || ch === '}' || ch === '<' || ch === '>') {
      flush();
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
          const { segment, subBody, nextIdx } = readDollarParen(text, i);
          current += segment;
          substitutions.push(subBody);
          i = nextIdx;
          continue;
        }
        if (c === '`') {
          const { segment, subBody, nextIdx } = readBacktick(text, i);
          current += segment;
          substitutions.push(subBody);
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
      const { segment, subBody, nextIdx } = readDollarParen(text, i);
      current += segment;
      substitutions.push(subBody);
      i = nextIdx;
      continue;
    }
    if (ch === '`') {
      hasToken = true;
      const { segment, subBody, nextIdx } = readBacktick(text, i);
      current += segment;
      substitutions.push(subBody);
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
    if (tok.type === 'op' && ['|', '&&', '||', ';', '\n', '&'].includes(tok.value)) {
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
 * Unwrap wrapper prefixes (`env`, `timeout`, `xargs`, `nohup`, etc.) and extract
 * inner command + shell `-c` script payload if present.
 */
function unwrapSegmentWords(words) {
  let idx = 0;
  const chain = [];
  const extraScripts = [];

  while (idx < words.length && isAssignmentWord(words[idx])) {
    idx += 1;
  }

  while (idx < words.length) {
    const cmd = baseCommandName(words[idx]);
    if (!SIMPLE_WRAPPERS.has(cmd)) break;
    chain.push(cmd);
    idx += 1;

    const valFlags = WRAPPER_VALUE_FLAGS.get(cmd) || new Set();
    let sawTimeFormat = false;
    while (idx < words.length) {
      const w = words[idx];
      if (cmd === 'env' && isAssignmentWord(w)) {
        idx += 1;
        continue;
      }
      if (cmd === 'env' && (w === '-S' || w === '--split-string' || w.startsWith('--split-string=') || (w.startsWith('-S') && w.length > 2))) {
        let splitVal = '';
        if (w.startsWith('--split-string=')) {
          splitVal = w.slice('--split-string='.length);
          idx += 1;
        } else if (w.startsWith('-S') && w.length > 2) {
          splitVal = w.slice(2);
          idx += 1;
        } else {
          splitVal = words[idx + 1] ?? '';
          idx += 2;
        }
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
  }

  const remaining = words.slice(idx);
  if (remaining.length === 0) {
    return { chain, command: null, args: [], nestedScript: null, readsStdinAsCode: false, extraScripts };
  }

  const command = baseCommandName(remaining[0]);
  const args = remaining.slice(1);
  let nestedScript = null;
  let readsStdinAsCode = false;

  if (SHELL_BINARIES.has(command)) {
    let seenDashC = false;
    let seenScriptFile = false;
    for (let j = 0; j < args.length; j++) {
      const opt = args[j];
      if (opt === '--') {
        if (j + 1 < args.length) seenScriptFile = true;
        break;
      }
      if (SHELL_LONG_VALUE_OPTIONS.has(opt)) {
        j += 1;
        continue;
      }
      if (opt.startsWith('--')) {
        continue;
      }
      if (/^-[A-Za-z]+$/.test(opt) || /^\+[A-Za-z]+$/.test(opt)) {
        const flags = opt.slice(1);
        for (let k = 0; k < flags.length; k++) {
          const f = flags[k];
          if (f === 'c' && opt.startsWith('-')) {
            seenDashC = true;
          } else if (f === 's' && opt.startsWith('-')) {
            readsStdinAsCode = true;
          } else if (SHELL_VALUE_OPTIONS.has(f) && k === flags.length - 1) {
            j += 1;
          }
        }
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
        break;
      }
    }
    if (!seenDashC && !seenScriptFile) {
      readsStdinAsCode = true;
    }
  }

  return { chain, command, args, nestedScript, readsStdinAsCode, extraScripts };
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
      const words = seg.tokens.filter((t) => t.type === 'word').map((t) => t.value);
      if (words.length === 0) continue;

      const parsed = unwrapSegmentWords(words);
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
        });
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

      // Check pipeline feeder into stdin-reading shell (`cat <<EOF | bash`, `echo '...' | bash`, `cat script.sh | bash`)
      if (sIdx > 0 && segments[sIdx - 1].opAfter === '|' && parsed.readsStdinAsCode) {
        if (heredocBodies.length > 0) {
          for (const hd of heredocBodies) {
            heredocScripts.push(hd.body);
            walk(hd.body, depth + 1, [...fullTrail, `pipe-heredoc(${hd.delim})`]);
          }
        } else {
          const prevSeg = segments[sIdx - 1];
          const prevWords = prevSeg.tokens.filter((t) => t.type === 'word').map((t) => t.value);
          const prevParsed = unwrapSegmentWords(prevWords);
          const feederCmd = prevParsed.command || prevWords[0] || '';
          if (feederCmd === 'echo' || feederCmd === 'printf') {
            const hasEchoEsc = feederCmd === 'echo' && prevParsed.args.some((a) => /^-[neE]*e/.test(a));
            const payloadArgs = feederCmd === 'echo'
              ? prevParsed.args.filter((a) => !/^-[neE]+$/.test(a))
              : prevParsed.args;
            let pipedScript = payloadArgs.join(' ');
            if (feederCmd === 'printf' || hasEchoEsc) {
              pipedScript = pipedScript.replace(/\\n/g, '\n').replace(/\\t/g, '\t');
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
    }

    for (const sub of substitutions) {
      walk(sub, depth + 1, [...trail, '$()']);
    }
  }

  walk(String(script || ''), 0, []);
  return { records, heredocScripts, maxObservedDepth: records.reduce((m, r) => Math.max(m, r.depth), 0) };
}
