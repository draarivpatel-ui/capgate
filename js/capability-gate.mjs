/**
 * CapGate typed agent capability firewall, SSRF/IP normalizer, path traversal guard,
 * safe-rewrite synthesizer, SARIF 2.1.0 exporter, and comparator baselines.
 * Pure ES module (zero external dependencies).
 */

import { analyzeShellAst, SHELL_BINARIES } from './shell-ast.mjs';

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
  /(^|\/)\.ssh(\/|$)/i,
  /(^|\/)\.aws\/credentials/i,
  /(^|\/)\.gnupg(\/|$)/i,
  /(^|\/)\.docker\/config\.json/i,
  /(^|\/)\.kube\/config/i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.pypirc$/i,
  /(^|\/)\.netrc$/i,
  /id_rsa|id_ed25519|id_ecdsa/i,
  /^\/etc\/(passwd|shadow|gshadow|sudoers|sudoers\.d)/i,
  /^\/etc\/(pki|ssl\/private|ssh\/ssh_host)/i,
  /credentials\.json/i,
  /^\/proc\/self\/environ/i,
  /^\/var\/run\/secrets(\/|$)/i,
  /(^|\/)secrets?\//i,
  /(^|\/)\.git-credentials/i,
];

const SECRET_ENV_NAMES = /(API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|DATABASE_URL|DSN|CREDENTIAL|AUTH)/i;

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
  // Strip NUL and C0/C1 control bytes outright: they have no legitimate role
  // in a path token and are a classic truncation-smuggling trick.
  s = s.replace(/[\u0000-\u001f\u007f-\u009f]/g, '');
  // Map fullwidth and Unicode lookalike separators/dots to ASCII before decoding
  // so `%ef%bc%8f` (fullwidth solidus) and friends cannot smuggle a separator.
  s = s
    .replace(/[／∕⁄]/g, '/')
    .replace(/[．․‥…﹒｡]/g, '.')
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
    .replace(/[．․‥…﹒｡]/g, '.')
    .replace(/[＼∖]/g, '\\');
  // Strip any control/NUL bytes that arrived via percent-decoding (e.g. `%00`).
  s = s.replace(/[\u0000-\u001f\u007f-\u009f]/g, '');
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
  return clean.split('/').some((p) => p === '..');
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
  if (!clean.startsWith('/')) return true;
  const root = String(workspaceRoot || '').replace(/\\/g, '/').replace(/\/+$/, '');
  if (!root) return true;
  const normRoot = root.startsWith('/') ? root : `/${root}`;
  return clean === normRoot || clean.startsWith(`${normRoot}/`);
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

export function isPrivateOrInternalHost(hostInput) {
  let host = String(hostInput || '').trim().toLowerCase();
  if (!host) return false;
  if (host.includes('@')) host = host.slice(host.lastIndexOf('@') + 1);
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  host = host.replace(/\.+$/, '');
  if (!host) return false;

  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return true;
  }

  // IPv6 loopback / unspecified / link-local (fe80::/10) / unique local (fc00::/7)
  if (
    host === '::' ||
    host === '::1' ||
    /^(?:0+:){7}0*[01]$/.test(host) ||
    /^(?:0+:){1,6}:0*1$/.test(host) ||
    /^(?:fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)/.test(host)
  ) {
    return true;
  }

  // IPv4-mapped or IPv4-compatible IPv6 (e.g., ::ffff:127.0.0.1, ::ffff:7f000001, 0:0:0:0:0:ffff:127.0.0.1, ::127.0.0.1)
  const mappedMatch = /^(?:::ffff:|(?:0+:){5}0*ffff:)([0-9a-f.:]+)$/.exec(host) ||
    /^(?:::|(?:0+:){6})([0-9]+\.[0-9.]+)$/.exec(host);
  if (mappedMatch) {
    const sub = mappedMatch[1];
    if (sub.includes('.')) {
      const octets = parseIpv4Literal(sub);
      if (octets) return isPrivateIpv4Octets(octets);
    } else if (/^[0-9a-f]{1,8}$/.test(sub)) {
      const val = Number.parseInt(sub, 16);
      if (Number.isInteger(val)) return isPrivateIpv4Octets(intToOctets(val));
    } else {
      const hexParts = sub.split(':');
      if (hexParts.length === 2 && hexParts.every((p) => /^[0-9a-f]{1,4}$/.test(p))) {
        const hi = Number.parseInt(hexParts[0], 16);
        const lo = Number.parseInt(hexParts[1], 16);
        return isPrivateIpv4Octets([(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255]);
      }
    }
  }

  const octets = parseIpv4Literal(host);
  if (octets) return isPrivateIpv4Octets(octets);
  return false;
}

function isPrivateIpv4Octets([a, b]) {
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

export function extractUrlsAndHosts(text) {
  const hosts = [];
  const urlRe = /https?:\/\/([^\s/?#"']+)/gi;
  for (const m of String(text || '').matchAll(urlRe)) {
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
    hosts.push({ url: m[0], host });
  }
  return hosts;
}

/**
 * Evaluate a single agent tool-call trace against a capability policy.
 */
export function evaluateToolCall(toolCall, policyInput = DEFAULT_POLICY) {
  const policy = { ...DEFAULT_POLICY, ...policyInput };
  const allowedSet = new Set(policy.allowedCommands || []);
  const blockedSet = new Set(policy.blockedCommands || []);
  const netCmdSet = new Set(policy.networkCommands || []);
  const allowedDomains = new Set((policy.allowedDomains || []).map((d) => d.toLowerCase()));

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

      // Secret assignments passed to wrapper binaries (env -i, env FOO=,
      // timeout, command) are consumed by the unwrapper and never reach arg
      // inspection. Check the raw words for `NAME=secret` assignments.
      if (!policy.allowEnvSecrets) {
        for (const w of rec.rawWords) {
          const m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(w);
          if (m && SECRET_ENV_NAMES.test(m[1])) {
            addFinding('CAP-SECRET-02', 'critical', `Secret env assignment "${m[1]}" in ${rec.command}`,
              `Wrapper call injects secret environment variable ${m[1]}.`, rec.trail,
              'Inject scoped mock fixtures instead of passing raw environment secrets.');
            break;
          }
        }
      }

      const blockedInTrail = rec.trail.find((cmdName) => blockedSet.has(cmdName));
      if (blockedInTrail) {
        addFinding('CAP-CMD-01', 'critical', `Blocked command "${blockedInTrail}" detected via AST unwrap`,
          `Blocked command "${blockedInTrail}" found in chain [${rec.trail.join(' -> ')}].`,
          rec.trail, `Remove "${blockedInTrail}" or request explicit human elevation.`);
      } else if (netCmdSet.has(rec.command)) {
        // Inspect URLs / hosts in args
        const urlHits = extractUrlsAndHosts(rec.args.join(' '));
        const bareHostArg = rec.args.find((a) => !a.startsWith('-') && (parseIpv4Literal(a) || a.includes('localhost') || a.includes('169.254')));
        if (policy.blockPrivateIps && (urlHits.some((u) => isPrivateOrInternalHost(u.host)) || (bareHostArg && isPrivateOrInternalHost(bareHostArg)))) {
          addFinding('CAP-SSRF-01', 'critical', `SSRF internal/metadata probe via "${rec.command}"`,
            `Internal or encoded IP target in [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Disallow outbound requests to internal/metadata addresses.');
        } else if (!policy.allowNetwork) {
          const allAllowed = urlHits.length > 0 && urlHits.every((u) => allowedDomains.has(u.host.toLowerCase()));
          if (!allAllowed) {
            addFinding('CAP-NET-01', 'high', `Network utility "${rec.command}" blocked by offline capability policy`,
              `Command [${rec.trail.join(' -> ')}] attempts network egress without allowNetwork.`,
              rec.trail, 'Run offline or add explicit domain allowlist entry.');
          }
        }
      } else if (!allowedSet.has(rec.command) && !SHELL_BINARIES.has(rec.command)) {
        addFinding('CAP-CMD-02', 'medium', `Unlisted command "${rec.command}" outside capability allowlist`,
          `Command "${rec.command}" at [${rec.trail.join(' -> ')}] is not in allowedCommands.`,
          rec.trail, `Either add "${rec.command}" to allowedCommands or replace with an allowed tool.`);
      }

      // Inspect path arguments & redirection targets (including for `echo` redirects and secret expansion)
      for (const arg of rec.args) {
        if (arg.startsWith('-')) continue;
        if (hasTraversalSegment(arg)) {
          addFinding('CAP-PATH-01', 'critical', `Path traversal ".." detected in ${rec.command} argument`,
            `Normalized token "${arg}" in [${rec.trail.join(' -> ')}] contains "..".`,
            rec.trail, 'Use canonical workspace-relative paths without traversal.');
        } else if (arg.startsWith('/') && !isWithinWorkspace(arg, policy.workspaceRoot) && !arg.startsWith('/dev/null')) {
          addFinding('CAP-PATH-02', 'high', `Outside-workspace path "${arg}" in ${rec.command}`,
            `Path escapes "${policy.workspaceRoot}" at [${rec.trail.join(' -> ')}].`,
            rec.trail, `Keep file arguments inside ${policy.workspaceRoot}.`);
        }
        if (isSensitivePath(arg)) {
          addFinding('CAP-SECRET-01', 'critical', `Sensitive file path "${arg}" referenced by ${rec.command}`,
            `Credential/system target at [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Do not pass secret or system credential files to shell commands.');
        }
        if (!policy.allowEnvSecrets && /\$\{?([A-Z0-9_]+)\}?/.test(arg) && SECRET_ENV_NAMES.test(arg)) {
          addFinding('CAP-SECRET-02', 'critical', `Secret env expansion "${arg}" in ${rec.command}`,
            `Command interpolates a secret environment variable.`,
            rec.trail, 'Avoid expanding secret variables in shell arguments.');
        }
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

      // Special check: git push / send-pack / dangerous git config manipulation
      if (rec.command === 'git') {
        const { subcommand, rest } = findGitSubcommand(rec.args);
        if ((subcommand === 'push' || subcommand === 'send-pack') && !rest.includes('--dry-run') && !rest.includes('-n')) {
          addFinding('CAP-GIT-01', 'high', `Remote git ${subcommand} requires human review`,
            `${subcommand} detected in [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Stage commits locally and request human approval before pushing.');
        } else if (subcommand === 'config' && rest.some((a) => GIT_DANGEROUS_CONFIG_KEYS.test(a))) {
          addFinding('CAP-GIT-01', 'high', 'Git execution hook/alias configuration requires human review',
            `git config modification detected in [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Do not mutate executable git hooks, aliases, pagers, or credential helpers dynamically.');
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
          if (a.startsWith('--config-env=')) {
            const key = a.slice('--config-env='.length).split('=')[0];
            if (GIT_DANGEROUS_CONFIG_KEYS.test(key)) {
              addFinding('CAP-GIT-01', 'high', `git --config-env ${key} overrides executable config`,
                `git --config-env [${rec.trail.join(' -> ')}] sets a hook/pager/alias key.`,
                rec.trail, 'Avoid config-env overrides of pager, editor, alias, or credential keys.');
            }
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

const GIT_GLOBAL_VALUE_FLAGS = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env']);

/** Keys whose git config value can execute code or redirect a hook. */
const GIT_DANGEROUS_CONFIG_KEYS = /^(?:alias\.|core\.(?:sshcommand|fsmonitor|pager|editor|askpass|excludesfile|attributesfile)|credential\.|pager\.|diff\.external|textconv\.|filter\.|merge\.driver|sendemail\.)/i;

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
  ['ruby', ['-e', '-r']],
  ['perl', ['-e', '-E']],
  ['php', ['-r', '-f']],
  ['lua', ['-e', '-l']],
  ['Rscript', ['-e']],
  ['deno', ['eval', 'run']],
  ['bun', ['-e', 'run']],
]);

/**
 * If a command is an interpreter carrying inline code (or an `npm run`/`npx`
 * script), return the code payload and a human label. Otherwise null.
 */
function extractInlineCode(rec) {
  if (!rec || !rec.command) return null;
  const cmd = rec.command;
  const args = rec.args || [];

  if (cmd === 'npm' || cmd === 'npx' || cmd === 'pnpm' || cmd === 'yarn') {
    // `npm run <script>`, `npm test`, `npx <pkg>` execute package-defined code.
    // `npm test` and `npm start` are conventional safe entrypoints; an arbitrary
    // `npm run <name>` or `npx <pkg>` runs unknown code and must escalate.
    const runIdx = args.findIndex((a) => a === 'run' || a === 'run-script');
    if (runIdx >= 0) {
      const scriptName = args[runIdx + 1] || '';
      if (['test', 'start'].includes(scriptName)) return null;
      return { kind: 'npm-script', code: `package script: ${scriptName || 'default'}`, command: cmd };
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
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (flags.includes(a)) {
      const code = args[i + 1] || '';
      return { kind: 'inline', code, command: cmd };
    }
    // Combined short flag like `-cCODE` (python3 -c"code")
    for (const f of flags) {
      if (f.startsWith('-') && !f.startsWith('--') && a.startsWith(f) && a.length > f.length) {
        return { kind: 'inline', code: a.slice(f.length), command: cmd };
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
