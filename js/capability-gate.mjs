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
  maxShellNestingDepth: 2,
});

const SENSITIVE_PATH_PATTERNS = [
  /(^|\/)\.env(\.|$)/i,
  /(^|\/)\.ssh(\/|$)/i,
  /id_rsa|id_ed25519/i,
  /^\/etc\/(passwd|shadow|sudoers)/i,
  /credentials\.json|\.aws\/credentials/i,
  /^\/proc\/self\/environ/i,
];

const SECRET_ENV_NAMES = /(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AWS_ACCESS_KEY_ID|DATABASE_URL)/i;

export function hasTraversalSegment(rawPath) {
  let clean = String(rawPath || '');
  if (!clean) return false;
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(clean);
      if (next === clean) break;
      clean = next;
    } catch {
      break;
    }
  }
  const normalized = clean.replace(/\\/g, '/');
  return normalized.split('/').some((p) => p === '..');
}

export function isSensitivePath(rawPath) {
  const clean = String(rawPath || '').replace(/\\/g, '/').trim();
  if (!clean) return false;
  return SENSITIVE_PATH_PATTERNS.some((re) => re.test(clean));
}

export function isWithinWorkspace(rawPath, workspaceRoot) {
  const clean = String(rawPath || '').replace(/\\/g, '/').trim();
  if (!clean) return true;
  if (hasTraversalSegment(clean)) return false;
  if (!clean.startsWith('/')) return true;
  const root = workspaceRoot.endsWith('/') ? workspaceRoot.slice(0, -1) : workspaceRoot;
  return clean === root || clean.startsWith(`${root}/`);
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

function parseIpv6Groups(hostInput) {
  let host = String(hostInput || '');
  const zone = host.indexOf('%');
  if (zone >= 0) host = host.slice(0, zone);
  if (!host.includes(':') || !/^[0-9a-f:.]+$/.test(host)) return null;

  const lastColon = host.lastIndexOf(':');
  const tail = host.slice(lastColon + 1);
  if (tail.includes('.')) {
    const octets = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(tail) ? tail.split('.').map(Number) : null;
    if (!octets || octets.some((n) => n > 255)) return null;
    const hex = (hi, lo) => ((hi << 8) | lo).toString(16);
    host = `${host.slice(0, lastColon + 1)}${hex(octets[0], octets[1])}:${hex(octets[2], octets[3])}`;
  }

  const halves = host.split('::');
  if (halves.length > 2) return null;
  const toGroups = (text) => (text === '' ? [] : text.split(':'));
  const head = toGroups(halves[0]);
  const rest = halves.length === 2 ? toGroups(halves[1]) : [];
  if ([...head, ...rest].some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  const missing = 8 - head.length - rest.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  return [...head, ...new Array(halves.length === 2 ? missing : 0).fill('0'), ...rest].map((g) => Number.parseInt(g, 16));
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

  // IPv6 literal in any spelling (compressed, zero-padded, zone id, embedded IPv4)
  const groups = parseIpv6Groups(host);
  if (groups) {
    const leadingZero = (count) => groups.slice(0, count).every((g) => g === 0);
    const tailOctets = [groups[6] >> 8, groups[6] & 255, groups[7] >> 8, groups[7] & 255];
    // Unspecified (::) and loopback (::1)
    if (leadingZero(7) && groups[7] <= 1) return true;
    // Link-local (fe80::/10) and unique local (fc00::/7)
    if ((groups[0] & 0xffc0) === 0xfe80 || (groups[0] & 0xfe00) === 0xfc00) return true;
    // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d), and NAT64 (64:ff9b::/96)
    if (
      (leadingZero(5) && (groups[5] === 0xffff || groups[5] === 0)) ||
      (groups[0] === 0x64 && groups[1] === 0xff9b && groups.slice(2, 6).every((g) => g === 0))
    ) {
      return isPrivateIpv4Octets(tailOctets);
    }
    return false;
  }

  // Non-standard IPv4-mapped spelling with the address as one hex word (::ffff:7f000001)
  const mappedHex = /^(?:::ffff:|(?:0+:){5}0*ffff:)([0-9a-f]{5,8})$/.exec(host);
  if (mappedHex) return isPrivateIpv4Octets(intToOctets(Number.parseInt(mappedHex[1], 16)));

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
 * Host of a network target written with any scheme or none: "127.0.0.1:8080", "//host/x",
 * "ftp://user@host/x", "[::1]:80". Returns '' when the text has no host part.
 */
export function extractTargetHost(target) {
  let rest = String(target || '').trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/^\/\//, '');
  rest = rest.split(/[/?#]/)[0];
  const atIdx = rest.lastIndexOf('@');
  if (atIdx >= 0) rest = rest.slice(atIdx + 1);
  if (rest.startsWith('[')) {
    const endBracket = rest.indexOf(']');
    return endBracket > 0 ? rest.slice(0, endBracket + 1) : rest;
  }
  return rest.replace(/:\d*$/, '');
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

  const tool = String(toolCall?.tool || 'shell_exec');
  const args = toolCall?.args || {};

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
    const host = extracted[0]?.host || extractTargetHost(rawUrl) || String(args.host || '');
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

      const blockedInTrail = rec.trail.find((cmdName) => blockedSet.has(cmdName));
      if (blockedInTrail) {
        addFinding('CAP-CMD-01', 'critical', `Blocked command "${blockedInTrail}" detected via AST unwrap`,
          `Blocked command "${blockedInTrail}" found in chain [${rec.trail.join(' -> ')}].`,
          rec.trail, `Remove "${blockedInTrail}" or request explicit human elevation.`);
      } else if (netCmdSet.has(rec.command)) {
        // Inspect URLs / hosts in args
        const urlHits = extractUrlsAndHosts(rec.args.join(' '));
        const internalTargetArg = rec.args.some((a) => !a.startsWith('-') && isPrivateOrInternalHost(extractTargetHost(a)));
        if (policy.blockPrivateIps && (urlHits.some((u) => isPrivateOrInternalHost(u.host)) || internalTargetArg)) {
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

      // Special check: git push / send-pack / dangerous git config manipulation
      if (rec.command === 'git') {
        const { subcommand, rest } = findGitSubcommand(rec.args);
        if ((subcommand === 'push' || subcommand === 'send-pack') && !rest.includes('--dry-run') && !rest.includes('-n')) {
          addFinding('CAP-GIT-01', 'high', `Remote git ${subcommand} requires human review`,
            `${subcommand} detected in [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Stage commits locally and request human approval before pushing.');
        } else if (
          subcommand === 'config' &&
          rest.some((a) => /^(?:alias\.|core\.sshcommand$|core\.fsmonitor$|credential\.)/i.test(a))
        ) {
          addFinding('CAP-GIT-01', 'high', 'Git execution hook/alias configuration requires human review',
            `git config modification detected in [${rec.trail.join(' -> ')}].`,
            rec.trail, 'Do not mutate executable git hooks, aliases, or credential helpers dynamically.');
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
          version: '1.0.0',
          informationUri: 'https://github.com/draarivpatel-ui/capgate',
          rules,
        },
      },
      results,
    }],
  };
}
