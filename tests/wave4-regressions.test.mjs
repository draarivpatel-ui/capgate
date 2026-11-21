import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_POLICY,
  evaluateToolCall,
  expandBraceAlternates,
  globMayMatchSensitive,
  pathLikeCandidates,
} from '../js/capability-gate.mjs';
import { analyzeShellAst } from '../js/shell-ast.mjs';

const sh = (command, policy = DEFAULT_POLICY) =>
  evaluateToolCall({ tool: 'shell_exec', args: { command } }, policy);
const deny = (command, policy) => assert.equal(sh(command, policy).blocked, true, command);
const allow = (command, policy) => assert.equal(sh(command, policy).blocked, false, command);
const recordsOf = (command) => analyzeShellAst(command).records;

/* Glued and clustered -c ------------------------------------------------- */

test('wave4: glued -c payload on a shell is unwrapped and judged', () => {
  const records = recordsOf("bash -c'rm -rf /workspace/app/x'");
  assert.ok(records.some((r) => r.command === 'rm'), 'rm payload must surface');
  deny("bash -c'rm -rf /workspace/app/x'");
});

test('wave4: -c mid-cluster consumes the cluster rest as the command', () => {
  const records = recordsOf('bash -crm');
  assert.ok(records.some((r) => r.command === 'rm'));
  deny('bash -crm');
});

test('wave4: -c at cluster end takes the next argv as the command', () => {
  const records = recordsOf('bash -euc rm');
  assert.ok(records.some((r) => r.command === 'rm'));
  deny('bash -euc rm');
});

test('wave4: later -c words are positional, first -c wins (bash semantics)', () => {
  const ev = sh("bash -c 'echo ok' -c 'echo two'");
  assert.equal(ev.blocked, false);
  const records = recordsOf("bash -c 'echo ok' -c 'rm'");
  assert.ok(records.every((r) => r.command !== 'rm'), 'positional -c payload must not run');
});

test('wave4: glued -c with spaces decodes to its real payload', () => {
  const records = recordsOf("sh -c'cat /etc/passwd'");
  assert.ok(records.some((r) => r.command === 'cat' && r.args.includes('/etc/passwd')));
  deny("sh -c'cat /etc/passwd'");
});

test('wave4: zsh/dash style glued -c also unwraps', () => {
  for (const cmd of ["zsh -c'rm x'", "dash -c'rm x'", "ksh -c'rm x'"]) {
    const records = recordsOf(cmd);
    assert.ok(records.some((r) => r.command === 'rm'), cmd);
  }
});

test('wave4: cluster -c glued value containing a path is judged', () => {
  deny('bash -ccat /etc/passwd');
});

test('wave4: -o value flags are consumed, not mistaken for -c', () => {
  // `-o nounset` then `-c rm`: the -o value must not swallow -c.
  const records = recordsOf('bash -o nounset -c rm');
  assert.ok(records.some((r) => r.command === 'rm'));
  deny('bash -o nounset -c rm');
});

test('wave4: +o option cluster does not break -c detection', () => {
  const records = recordsOf('bash +o xtrace -c rm');
  assert.ok(records.some((r) => r.command === 'rm'));
  deny('bash +o xtrace -c rm');
});

test('wave4: -o glued value consumes its own word only', () => {
  const records = recordsOf('bash -onounset -c rm');
  assert.ok(records.some((r) => r.command === 'rm'));
});

/* Shell rc/init-file startup channels ------------------------------------- */

test('wave4: --rcfile names a startup script held as a code channel', () => {
  const ev = sh('bash --rcfile .evil -i');
  assert.equal(ev.blocked, true);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-CMD-05'));
});

test('wave4: --init-file=value form is also held', () => {
  const ev = sh('bash --init-file=.bashrc_evil -i');
  assert.equal(ev.blocked, true);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-CMD-05'));
});

test('wave4: --rcfile on a sensitive file is critical', () => {
  const ev = sh('bash --rcfile .env -i');
  assert.equal(ev.blocked, true);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-CMD-05' && f.severity === 'critical'));
});

test('wave4: zsh --rcs/--init-file style startup paths are held', () => {
  deny('zsh --rcfile .evil -i');
});

test('wave4: startup record carries the named file for inspection', () => {
  const records = recordsOf('bash --rcfile .evil -i');
  assert.ok(records.some((r) => r.startupScriptFile === '.evil'));
});

/* $IFS / ${IFS} word separators -------------------------------------------- */

test('wave4: unquoted $IFS acts as a word separator', () => {
  const records = recordsOf('cat$IFS/etc/passwd');
  assert.ok(records.some((r) => r.command === 'cat' && r.args.includes('/etc/passwd')));
});

test('wave4: unquoted ${IFS} acts as a word separator', () => {
  const records = recordsOf('cat${IFS}/etc/passwd');
  assert.ok(records.some((r) => r.command === 'cat' && r.args.includes('/etc/passwd')));
});

test('wave4: IFS-glued dangerous reads are denied', () => {
  deny('cat$IFS/etc/passwd');
  deny('cat${IFS}.env');
});

test('wave4: IFS splitting resolves benign words precisely', () => {
  allow('cat${IFS}src/main.js');
});

test('wave4: $IFSX is a variable name, not a separator', () => {
  const records = recordsOf('echo$IFSX ok');
  assert.ok(!records.some((r) => r.command === 'echo' && r.args.includes('ok') && r.args.length === 1) ||
            records.some((r) => r.command.startsWith('echo$')));
});

test('wave4: IFS between command and flag still parses', () => {
  const records = recordsOf('ls$IFS-la');
  assert.ok(records.some((r) => r.command === 'ls' && r.args.includes('-la')));
});

/* Brace operators vs brace expansion -------------------------------------- */

test('wave4: standalone { } group ops still split commands', () => {
  const records = recordsOf('{ cat /etc/passwd; }');
  assert.ok(records.some((r) => r.command === 'cat' && r.args.includes('/etc/passwd')));
});

test('wave4: { glued to a word is literal brace expansion, not grouping', () => {
  const records = recordsOf('cat {x,/etc/shadow}');
  assert.ok(records.some((r) => r.command === 'cat' && r.args.includes('{x,/etc/shadow}')));
});

test('wave4: xargs -I{} placeholder braces stay literal', () => {
  const records = recordsOf('xargs -I{} rm {}');
  assert.ok(records.some((r) => r.command === 'rm' && r.args.includes('{}')));
});

test('wave4: {(subshell)} group form still parses', () => {
  const records = recordsOf('{(cat /etc/passwd);}');
  assert.ok(records.some((r) => r.command === 'cat'));
});

test('wave4: brace alternate {a,/etc/shadow} is denied via expansion', () => {
  deny('cat {x,/etc/shadow}');
  deny('cat {ok,/etc/passwd}');
});

test('wave4: nested braces expand all alternates', () => {
  const out = expandBraceAlternates('{a,b}{c,d}');
  assert.deepEqual(out.sort(), ['ac', 'ad', 'bc', 'bd']);
});

test('wave4: numeric and alpha ranges expand', () => {
  assert.deepEqual(expandBraceAlternates('f{1..3}').sort(), ['f1', 'f2', 'f3']);
  assert.deepEqual(expandBraceAlternates('f{a..c}').sort(), ['fa', 'fb', 'fc']);
});

test('wave4: {a} without a comma stays literal', () => {
  assert.deepEqual(expandBraceAlternates('{a}'), ['{a}']);
});

test('wave4: hostile huge ranges stay bounded and literal', () => {
  const out = expandBraceAlternates('x{1..100000}');
  assert.ok(out.length <= 2, 'range must not explode');
});

test('wave4: brace expansion in pathLikeCandidates surfaces hidden paths', () => {
  const cands = pathLikeCandidates('{x,/etc/shadow}');
  assert.ok(cands.includes('/etc/shadow'));
});

/* Glob-to-sensitive expansion ---------------------------------------------- */

test('wave4: cat .env* is denied (glob reaches dotfile secrets)', () => {
  deny('cat .env*');
  deny('cat .e?*');
  deny('cat .env??????');
});

test('wave4: cat *.env is denied (env-suffixed names are secret-shaped)', () => {
  deny('cat *.env');
});

test('wave4: cat id_* is denied (key-file glob)', () => {
  deny('cat id_*');
});

test('wave4: cat * is held (glob can reach credential files)', () => {
  deny('cat *');
});

test('wave4: globs that cannot reach secrets stay allowed', () => {
  allow('cat src/*.js');
  allow('cat *.txt~'); // tilde suffix does not match sample secrets
});

test('wave4: * never matches leading dots', () => {
  assert.equal(globMayMatchSensitive('*'), true); // reaches id_rsa/environment
  assert.equal(globMayMatchSensitive('*.md'), false);
});

test('wave4: metadata-only commands are exempt from the glob check', () => {
  allow('ls *');
});

test('wave4: glob inside an env-assigned value is still checked', () => {
  const ev = sh('cat F=.env*');
  assert.equal(ev.blocked, true);
});

/* find -exec / -ok / -delete ------------------------------------------------ */

test('wave4: find -exec payload is unwrapped and judged', () => {
  const records = recordsOf('find . -exec rm {} +');
  assert.ok(records.some((r) => r.command === 'rm'));
  deny('find . -exec rm {} +');
});

test('wave4: find -exec ... \\; terminator parses the payload', () => {
  const records = recordsOf('find . -exec rm -f {} \\;');
  assert.ok(records.some((r) => r.command === 'rm' && r.args.includes('-f')));
  deny('find . -exec rm -f {} \\;');
});

test('wave4: find -execdir and -ok variants also unwrap', () => {
  deny('find . -execdir rm {} \\;');
  deny('find . -ok rm {} \\;');
  deny('find . -okdir rm {} \\;');
});

test('wave4: find -delete is held as a delete channel', () => {
  const ev = sh('find . -delete');
  assert.equal(ev.blocked, true);
  assert.ok(ev.findings.some((f) => f.title.includes('find -delete')));
});

test('wave4: find -exec with a benign payload is precise', () => {
  // `find` itself is unlisted -> ESCALATE, but the echo payload adds nothing.
  const ev = sh('find . -exec echo {} \\;');
  assert.equal(ev.decision, 'ESCALATE');
  assert.ok(ev.findings.every((f) => f.severity === 'medium'));
});

test('wave4: find -exec sh -c payload unwraps the nested script', () => {
  deny('find . -exec sh -c "rm -f x" \\;');
});

test('wave4: find -exec unlisted payload escalates', () => {
  const ev = sh('find . -exec id {} \\;');
  assert.equal(ev.decision, 'ESCALATE');
});

/* printf / echo feeder escape decoding -------------------------------------- */

test('wave4: printf hex escapes decode before shell walk', () => {
  deny(String.raw`printf '\x72\x6d -rf /workspace/app' | bash`);
});

test('wave4: printf octal escapes decode before shell walk', () => {
  deny(String.raw`printf '\162\155 -rf /workspace/app' | bash`);
});

test('wave4: echo -e escapes decode before shell walk', () => {
  deny(String.raw`echo -e '\x72\x6d x' | bash`);
});

test('wave4: printf double-backslash produces a literal backslash payload', () => {
  const records = recordsOf(String.raw`printf '\\x69' | bash`);
  assert.ok(records.length > 0);
});

test('wave4: benign printf payload stays precise', () => {
  const ev = sh(String.raw`printf 'echo ok' | bash`);
  assert.equal(ev.decision === 'DENY' && ev.findings.some((f) => f.ruleId === 'CAP-CMD-01'), false);
});

test('wave4: printf without escapes into shell stays inspectable', () => {
  deny("printf 'rm -rf /workspace/app' | bash");
});

/* Wrapper flag tables ------------------------------------------------------- */

test('wave4: flock -x/-s/-n/-u/-o flags do not consume the command', () => {
  deny('flock -x lock rm');
  deny('flock -n lock rm');
  deny('flock -s lock rm');
});

test('wave4: watch non-value flags do not swallow the command', () => {
  const ev = sh('watch --exec id');
  assert.ok(ev.blocked || ev.decision === 'ESCALATE');
  deny('watch -n 1 rm');
});

test('wave4: unshare -R/-e style flags do not swallow the command', () => {
  deny('unshare -R rm');
  deny('unshare -mrm');
});

test('wave4: nsenter -e is not a value flag', () => {
  deny('nsenter -e rm');
});

test('wave4: setpriv --reset-env is not a value flag', () => {
  deny('setpriv --reset-env rm');
});

test('wave4: chrt -m and ionice -t do not swallow the command', () => {
  deny('chrt -m rm');
  deny('ionice -t rm');
});

test('wave4: xargs -e is not a value flag', () => {
  deny('xargs -e rm');
});

test('wave4: ssh-agent -k is not a value flag', () => {
  deny('ssh-agent -k rm');
});

/* Interpreter long cmd flags ------------------------------------------------ */

test('wave4: fish --command= payload unwraps and denies', () => {
  deny('fish --command=rm');
});

test('wave4: fish --command with a separate payload arg unwraps', () => {
  deny('fish --command "rm -rf /workspace/app/x"');
});

test('wave4: fish -c glued payload unwraps', () => {
  const records = recordsOf('fish -crm');
  assert.ok(records.some((r) => r.command === 'rm'));
});

/* Git execution channels ---------------------------------------------------- */

test('wave4: git --upload-pack/-u names a local program (denied)', () => {
  deny('git fetch --upload-pack=id origin');
  deny('git fetch -u id origin');
});

test('wave4: git ext:: transport executes a shell command (critical)', () => {
  const ev = sh('git clone ext::sh x');
  assert.equal(ev.blocked, true);
  assert.ok(ev.findings.some((f) => f.severity === 'critical'));
});

test('wave4: git archive --remote reaches a daemon (held)', () => {
  deny('git archive --remote=https://x HEAD');
});

test('wave4: git archive --remote to an internal host is critical', () => {
  const ev = sh('git archive --remote=http://169.254.169.254/x HEAD');
  assert.equal(ev.blocked, true);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-SSRF-01'));
});

test('wave4: git shell -c is held', () => {
  deny('git shell -c id');
});

test('wave4: git fast-import/svn/p4 helper channels are held', () => {
  deny('git fast-import < stream');
  deny('git svn clone https://x');
  deny('git p4 clone //depot/x');
  deny('git imap-send < patch');
});

test('wave4: git upload-pack/receive-pack daemons are held', () => {
  deny('git upload-pack .');
  deny('git receive-pack .');
});

test('wave4: ordinary git commands stay allowed', () => {
  allow('git status');
  allow('git log --oneline');
  allow('git diff HEAD');
});

/* Config-file channels ------------------------------------------------------- */

test('wave4: curl -K/--config loads attacker options (held)', () => {
  deny('curl -K ./cfg https://api.github.com');
  deny('curl --config=./cfg https://api.github.com');
});

test('wave4: wget --config and -i input-file channels are held', () => {
  deny('wget --config=./cfg https://x');
  deny('wget -i url.list');
});

test('wave4: ssh -F config injection is held', () => {
  deny('ssh -F ./cfg example.com');
  deny('scp -F ./cfg x y');
});

test('wave4: plain allowed network commands still hold their verdict logic', () => {
  const ev = sh('curl https://api.github.com');
  assert.ok(ev.decision !== 'ALLOW' || ev.findings.length === 0 || ev.findings.every((f) => f.severity !== 'critical'));
});

/* awk execution channels ----------------------------------------------------- */

test('wave4: awk system() inside script text is denied', () => {
  deny(`awk 'BEGIN{system("id")}'`);
  deny(`gawk '{ system("rm x") }' file`);
});

test('wave4: awk @include/@load are denied', () => {
  deny(`awk '@include "evil"' file`);
});

test('wave4: awk -f script file channel is held', () => {
  deny('awk -f ./prog.awk file');
});

test('wave4: benign awk usage stays escalate-not-deny', () => {
  const ev = sh(`awk '{print}' file.txt`);
  assert.notEqual(ev.decision, 'DENY');
});

/* xargs -a arg-file channel -------------------------------------------------- */

test('wave4: xargs -a file escalates (argv from uninspected file)', () => {
  const ev = sh('xargs -a src/main.js cat');
  assert.equal(ev.decision, 'ESCALATE');
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-CMD-08'));
});

test('wave4: xargs -a on a sensitive file is still denied by path scan', () => {
  deny('xargs -a .env echo');
});

/* Misc regressions ------------------------------------------------------------ */

test('wave4: eval still unwraps its payload', () => {
  deny('eval "rm -rf /workspace/app/x"');
});

test('wave4: env -S split-string still unwraps', () => {
  deny('env -S "rm -rf /workspace/app/x"');
});

test('wave4: benign commands still allow', () => {
  allow('cat src/main.js');
  allow('ls -la');
  allow('echo hello world');
  allow('wc -l src/*.js');
});

test('wave4: dynamic command names still held', () => {
  const ev = sh('$X --help');
  assert.notEqual(ev.decision, 'ALLOW');
});

test('wave4: process substitution into shell still held', () => {
  const ev = sh('bash <(echo hi)');
  assert.notEqual(ev.decision, 'ALLOW');
});
