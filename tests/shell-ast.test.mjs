import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeShellAst, decodeWord } from '../js/shell-ast.mjs';

test('decodeWord strips quotes and escapes without losing literal chars', () => {
  assert.equal(decodeWord(`r'm'`), 'rm');
  assert.equal(decodeWord(`"../etc"`), '../etc');
  assert.equal(decodeWord(`.\\./secret`), '../secret');
  assert.equal(decodeWord(`'a\\"b'`), 'a\\"b');
});

test('analyzeShellAst unwraps chained wrappers with value flags', () => {
  const ast = analyzeShellAst('timeout -k 5 10 env FOO=1 nohup ionice -c 3 pkill -9 node');
  assert.equal(ast.records.length, 1);
  assert.equal(ast.records[0].command, 'pkill');
  assert.deepEqual(ast.records[0].trail, ['timeout', 'env', 'nohup', 'ionice', 'pkill']);
});

test('analyzeShellAst extracts heredoc piped to stdin-reading shell', () => {
  const ast = analyzeShellAst("cat <<'EOF' | bash -s\ncurl http://169.254.169.254/latest\nEOF");
  const cmds = ast.records.map((r) => r.command);
  assert.ok(cmds.includes('bash'));
  assert.ok(cmds.includes('curl'));
  assert.equal(ast.heredocScripts.length, 1);
});

test('analyzeShellAst does NOT treat non-shell cat heredoc as executable code', () => {
  const ast = analyzeShellAst("cat <<'EOF'\nsudo rm -rf /\nEOF");
  assert.equal(ast.records.length, 1);
  assert.equal(ast.records[0].command, 'cat');
  assert.equal(ast.heredocScripts.length, 0);
});

test('analyzeShellAst extracts command substitution inside double-quoted echo', () => {
  const ast = analyzeShellAst('echo "val=$(cat /etc/shadow)"');
  const cmds = ast.records.map((r) => r.command);
  assert.ok(cmds.includes('echo'));
  assert.ok(cmds.includes('cat'));
});

test('analyzeShellAst handles clustered shell options before -c', () => {
  const ast = analyzeShellAst('bash -euo pipefail -c "chmod 777 a.sh"');
  const cmds = ast.records.map((r) => r.command);
  assert.ok(cmds.includes('chmod'));
});

test('analyzeShellAst unwraps env -S, --norc shell flags, here-strings, fd heredocs, and process substitution', () => {
  const envS = analyzeShellAst("env -S 'rm -rf /workspace/app'");
  assert.ok(envS.records.some((r) => r.command === 'rm'));

  const norc = analyzeShellAst("bash --norc --posix -c 'rm -rf /workspace/app'");
  assert.ok(norc.records.some((r) => r.command === 'rm'));

  const hs = analyzeShellAst("bash <<< 'sudo id'");
  assert.ok(hs.records.some((r) => r.trail.includes('sudo')));

  const fdHd = analyzeShellAst("bash 0<<'EOF'\npkill node\nEOF");
  assert.ok(fdHd.records.some((r) => r.command === 'pkill'));

  const procSub = analyzeShellAst('cat <(cat /etc/passwd)');
  assert.ok(procSub.records.some((r) => r.command === 'cat' && r.args.includes('/etc/passwd')));

  const ansiC = analyzeShellAst("bash -c $'sudo id'");
  assert.ok(ansiC.records.some((r) => r.trail.includes('sudo') && r.command === 'id'));

  const pipeEcho = analyzeShellAst("echo 'rm -rf /workspace/app' | bash");
  assert.ok(pipeEcho.records.some((r) => r.command === 'rm'));

  const pipeCat = analyzeShellAst('cat /workspace/app/install.sh | bash');
  assert.ok(pipeCat.records.some((r) => r.command === '__pipe_stdin_shell__'));
});
