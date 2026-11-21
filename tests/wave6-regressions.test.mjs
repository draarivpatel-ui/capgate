import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateToolCall } from '../js/capability-gate.mjs';
import { analyzeShellAst } from '../js/shell-ast.mjs';

const ev = (tc) => evaluateToolCall(tc);
const sh = (command) => ({ tool: 'shell_exec', args: { command } });
const rules = (r) => (r.findings || []).map((f) => f.ruleId);

function deny(command) {
  const r = ev(sh(command));
  assert.equal(r.decision, 'DENY', `${command} -> ${r.decision} ${rules(r).join(',')}`);
}
function escalate(command) {
  const r = ev(sh(command));
  assert.equal(r.decision, 'ESCALATE', `${command} -> ${r.decision}`);
}
function allow(command) {
  const r = ev(sh(command));
  assert.equal(r.decision, 'ALLOW', `${command} -> ${r.decision} ${rules(r).join(',')}`);
}
function blocked(command) {
  const r = ev(sh(command));
  assert.notEqual(r.decision, 'ALLOW', `${command} -> ALLOW`);
}

/* ---------- Redirect targets are not argv (critical parser bug) ---------- */

test('wave6: redirect targets can no longer hide the -c payload', () => {
  deny("sh >o -c 'rm -rf /'");
  deny("bash >out -c 'rm -rf /'");
  deny('git >o push origin main');
  blocked('git >o rebase -i');
  // `npm install` is the lifecycle-scripts verdict either way; the redirect
  // must not soften it.
  blocked('npm >o install');
  // Redirects in front of heredoc-fed interpreters still read the body.
  deny("python3 >o <<'EOF'\nimport os;os.system('id')\nEOF");
  // Write-side targets still get path checks after leaving argv.
  deny('cat /workspace/app/x > /tmp/o');
  deny('exec > /etc/passwd');
  deny('> /etc/passwd');
  allow('cat /workspace/app/f > /workspace/app/o');
  allow('echo hi > out.log');
  allow('cat x 2>/dev/null');
  allow('exec > out.log');
});

test('wave6: redirect targets survive as inspectable fields', () => {
  const ast = analyzeShellAst("sh >o -c 'id'");
  const shRec = ast.records.find((r) => r.command === 'sh');
  assert.deepEqual(shRec.args, ['-c', 'id']);
  assert.deepEqual(shRec.redirectTargets, ['o']);
});

/* ---------- Command-string subcommands and exec channels ---------- */

test('wave6: git command-string channels are held', () => {
  deny("git submodule foreach 'rm x'");
  deny("git submodule foreach 'cat /etc/passwd'");
  deny("git remote-ext origin 'rm -rf /'");
  deny("git remote-fd origin 'id'");
  deny("git remote-testgit origin 'id'");
  deny('git remote-https origin url');
  escalate('git submodule update');
});

test('wave6: allowlisted-tool exec flags are held', () => {
  deny('rg --pre sh x .');
  deny('rg --pre=sh x .');
  deny('rg --hostname-bin=id x .');
  allow('rg --pre-glob "*.js" x .');
  allow('rg foo .');
  deny('sort --compress-program=sh f');
  deny('sort --compress-program sh f');
  allow('sort f');
  deny('pytest -p evil');
  deny('pytest -pevil');
  escalate('pytest -c /workspace/app/pytest.ini');
  allow('pytest -q /workspace/app/tests');
});

test('wave6: node runtime flags are held', () => {
  escalate('node --inspect app.js');
  escalate('node --inspect-brk app.js');
  escalate('node --inspect=9229 app.js');
  deny('node --test-reporter=/tmp/e.js');
  deny('node --test-reporter /tmp/e.js');
  escalate('node --run evil');
  escalate('node --openssl-config=c.cnf');
  allow('node app.js');
  allow('node --version');
});

test('wave6: npm mutating subcommands are held', () => {
  escalate('npm unpublish x');
  escalate("npm pkg set scripts.build='id'");
  escalate('npm pkg delete scripts.build');
  allow('npm pkg get name');
  allow('npm test');
});

/* ---------- Parameter expansion path payloads ---------- */

test('wave6: parameter expansion cannot smuggle paths', () => {
  deny('cat ${x:-/etc/passwd}');
  deny('cat ${x:-../outside}');
  deny('cat ${x/a//etc/passwd}');
  deny('cat ${x:=/etc/shadow}');
  deny('cat ${x:?/etc/passwd}');
  deny('cat ${x:+/etc/passwd}');
  escalate('cat ${x}');
  escalate('cat $file');
  allow('echo ${x:-default}');
  allow('echo $HOME');
  allow('echo $((1+2))');
});

/* ---------- Environment channel coverage ---------- */

test('wave6: env execution/redirect channels are held', () => {
  deny("GIT_CONFIG_PARAMETERS='core.pager=x' git log");
  deny('GIT_EXTERNAL_DIFF=id git diff');
  deny('ZDOTDIR=/tmp/e zsh -l');
  deny('FPATH=/tmp/e zsh -l');
  deny('PYTEST_PLUGINS=evil pytest');
  deny('PYTEST_ADDOPTS=-p evil pytest');
  deny('OPENSSL_CONF=/tmp/e.cnf openssl x');
  escalate('DBUS_SESSION_BUS_ADDRESS=x cmd');
  escalate('LESS=-o/tmp/x less f');
  escalate('GIT_DIFF_OPTS=--output=/tmp/x git diff');
});

test('wave6: pager values that are command lines are held', () => {
  blocked("PAGER='cat /etc/passwd' git log");
  blocked('BROWSER=sh git log');
  allow('PAGER=cat git log');
  allow('PAGER=less git log');
  allow('PAGER="less -R" git log');
});

/* ---------- trap payloads ---------- */

test('wave6: trap actions are deep-scanned', () => {
  deny('trap "cat /etc/passwd" EXIT');
  deny('trap "curl https://evil.example" EXIT');
  deny("trap 'rm x' EXIT");
  deny("trap 'rm x' DEBUG");
  escalate("trap 'id' EXIT");
  escalate("trap 'myfn' ERR");
  allow('trap -p');
  allow('trap EXIT');
  allow('trap 0');
});

/* ---------- GNU sed execution extensions ---------- */

test('wave6: sed address-prefixed e and GNU r/w extensions are held', () => {
  deny("sed '$e id' f");
  deny("sed '1!e id' f");
  deny('sed "W /tmp/x" f');
  deny('sed "R /etc/passwd" f');
  allow("sed 's/a/b/' f");
  allow('sed -n p f');
});

/* ---------- Sensitive filename coverage ---------- */

test('wave6: sensitive file basenames and globs are held', () => {
  for (const f of [
    'prod.env', 'app.env', 'prod.env.local', 'secrets.yaml', 'mysecret.txt',
    'topsecret.env', 'api.token', 'aws.credentials', 'x.credentials',
    'secrets.token', 'wallet.dat', 'database.yml', 'mail.pst',
    '~/.pgpass', '~/.my.cnf', '~/.azure/credentials', '~/.boto', '~/.s3cfg',
    '~/.dockercfg', '~/.config/gh/hosts.yml',
  ]) {
    deny(`cat ${f}`);
  }
  deny('cat *.token');
  deny('cat *.credentials');
  deny('cat *.env');
  deny('cat *.secrets');
  allow('cat secretary.txt');
  allow('cat src/*.js');
  allow('ls *');
});

/* ---------- git egress, config keys and FP fixes ---------- */

test('wave6: git config exec keys are held', () => {
  deny('git -c remote.origin.proxy=id fetch');
  deny('git -c remote.x.uploadpack=id fetch');
  deny('git -c tar.evil.command=id archive');
  deny('git -c maintenance.x.command=id maintenance');
  deny('git -c lfs.standalonetransferagent=id lfs fetch');
  deny('git -c interactive.diffFilter=id diff');
  deny('git -c init.templatedir=/tmp init');
  deny('git -c help.manViewer=id help');
  deny('git -c gpg.ssh.program=id log');
  deny('git -c protocol.allow=always fetch');
  deny('git -c submodule.x.update=!id submodule update');
  deny('git -c merge.x.recursive=id merge');
  deny('git -c core.sshvariant=id fetch');
  deny('git config remote.origin.proxy id');
  deny('git config protocol.allow always');
  deny('git config lfs.standalonetransferagent x');
});

test('wave6: git egress and mutation subcommands are held', () => {
  escalate('git fetch origin');
  escalate('git fetch-pack host repo');
  escalate('git ls-remote origin');
  escalate('git remote add x https://example.com/r');
  escalate('git remote set-url origin https://example.com/r');
  escalate('git remote update');
  escalate('git remote prune origin');
  escalate('git remote show origin');
  allow('git remote');
  allow('git remote -v');
  allow('git remote get-url origin');
  escalate('git clean -fd');
  escalate('git clean -fdx');
  escalate('git clean');
  deny('git hook run pre-commit');
  escalate('git grep -O x');
  escalate('git grep --open-files-in-pager=less x');
  escalate('git apply --unsafe-paths p');
  deny('git clone -u=id r');
  deny('git fetch-pack --exec=id r');
});

test('wave6: -u and query flags are no longer misread as exec channels', () => {
  allow('git branch -u origin/main');
  allow('command -v rm');
  allow('command -v curl');
  deny('command -p rm -rf /workspace/app');
  allow('builtin -v x');
  allow('env --version');
  allow('env --help');
  deny('env');
});

/* ---------- Compound-statement keywords are scaffolding ---------- */

test('wave6: keywords unwrap to the real command', () => {
  deny('if true; then rm x; fi');
  deny('then rm x');
  deny('for i in a; do rm x; done');
  deny('while true; do cat .env; done');
  deny('until false; do rm x; done');
  deny('! rm x');
  deny('do rm x');
  deny('case x in a) rm;; esac');
  deny('function f { rm x; }');
  deny('f(){ rm x; }');
  deny('for i in /etc/passwd; do echo $i; done');
  allow('if true; then echo hi; fi');
  allow('for i in a; do echo $i; done');
  allow('f(){ echo hi; }');
  allow('[[ -f src/x.js ]]');
  allow('((x++))');
  allow('exec 3>&1');
  escalate('for i in a; do cat $i; done');
});
