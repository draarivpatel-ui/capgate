import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('HTML references only local files and has zero inline JS or event handlers', () => {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  assert.ok(html.includes('href="styles.css"'));
  assert.ok(html.includes('src="js/app.js"'));
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html));
  assert.ok(!/\son[a-z]+\s*=/i.test(html));
  assert.ok(fs.existsSync(path.join(ROOT, 'styles.css')));
  assert.ok(fs.existsSync(path.join(ROOT, 'js/app.js')));
});

test('all DOM IDs used by js/app.js exist in index.html', () => {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  const appJs = fs.readFileSync(path.join(ROOT, 'js/app.js'), 'utf8');
  const ids = [...appJs.matchAll(/document\.getElementById\('([^']+)'\)/g)].map((m) => m[1]);
  assert.ok(ids.length >= 20);
  for (const id of ids) {
    assert.ok(html.includes(`id="${id}"`), `Missing id="${id}" in index.html`);
  }
});

test('all CapGate JS modules parse cleanly', () => {
  const jsFiles = ['js/shell-ast.mjs', 'js/capability-gate.mjs', 'js/corpus.mjs', 'js/benchmark.mjs', 'js/viewmodel.mjs', 'js/app.js'];
  for (const rel of jsFiles) {
    assert.doesNotThrow(() => {
      execFileSync(process.execPath, ['--check', path.join(ROOT, rel)], { stdio: 'pipe' });
    });
  }
});

test('repository hygiene checks pass with zero forbidden punctuation or local path leaks', () => {
  const homePrefixRe = new RegExp(String.fromCharCode(47, 85, 115, 101, 114, 115, 47));
  const mailRe = new RegExp(['gmail', 'icloud'].map((d) => `${d}\\.com`).join('|'), 'i');
  const walk = (dir) => {
    const out = [];
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ent.name === '.git' || ent.name === 'node_modules') continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) out.push(...walk(full));
      else out.push(full);
    }
    return out;
  };
  const textExts = new Set(['.html', '.css', '.js', '.mjs', '.md', '.json', '.txt']);
  for (const file of walk(ROOT)) {
    const ext = path.extname(file).toLowerCase();
    if (!textExts.has(ext) && path.basename(file) !== 'LICENSE') continue;
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.includes('\u2014'), false, `Em-dash in ${file}`);
    assert.equal(text.includes('\u2013'), false, `En-dash in ${file}`);
    assert.equal(homePrefixRe.test(text), false, `Local path in ${file}`);
    assert.equal(mailRe.test(text), false, `Personal email domain in ${file}`);
  }
});

test('page loads nothing from outside the repository and keeps a strict CSP', () => {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  for (const m of html.matchAll(/<(?:script|link)\b[^>]*(?:src|href)="([^"]+)"/g)) {
    assert.equal(/^https?:/i.test(m[1]), false, `external asset ${m[1]}`);
  }
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /style-src 'self'[;"]/);
  assert.ok(!/\sstyle="/i.test(html), 'inline style attributes would be dropped by the CSP');
  const css = fs.readFileSync(path.join(ROOT, 'styles.css'), 'utf8');
  assert.equal(/@import|url\(\s*['"]?https?:/i.test(css), false);
  assert.match(css, /prefers-color-scheme: dark/);
  assert.match(css, /:root\[data-theme="dark"\]/);
  assert.match(css, /prefers-reduced-motion/);
});

test('page has one h1, no skipped heading levels, and a title that stands alone', () => {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  assert.equal((html.match(/<h1\b/g) || []).length, 1);
  const levels = [...html.matchAll(/<h([1-6])\b/g)].map((m) => Number(m[1]));
  for (let i = 1; i < levels.length; i += 1) assert.ok(levels[i] <= levels[i - 1] + 1);
  assert.ok(!/brand-sub|tagline|eyebrow|kicker/.test(html));
});

test('app.js renders untrusted corpus and input text through textContent only', () => {
  const appJs = fs.readFileSync(path.join(ROOT, 'js/app.js'), 'utf8');
  assert.equal(/innerHTML|insertAdjacentHTML|outerHTML/.test(appJs), false);
});
