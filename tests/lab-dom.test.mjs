import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const labJs = fs.readFileSync(path.join(ROOT, 'js/lab.js'), 'utf8');
const css = fs.readFileSync(path.join(ROOT, 'styles.css'), 'utf8');

test('lab: index.html mounts the attack-lab section with a deploy marker', () => {
  assert.ok(html.includes('id="attack-lab"'));
  assert.ok(html.includes('data-deploy="attack-lab-v1"'));
});

test('lab: lab.js is loaded as a module script after app.js', () => {
  assert.ok(html.includes('src="js/lab.js"'));
  assert.ok(html.indexOf('src="js/app.js"') < html.indexOf('src="js/lab.js"'));
});

test('lab: every DOM id used by lab.js exists in index.html', () => {
  const ids = [...labJs.matchAll(/document\.getElementById\('([^']+)'\)/g)].map((m) => m[1]);
  assert.ok(ids.length >= 15);
  for (const id of ids) {
    assert.ok(html.includes(`id="${id}"`), `missing id="${id}"`);
  }
});

test('lab: lab.js never parses attacker text as markup', () => {
  assert.equal(/innerHTML|insertAdjacentHTML|outerHTML|document\.write|\beval\(/.test(labJs), false);
});

test('lab: the lattice SVG is built through createElementNS, not string markup', () => {
  assert.ok(labJs.includes('createElementNS'));
  assert.equal(/<svg/.test(labJs), false);
});

test('lab: new modules parse cleanly with node --check', () => {
  for (const rel of ['js/attack-lab.mjs', 'js/lattice-view.mjs', 'js/policy-report.mjs', 'js/self-tests.mjs', 'js/lab.js']) {
    assert.doesNotThrow(() => execFileSync(process.execPath, ['--check', path.join(ROOT, rel)], { stdio: 'pipe' }), rel);
  }
});

test('lab: CSP is unchanged and still forbids connections and inline handlers', () => {
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /default-src 'self'/);
  const labSection = html.slice(html.indexOf('id="attack-lab"'));
  assert.ok(!/\son[a-z]+\s*=/i.test(labSection), 'inline handler in lab section');
  assert.ok(!/\sstyle="/i.test(labSection), 'inline style attribute in lab section');
});

test('lab: heading order stays legal with the new section (h1 then h2s then h3s)', () => {
  const levels = [...html.matchAll(/<h([1-6])\b/g)].map((m) => Number(m[1]));
  for (let i = 1; i < levels.length; i += 1) {
    assert.ok(levels[i] <= levels[i - 1] + 1, `h${levels[i - 1]} -> h${levels[i]} skips a level`);
  }
});

test('lab: lab selects and textarea carry accessible labels', () => {
  // Labels wrap their controls with a span caption in this codebase.
  assert.match(html, /<label[^>]*lab-compare-field[^>]*>\s*<span>[^<]+<\/span>\s*<select id="lab-compare-select"/);
  assert.match(html, /<label[^>]*lab-compare-field[^>]*>\s*<span>[^<]+<\/span>\s*<select id="lab-chain-select"/);
  assert.match(html, /<textarea id="lab-verify-input"[^>]*aria-label="[^"]+"/);
  assert.match(html, /<svg id="lab-lattice"[^>]*aria-label="[^"]+"/);
});

test('lab: chain grid, diff matrix and self-test list exist in markup', () => {
  for (const id of ['lab-chain-grid', 'lab-diff-matrix', 'lab-selftest-list', 'lab-lattice', 'lab-legend']) {
    assert.ok(html.includes(`id="${id}"`), id);
  }
});

test('lab: styles define the lab classes and keep lattice in a scroll container', () => {
  for (const cls of ['.lab-policy-cards', '.lab-chain-grid', '.lab-diff', '.lat-edge', '.lat-node-box', '.lab-legend', '.lab-selftest-list']) {
    assert.ok(css.includes(cls), cls);
  }
  assert.match(css, /\.lattice-scroll/);
});

test('lab: edge classes cover the three edge statuses and chain marks', () => {
  for (const cls of ['.lat-edge.edge-open', '.lat-edge.edge-blocked', '.lat-edge.edge-held', '.lat-edge.chain-traversed', '.lat-edge.chain-halted', '.lat-edge.chain-pending']) {
    assert.ok(css.includes(cls), cls);
  }
});

test('lab: status chip classes cover all five step statuses', () => {
  for (const cls of ['.status-allowed', '.status-denied', '.status-held', '.status-budget', '.status-skipped']) {
    assert.ok(css.includes(cls), cls);
  }
});

test('lab: mobile breakpoints collapse the lab grids', () => {
  assert.match(css, /@media \(max-width: 860px\)[\s\S]*\.lab-chain-grid\s*\{\s*grid-template-columns:\s*minmax\(0, 1fr\)/);
  assert.match(css, /@media \(max-width: 560px\)[\s\S]*\.lab-policy-cards/);
});

test('lab: the section keeps the honest static-analysis disclosure nearby', () => {
  assert.ok(html.includes('deterministic'));
  assert.ok(html.includes('scope-note'));
});
