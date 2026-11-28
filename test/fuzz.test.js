import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fc from 'fast-check';

import { csvCellSafe } from '../js/audit-export.mjs';
import { evaluateToolCall, isPrivateOrInternalHost } from '../js/capability-gate.mjs';
import { canonicalJson, sha256Hex } from '../js/hash.mjs';
import { analyzeShellAst } from '../js/shell-ast.mjs';

const DEFAULT_FUZZ_SEED = 20261127;

function fuzzSeed() {
  const raw = process.env.FUZZ_SEED;
  if (raw === undefined) return DEFAULT_FUZZ_SEED;
  if (!/^-?\d+$/.test(raw)) throw new Error('FUZZ_SEED must be an integer');
  const seed = Number(raw);
  if (!Number.isSafeInteger(seed)) throw new Error('FUZZ_SEED must be a safe integer');
  return seed;
}

const asciiUnit = fc.constantFrom(
  'a', 'b', 'c', 'x', 'y', 'z', 'A', 'B', 'C', 'X', 'Y', 'Z',
  '0', '1', '2', '7', '8', '9', ' ', '/', '\\', '.', '-', '_', '=', '+', '@', '%', '$', ';', ':'
);
const asciiText = fc.string({ unit: asciiUnit, maxLength: 120 });
const keyText = fc.string({
  unit: fc.constantFrom('a', 'b', 'c', 'k', 'x', 'y', 'z', '0', '1', '2'),
  minLength: 1,
  maxLength: 10,
});

test('fast-check shell parser accepts hostile text without unbounded recursion or malformed records', () => {
  fc.assert(fc.property(fc.string({ maxLength: 120 }), (script) => {
    const maxDepth = 4;
    const ast = analyzeShellAst(script, maxDepth);
    assert.ok(Array.isArray(ast.records));
    assert.ok(Array.isArray(ast.heredocScripts));
    assert.ok(ast.maxObservedDepth <= maxDepth + 1, `depth ${ast.maxObservedDepth} escaped the parser cap`);
    for (const record of ast.records) {
      assert.equal(typeof record.command, 'string');
      assert.ok(Array.isArray(record.args));
      assert.ok(Array.isArray(record.rawWords));
      assert.ok(Array.isArray(record.trail));
      assert.ok(record.depth <= maxDepth + 1, `record depth ${record.depth} escaped the parser cap`);
    }
  }), { seed: fuzzSeed(), numRuns: 100 });
});

test('fast-check traversal chains outside the workspace are always denied', () => {
  fc.assert(fc.property(
    fc.integer({ min: 0, max: 5 }),
    fc.integer({ min: 1, max: 5 }),
    (depth, extraParents) => {
      const path = `/workspace/app/${'a/'.repeat(depth)}${'../'.repeat(depth + extraParents)}leak.txt`;
      const result = evaluateToolCall({ tool: 'fs_read', args: { path } });
      assert.equal(result.decision, 'DENY', `traversal was not denied: ${path}`);
      assert.ok(result.findings.some((finding) => finding.ruleId === 'CAP-PATH-01'));
    }
  ), { seed: fuzzSeed(), numRuns: 100 });
});

test('fast-check encoded private IPv4 literals stay internal and are denied for fetch', () => {
  const octet = fc.integer({ min: 0, max: 255 });
  const privateOctets = fc.oneof(
    fc.tuple(fc.constant(10), octet, octet, octet),
    fc.tuple(fc.constant(127), octet, octet, octet),
    fc.tuple(fc.constant(169), fc.constant(254), octet, octet),
    fc.tuple(fc.constant(172), fc.integer({ min: 16, max: 31 }), octet, octet),
    fc.tuple(fc.constant(192), fc.constant(168), octet, octet),
    fc.tuple(fc.constant(100), fc.integer({ min: 64, max: 127 }), octet, octet)
  );
  fc.assert(fc.property(
    privateOctets,
    fc.constantFrom('dotted', 'integer', 'hex'),
    ([a, b, c, d], style) => {
      let host;
      if (style === 'integer') {
        host = String(a * 0x1000000 + b * 0x10000 + c * 0x100 + d);
      } else if (style === 'hex') {
        host = [a, b, c, d].map((part) => `0x${part.toString(16)}`).join('.');
      } else {
        host = [a, b, c, d].join('.');
      }
      assert.equal(isPrivateOrInternalHost(host), true, `${style} host was not internal: ${host}`);
      const result = evaluateToolCall({ tool: 'http_fetch', args: { url: `http://${host}/` } });
      assert.equal(result.decision, 'DENY', `${style} host was not denied: ${host}`);
      assert.ok(result.findings.some((finding) => finding.ruleId === 'CAP-SSRF-01'));
    }
  ), { seed: fuzzSeed(), numRuns: 100 });
});

test('fast-check canonical JSON is key-order invariant and SHA-256 matches the platform digest', () => {
  fc.assert(fc.property(
    fc.uniqueArray(keyText, { minLength: 2, maxLength: 10 }),
    asciiText,
    (keys, text) => {
      const forward = {};
      const reverse = {};
      keys.forEach((key, index) => { forward[key] = index; });
      [...keys].reverse().forEach((key) => { reverse[key] = forward[key]; });
      assert.equal(canonicalJson(forward), canonicalJson(reverse));
      assert.equal(sha256Hex(text), createHash('sha256').update(text, 'utf8').digest('hex'));
    }
  ), { seed: fuzzSeed(), numRuns: 100 });
});

test('fast-check spreadsheet formula cells are always text-prefixed before export', () => {
  const prefixUnit = fc.constantFrom('', ' ', '\t', '\n', '\u200b', '\u00a0');
  fc.assert(fc.property(
    fc.string({ unit: prefixUnit, maxLength: 3 }),
    fc.constantFrom('=', '+', '-', '@'),
    asciiText,
    (prefix, marker, payload) => {
      const input = prefix + marker + payload;
      const output = csvCellSafe(input);
      assert.ok(output.startsWith('"\''), `dangerous cell was not text-prefixed: ${JSON.stringify(input)} -> ${JSON.stringify(output)}`);
      assert.ok(!/^[\s\u200b\u200c\u200d\u2060\ufeff]*[=+\-@]/.test(output), 'exported cell still begins as a spreadsheet formula');
    }
  ), { seed: fuzzSeed(), numRuns: 100 });
});
