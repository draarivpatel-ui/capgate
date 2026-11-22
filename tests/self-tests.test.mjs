import test from 'node:test';
import assert from 'node:assert/strict';
import { runSelfTests, SELF_TEST_COUNT } from '../js/self-tests.mjs';

const rows = runSelfTests();

test('self-tests: runner returns one row per registered check', () => {
  assert.equal(rows.length, SELF_TEST_COUNT);
  assert.ok(rows.length >= 20);
});

test('self-tests: every row has id, name, pass and detail', () => {
  for (const r of rows) {
    assert.ok(typeof r.id === 'string' && r.id.length > 0);
    assert.ok(typeof r.name === 'string' && r.name.length > 5);
    assert.ok(typeof r.pass === 'boolean');
    assert.ok(typeof r.detail === 'string');
  }
});

test('self-tests: check ids are unique', () => {
  assert.equal(new Set(rows.map((r) => r.id)).size, rows.length);
});

for (const row of rows) {
  test(`self-test passes in Node: ${row.id} - ${row.name}`, () => {
    assert.equal(row.pass, true, row.detail);
  });
}
