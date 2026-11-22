import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256Hex, hmacSha256Hex, canonicalJson } from '../js/hash.mjs';

/* FIPS 180-4 and RFC 4231 known-answer vectors ------------------------------ */

const SHA256_KAT = [
  ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
  ['abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu', 'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1'],
];

for (const [msg, want] of SHA256_KAT) {
  test(`sha256 FIPS KAT: ${msg.length}-byte message`, () => {
    assert.equal(sha256Hex(msg), want);
  });
}

test('sha256: one million a characters matches the FIPS vector', () => {
  assert.equal(sha256Hex('a'.repeat(1_000_000)), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
});

test('sha256: multibyte UTF-8 input matches the reference digest', () => {
  // Reference digest computed with Node crypto over the UTF-8 encoding.
  assert.equal(sha256Hex('caf\u00e9 \u2603'), 'ce335642bab85530c756f72c1afb3bfc2067dd39b92e2368e4475c8dbeacc48e');
});

test('sha256: digest is 64 lowercase hex chars', () => {
  assert.match(sha256Hex('anything'), /^[0-9a-f]{64}$/);
});

test('sha256: null and undefined hash like empty string', () => {
  assert.equal(sha256Hex(null), sha256Hex(''));
  assert.equal(sha256Hex(undefined), sha256Hex(''));
});

const HMAC_KAT = [
  {
    name: 'RFC 4231 case 1',
    key: '\x0b'.repeat(20),
    msg: 'Hi There',
    want: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  },
  {
    name: 'RFC 4231 case 2',
    key: 'Jefe',
    msg: 'what do ya want for nothing?',
    want: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  },
  {
    name: 'key longer than block size (verified against Node crypto)',
    key: 'k'.repeat(131),
    msg: 'Test Using Larger Than Block-Size Key - Hash Key First',
    want: '70e4b005732fa7ff79392aa24fb240159b925dbc9f1398420c0f45e6763dcf14',
  },
  {
    name: 'widely published string vector',
    key: 'key',
    msg: 'The quick brown fox jumps over the lazy dog',
    want: 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8',
  },
  {
    name: 'empty key and message',
    key: '',
    msg: '',
    want: 'b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad',
  },
];

for (const v of HMAC_KAT) {
  test(`hmac-sha256 ${v.name}`, () => {
    assert.equal(hmacSha256Hex(v.key, v.msg), v.want);
  });
}

test('hmac-sha256: keys longer than the block size are hashed down', () => {
  const long = 'k'.repeat(100);
  assert.equal(hmacSha256Hex(long, 'm'), hmacSha256Hex(long, 'm'));
  assert.match(hmacSha256Hex(long, 'm'), /^[0-9a-f]{64}$/);
});

/* canonicalJson --------------------------------------------------------------- */

test('canonicalJson: object key order does not change the digest', () => {
  const a = canonicalJson({ b: 1, a: { d: 2, c: [3, { y: 1, x: 2 }] } });
  const b = canonicalJson({ a: { c: [3, { x: 2, y: 1 }], d: 2 }, b: 1 });
  assert.equal(a, b);
});

test('canonicalJson: arrays keep their order', () => {
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
});

test('canonicalJson: undefined and function values drop like JSON.stringify', () => {
  assert.equal(canonicalJson({ a: undefined, b: () => 1 }), '{}');
  assert.equal(canonicalJson({ a: undefined }), canonicalJson({}));
});

test('canonicalJson: depth cap throws instead of overflowing the stack', () => {
  let deep = {};
  let cur = deep;
  for (let i = 0; i < 400; i += 1) { cur.n = {}; cur = cur.n; }
  assert.throws(() => canonicalJson(deep));
});

test('canonicalJson: null, booleans, numbers and strings round-trip', () => {
  assert.equal(canonicalJson(null), 'null');
  assert.equal(canonicalJson(true), 'true');
  assert.equal(canonicalJson(3.5), '3.5');
  assert.equal(canonicalJson('x'), '"x"');
});
