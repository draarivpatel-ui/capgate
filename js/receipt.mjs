/**
 * Verifiable integrity receipts for CapGate policy decisions.
 *
 * The receipt is signed with an HMAC whose key is derived from the exact policy
 * and evaluation payload. Because the key is public-by-construction (derived
 * from data in the receipt itself), this is NOT a security signature against a
 * malicious author, but it IS a strong tamper-evidence check: any edit to any
 * covered field changes the derived key or the canonical payload, so the
 * embedded digest will no longer match. A judge can paste a receipt into the
 * verify panel and immediately see VALID or TAMPERED with the changed field.
 */

import { canonicalJson, sha256Hex, hmacSha256Hex } from './hash.mjs';

export const TOOL_VERSION = '1.1.0';

const DIGEST_ALGORITHM = 'SHA-256+HMAC-SHA256';
const DIGEST_KEYS = new Set(['algorithm', 'canonicalJson', 'signature']);

const COVERED_FIELDS = ['tool', 'version', 'policy', 'inspectedToolCall', 'evaluation', 'benchmark'];

/** Deterministic key derived from the canonical covered payload. */
function receiptKey(payload) {
  return `capgate-v1:${sha256Hex(canonicalJson(payload))}`;
}

/** Build a signed receipt object for one inspected call and its benchmark. */
export function buildReceipt({ policy, toolCall, evaluation, benchmark }) {
  const payload = {
    tool: 'CapGate',
    version: TOOL_VERSION,
    policy: policy ?? null,
    inspectedToolCall: toolCall ?? null,
    evaluation: evaluation ?? null,
    benchmark: benchmark ?? null,
  };
  const canonical = canonicalJson(payload);
  const bodyHash = sha256Hex(canonical);
  const signature = hmacSha256Hex(receiptKey(payload), canonical);
  return {
    ...payload,
    digest: {
      algorithm: DIGEST_ALGORITHM,
      canonicalJson: bodyHash,
      signature,
    },
  };
}

/**
 * Verify a receipt. Returns VALID, TAMPERED, or MALFORMED with the list of
 * top-level fields that differ from the recomputed values.
 */
export function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt) || !receipt.digest) {
    return { status: 'MALFORMED', changedFields: ['digest'], detail: 'Receipt has no digest object.' };
  }
  const digest = receipt.digest;
  if (typeof digest !== 'object' || Array.isArray(digest)) {
    return { status: 'MALFORMED', changedFields: ['digest'], detail: 'Receipt digest is not an object.' };
  }
  const payload = {};
  for (const field of COVERED_FIELDS) {
    if (field in receipt) payload[field] = receipt[field];
  }
  if (!('tool' in payload) || !('version' in payload)) {
    return { status: 'MALFORMED', changedFields: ['tool', 'version'], detail: 'Receipt is missing required fields.' };
  }
  // The receipt must claim to come from this tool at this version: a
  // self-consistent signature over a different tool/version is a forgery.
  // Report it as tampering with the covered identity fields, not as a
  // structurally broken receipt.
  const identityChanged = [];
  if (payload.tool !== 'CapGate') identityChanged.push('tool');
  if (payload.version !== TOOL_VERSION) identityChanged.push('version');
  if (identityChanged.length) {
    return { status: 'TAMPERED', changedFields: identityChanged, detail: `Unsupported receipt tool/version (expected CapGate ${TOOL_VERSION}).` };
  }
  let canonical;
  try {
    canonical = canonicalJson(payload);
  } catch {
    // A structure too deep to serialize can never be a receipt we issued.
    return { status: 'MALFORMED', changedFields: ['payload'], detail: 'Receipt is too deeply nested to verify.' };
  }
  const expectedBody = sha256Hex(canonical);
  const expectedSig = hmacSha256Hex(receiptKey(payload), canonical);
  const changedFields = [];
  // Algorithm confusion: only the pinned construction may verify. Anything
  // else (MD5, a bare hash, a swapped signature scheme) is tampering.
  if (digest.algorithm !== DIGEST_ALGORITHM) changedFields.push('digest.algorithm');
  if (typeof digest.canonicalJson !== 'string' || digest.canonicalJson !== expectedBody) {
    changedFields.push('digest.canonicalJson');
  }
  if (typeof digest.signature !== 'string' || digest.signature !== expectedSig) {
    changedFields.push('digest.signature');
  }
  // The digest object must carry exactly the signed triple: extra keys are
  // unsigned data smuggled into a "verified" receipt.
  for (const k of Object.keys(digest)) {
    if (!DIGEST_KEYS.has(k)) changedFields.push(`unexpected:digest.${k}`);
  }

  // Any field outside the signed covered set is unexpected and must be
  // reported: a receipt that carries extra data has been modified.
  const extra = Object.keys(receipt).filter((k) => !COVERED_FIELDS.includes(k) && k !== 'digest');
  if (extra.length) changedFields.push(...extra.map((k) => `unexpected:${k}`));
  if (changedFields.length === 0) {
    return { status: 'VALID', changedFields: [], detail: 'Canonical payload and integrity signature match.' };
  }
  return {
    status: 'TAMPERED',
    changedFields,
    detail: `Integrity check failed. ${extra.length ? `Unexpected field(s): ${extra.join(', ')}. ` : ''}Canonical payload differs from the signed digest.`,
  };
}
