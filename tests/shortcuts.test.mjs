import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isEditableTarget,
  shouldFireShortcut,
  SHORTCUT_MAP,
} from '../js/shortcuts.mjs';

const ev = (key, extras = {}) => ({ key, ...extras });
const textInput = { tagName: 'INPUT', type: 'text' };
const buttonInput = { tagName: 'INPUT', type: 'button' };
const textarea = { tagName: 'TEXTAREA' };
const select = { tagName: 'SELECT' };
const div = { tagName: 'DIV' };
const editable = { tagName: 'DIV', isContentEditable: true };

/* isEditableTarget ------------------------------------------------------------ */

test('kbd: text-ish inputs are editable', () => {
  for (const type of ['text', 'search', 'url', 'password', 'email', 'number']) {
    assert.equal(isEditableTarget({ tagName: 'INPUT', type }), true, type);
  }
});

test('kbd: non-text inputs are not editable', () => {
  for (const type of ['button', 'checkbox', 'radio', 'range', 'submit', 'file']) {
    assert.equal(isEditableTarget({ tagName: 'INPUT', type }), false, type);
  }
});

test('kbd: textarea and select are editable', () => {
  assert.equal(isEditableTarget(textarea), true);
  assert.equal(isEditableTarget(select), true);
});

test('kbd: contenteditable is editable', () => {
  assert.equal(isEditableTarget(editable), true);
});

test('kbd: plain elements and null are not editable', () => {
  assert.equal(isEditableTarget(div), false);
  assert.equal(isEditableTarget(null), false);
  assert.equal(isEditableTarget(undefined), false);
});

/* shouldFireShortcut ----------------------------------------------------------- */

test('kbd: single key on body fires', () => {
  assert.equal(shouldFireShortcut(ev('n', { target: div })), true);
});

test('kbd: disabled toggle blocks firing', () => {
  assert.equal(shouldFireShortcut(ev('n', { target: div }), { enabled: false }), false);
});

test('kbd: ctrl/meta/alt modifiers block firing', () => {
  assert.equal(shouldFireShortcut(ev('n', { target: div, ctrlKey: true })), false);
  assert.equal(shouldFireShortcut(ev('n', { target: div, metaKey: true })), false);
  assert.equal(shouldFireShortcut(ev('n', { target: div, altKey: true })), false);
});

test('kbd: shift is allowed (capital letters may map to actions)', () => {
  assert.equal(shouldFireShortcut(ev('N', { target: div, shiftKey: true })), true);
});

test('kbd: focus inside a text input blocks firing', () => {
  assert.equal(shouldFireShortcut(ev('n', { target: textInput })), false);
});

test('kbd: focus inside textarea/select/contenteditable blocks firing', () => {
  assert.equal(shouldFireShortcut(ev('n', { target: textarea })), false);
  assert.equal(shouldFireShortcut(ev('n', { target: select })), false);
  assert.equal(shouldFireShortcut(ev('n', { target: editable })), false);
});

test('kbd: focus on a button still allows firing', () => {
  assert.equal(shouldFireShortcut(ev('n', { target: buttonInput })), true);
});

test('kbd: multi-char keys do not fire', () => {
  assert.equal(shouldFireShortcut(ev('Enter', { target: div })), false);
  assert.equal(shouldFireShortcut(ev('Escape', { target: div })), false);
  assert.equal(shouldFireShortcut(ev('F5', { target: div })), false);
});

test('kbd: IME composition events do not fire', () => {
  assert.equal(shouldFireShortcut(ev('n', { target: div, isComposing: true })), false);
});

test('kbd: missing event or key cannot fire', () => {
  assert.equal(shouldFireShortcut(null), false);
  assert.equal(shouldFireShortcut(ev('', { target: div })), false);
});

test('kbd: explicit target overrides event.target', () => {
  assert.equal(shouldFireShortcut(ev('n', { target: div }), { target: textInput }), false);
});

/* SHORTCUT_MAP ------------------------------------------------------------------ */

test('kbd: map covers the advertised single keys', () => {
  assert.equal(SHORTCUT_MAP.n, 'next-attack');
  assert.equal(SHORTCUT_MAP.i, 'inspect');
  assert.equal(SHORTCUT_MAP.t, 'theme');
  assert.equal(SHORTCUT_MAP.r, 'rerun');
  assert.equal(SHORTCUT_MAP.e, 'export-receipt');
});

test('kbd: every mapped key is a single lowercase character', () => {
  for (const k of Object.keys(SHORTCUT_MAP)) {
    assert.match(k, /^[a-z]$/);
  }
});
