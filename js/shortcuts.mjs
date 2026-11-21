/**
 * WCAG 2.1.4 character-key shortcut handling for the CapGate playground.
 * A single printable key may trigger a page action only when all of these
 * hold: the user has not disabled shortcuts, no modifier key is held, the
 * key is exactly one character, and focus is not inside a text-accepting
 * control. The logic is pure so it can be unit-tested without a DOM.
 */

/** Elements whose focus means "the user is typing"; keys belong to them. */
export function isEditableTarget(t) {
  if (!t || typeof t !== 'object') return false;
  if (t.isContentEditable) return true;
  const tag = String(t.tagName || t.nodeName || '').toLowerCase();
  if (tag === 'textarea' || tag === 'select') return true;
  if (tag === 'input') {
    // Buttons, checkboxes, and other non-text inputs do not swallow keys.
    const type = String(t.type || 'text').toLowerCase();
    return !['button', 'submit', 'reset', 'checkbox', 'radio', 'range', 'color', 'image', 'file'].includes(type);
  }
  return false;
}

/**
 * Decide whether a KeyboardEvent-shaped object may fire a single-key
 * shortcut. `target` may be passed explicitly for tests; it defaults to the
 * event's own target.
 */
export function shouldFireShortcut(event, { enabled = true, target } = {}) {
  if (!enabled || !event || typeof event !== 'object') return false;
  if (event.ctrlKey || event.metaKey || event.altKey) return false;
  const key = String(event.key || '');
  // Exactly one printable character; function keys and IME output excluded.
  if (key.length !== 1 || event.isComposing) return false;
  const t = target === undefined ? event.target : target;
  if (isEditableTarget(t)) return false;
  return true;
}

/** Key -> action id map for the playground's single-key shortcuts. */
export const SHORTCUT_MAP = Object.freeze({
  n: 'next-attack',
  i: 'inspect',
  t: 'theme',
  r: 'rerun',
  e: 'export-receipt',
});
