import test from 'node:test';
import assert from 'node:assert/strict';

import { buildPost, clampPostText, graphemes } from '../web/postText.js';

test('clamps posts to 300 grapheme clusters', () => {
  const text = 'a'.repeat(301);
  const clamped = clampPostText(text, 300);

  assert.equal(graphemes(clamped).length, 300);
  assert.equal(clamped.endsWith('...'), true);
});

test('treats multi-codepoint emoji as one grapheme', () => {
  assert.equal(graphemes('👍🏽').length, 1);
});

test('adds Bluesky link facets with byte indexes', () => {
  const post = buildPost('See https://example.com/path.', undefined, 300);

  assert.equal(post.facets.length, 1);
  assert.equal(post.facets[0].features[0].uri, 'https://example.com/path');
  assert.deepEqual(post.facets[0].index, { byteStart: 4, byteEnd: 28 });
});
