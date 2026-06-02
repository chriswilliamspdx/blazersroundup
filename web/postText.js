const DEFAULT_POST_CHAR_LIMIT = 300;

const segmenter = typeof Intl.Segmenter === 'function'
  ? new Intl.Segmenter('en', { granularity: 'grapheme' })
  : null;

export function graphemes(text) {
  if (segmenter) return Array.from(segmenter.segment(String(text || '')), item => item.segment);
  return Array.from(String(text || ''));
}

export function clampPostText(text, limit = DEFAULT_POST_CHAR_LIMIT) {
  const clean = String(text || '')
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map(line => line.replace(/\s+/g, ' ').trim())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  const parts = graphemes(clean);
  if (parts.length <= limit) return clean;
  if (limit <= 3) return '.'.repeat(limit);
  return parts.slice(0, limit - 3).join('').trimEnd() + '...';
}

export function byteIndex(text, charIndex) {
  return Buffer.byteLength(text.slice(0, charIndex), 'utf8');
}

export function parseUrlFacets(text) {
  const facets = [];
  const urlRegex = /https?:\/\/[^\s<>"']+/g;
  for (const match of text.matchAll(urlRegex)) {
    const rawUrl = match[0];
    const uri = rawUrl.replace(/[),.!?;:]+$/g, '');
    if (!uri) continue;
    const start = match.index;
    const end = start + uri.length;
    facets.push({
      index: {
        byteStart: byteIndex(text, start),
        byteEnd: byteIndex(text, end),
      },
      features: [
        {
          $type: 'app.bsky.richtext.facet#link',
          uri,
        },
      ],
    });
  }
  return facets;
}

export function buildPost(text, reply, limit = DEFAULT_POST_CHAR_LIMIT, embed) {
  const safeText = clampPostText(text, limit);
  const post = { text: safeText };
  const facets = parseUrlFacets(safeText);
  if (facets.length) post.facets = facets;
  if (reply) post.reply = reply;
  if (embed) post.embed = embed;
  return post;
}
