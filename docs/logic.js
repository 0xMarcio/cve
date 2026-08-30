'use strict';

const REPLACE_STRINGS = ['HackTheBox - ', 'VulnHub - ', 'UHC - '];
const PAGE_SIZE = 50;
const POC_PREVIEW = 5;
const TREND_ROWS = 20;

const state = {
  query: '',
  mode: 'TRENDING',
  shown: PAGE_SIZE,
  descOpen: new Set(),
  pocOpen: new Set(),
  ready: false,
  results: []
};

let dataset = [];
let repoMeta = {};
let trending = [];
let indexMeta = null;

/* ---- formatting -------------------------------------------------------- */

function escapeHTML(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
}

function formatCount(n) {
  return n.toLocaleString('en-US');
}

function formatStars(n) {
  return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n);
}

function hoursSince(iso) {
  if (!iso) return null;
  const then = Date.parse(iso.length === 10 ? iso + 'T00:00:00Z' : iso);
  if (Number.isNaN(then)) return null;
  return (Date.now() - then) / 36e5;
}

/** Long form for the trending table: "3 hours ago", "4 months ago". */
function longAge(hours) {
  if (hours == null) return '';
  const units = [
    [8760, 'year'], [720, 'month'], [168, 'week'], [24, 'day'], [1, 'hour']
  ];
  for (const [size, name] of units) {
    if (hours >= size) {
      const n = Math.floor(hours / size);
      return `${n} ${name}${n === 1 ? '' : 's'} ago`;
    }
  }
  const minutes = Math.max(1, Math.round(hours * 60));
  return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
}

/** Compact age for the PoC columns: 3h, 3d, 2w, 5mo, 2y. */
function shortAge(hours) {
  if (hours == null) return '';
  if (hours < 24) return Math.max(1, Math.round(hours)) + 'h';
  const days = hours / 24;
  if (days < 14) return Math.round(days) + 'd';
  if (days < 60) return Math.round(days / 7) + 'w';
  if (days < 730) return Math.round(days / 30) + 'mo';
  return Math.round(days / 365) + 'y';
}

function repoFromUrl(url) {
  const match = /^https?:\/\/(?:www\.)?github\.com\/([^/#?]+)\/([^/#?]+)/i.exec(url || '');
  if (!match) return null;
  return { owner: match[1], repo: match[2].replace(/\.git$/i, '') };
}

/** Everything after the host, for links that are not GitHub repositories. */
function plainLinkLabel(url) {
  try {
    const parsed = new URL(url);
    return parsed.host.replace(/^www\./, '') + parsed.pathname.replace(/\/$/, '');
  } catch (err) {
    return url;
  }
}

/* ---- matching ---------------------------------------------------------- */

function normalizeToSpaces(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

function buildLooseRegex(value) {
  const compact = value.toLowerCase().replace(/[^a-z0-9]+/g, '');
  if (compact.length < 4) return null;
  const escaped = compact.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(escaped.split('').join('[^a-z0-9]*'));
}

function buildMatcher(term) {
  const raw = term.toLowerCase().trim();
  if (!raw) return null;
  const isPhrase = /\s/.test(raw);
  const normalized = raw.replace(/[^a-z0-9]+/g, '');
  return {
    raw,
    isPhrase,
    phrase: isPhrase ? normalizeToSpaces(raw) : '',
    loose: !isPhrase && normalized.length >= 4 ? buildLooseRegex(raw) : null
  };
}

// Plain substring matching made "rce" hit "open source" and "sudo" hit
// "pseudo". Require the term to start a word; matching into the end of one is
// still allowed so that "word" finds "wordpress".
function wordStart(text, term) {
  let at = text.indexOf(term);
  while (at > 0) {
    const code = text.charCodeAt(at - 1);
    if (!((code > 96 && code < 123) || (code > 47 && code < 58))) return at;
    at = text.indexOf(term, at + 1);
  }
  return at;
}

// A term in the opening of an advisory is what it is about; one buried deep in
// the prose is usually incidental. Coarse buckets so that a few characters of
// difference never outweighs the newest-first tie-break.
function leadBonus(index) {
  if (index < 0) return 0;
  if (index < 80) return 80;
  if (index < 300) return 40;
  return 0;
}

function pocText(entry) {
  if (entry._pocText === undefined) {
    entry._pocText = (entry.poc || []).join(' ').toLowerCase();
  }
  return entry._pocText;
}

function pocSpace(entry) {
  if (entry._pocSpace === undefined) {
    entry._pocSpace = normalizeToSpaces(pocText(entry));
  }
  return entry._pocSpace;
}

function descSpace(entry) {
  if (entry._descSpace === undefined) {
    entry._descSpace = normalizeToSpaces(entry._descText);
  }
  return entry._descSpace;
}

function scoreEntry(entry, matcher) {
  if (!matcher || !matcher.raw) return 0;

  if (matcher.isPhrase) {
    const phrase = matcher.phrase;
    if (!phrase) return 0;
    const at = wordStart(descSpace(entry), phrase);
    if (at >= 0) return 200 + leadBonus(at);
    if (wordStart(pocSpace(entry), phrase) >= 0) return 80;
    return 0;
  }

  const raw = matcher.raw;
  if (entry._cveText.includes(raw)) return 600;
  const at = wordStart(entry._descText, raw);
  if (at >= 0) return 240 + leadBonus(at);
  if (wordStart(pocText(entry), raw) >= 0) return 80;
  if (matcher.loose) {
    if (matcher.loose.test(entry._descText)) return 160;
    if (matcher.loose.test(pocText(entry))) return 60;
  }
  return 0;
}

function runSearch(query) {
  const terms = query.match(/-?"[^"]+"|-?\S+/g) || [];
  const cleaned = terms.map(t => t.replace(/^(-?)"/, '$1').replace(/"$/, ''));
  const positive = cleaned.filter(t => t && t[0] !== '-');
  const matchers = positive.map(buildMatcher).filter(Boolean);
  // Unquoted words are matched independently, so "active directory" also hits a
  // description holding "active session" and "working directory". Reward the
  // words appearing together to keep those below real matches.
  const adjacent = positive.length > 1 ? positive.join(' ').toLowerCase() : '';
  const negatives = cleaned
    .filter(t => t && t[0] === '-')
    .map(t => t.slice(1))
    .filter(Boolean)
    .map(buildMatcher)
    .filter(Boolean);

  const results = [];
  for (const entry of dataset) {
    let score = 0;
    let matched = true;
    for (const matcher of matchers) {
      const termScore = scoreEntry(entry, matcher);
      if (termScore === 0) { matched = false; break; }
      score += termScore;
    }
    if (!matched) continue;
    if (negatives.some(m => scoreEntry(entry, m) > 0)) continue;

    if (adjacent) {
      const at = wordStart(entry._descText, adjacent);
      if (at >= 0) score += 300 + leadBonus(at);
      else if (wordStart(pocText(entry), adjacent) >= 0) score += 100;
    }
    entry._score = score;
    results.push(entry);
  }

  results.sort((a, b) => {
    if (b._score !== a._score) return b._score - a._score;
    if (b._year !== a._year) return b._year - a._year;
    return b._num - a._num;
  });
  return results;
}

function prepareDataset(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const entry of raw) {
    const cve = (entry.cve || '').trim();
    if (!cve || !Array.isArray(entry.poc) || entry.poc.length === 0) continue;
    const parts = cve.split('-');
    entry._cveText = cve.toLowerCase();
    entry._descText = REPLACE_STRINGS
      .reduce((desc, str) => desc.replace(str, ''), entry.desc || '')
      .toLowerCase();
    entry._year = parseInt(parts[1], 10) || 0;
    entry._num = parseInt(parts[2], 10) || 0;
    out.push(entry);
  }
  return out;
}

/* ---- rendering --------------------------------------------------------- */

const el = {
  input: document.querySelector('[data-search]'),
  status: document.querySelector('[data-status]'),
  results: document.querySelector('[data-results]'),
  trending: document.querySelector('[data-trending]'),
  trendTitle: document.querySelector('[data-trend-title]'),
  trendNote: document.querySelector('[data-trend-note]'),
  trendRows: document.querySelector('[data-trend-rows]'),
  refreshed: document.querySelector('[data-refreshed]')
};

function pocRow(url) {
  const parsed = repoFromUrl(url);
  const href = escapeHTML(url);
  if (!parsed) {
    return `<div class="poc-row"><span class="poc-name">` +
      `<a href="${href}" target="_blank" rel="noopener">${escapeHTML(plainLinkLabel(url))}</a>` +
      `</span><span class="poc-stars"></span><span class="poc-age"></span></div>`;
  }
  const key = (parsed.owner + '/' + parsed.repo).toLowerCase();
  const meta = repoMeta[key];
  const stars = meta ? meta[0] : null;
  const hours = meta ? hoursSince(meta[1]) : null;
  const starClass = stars != null && stars >= 500 ? 'poc-stars is-popular' : 'poc-stars';
  return `<div class="poc-row">` +
    `<span class="poc-name"><span class="poc-owner">${escapeHTML(parsed.owner)}</span>` +
    `<span class="poc-sep"> / </span>` +
    `<a href="${href}" target="_blank" rel="noopener">${escapeHTML(parsed.repo)}</a></span>` +
    `<span class="${starClass}">${stars == null ? '' : formatStars(stars) + ' ★'}</span>` +
    `<span class="poc-age">${escapeHTML(shortAge(hours))}</span></div>`;
}

/** Best-known repositories first, so the five shown by default are the five
 *  worth opening. Links without a star count keep their original order behind
 *  them; references from the CVE record have no repository to rank. */
function rankedLinks(entry) {
  if (entry._ranked) return entry._ranked;
  const scored = (entry.poc || []).map((url, index) => {
    const parsed = repoFromUrl(url);
    const meta = parsed && repoMeta[(parsed.owner + '/' + parsed.repo).toLowerCase()];
    return { url, index, stars: meta ? meta[0] : -1 };
  });
  scored.sort((a, b) => (b.stars - a.stars) || (a.index - b.index));
  entry._ranked = scored.map(item => item.url);
  return entry._ranked;
}

function resultRow(entry) {
  const id = entry.cve;
  const open = state.descOpen.has(id);
  const all = state.pocOpen.has(id);
  const links = rankedLinks(entry);
  const visible = all ? links : links.slice(0, POC_PREVIEW);
  const more = all
    ? '↑ show fewer'
    : (links.length > POC_PREVIEW
        ? `+ ${formatCount(links.length - POC_PREVIEW)} more repositories`
        : 'all repositories shown');

  const dates = [];
  if (entry.published) dates.push(['published', entry.published]);
  if (entry.modified) dates.push(['modified', entry.modified]);
  const dateHtml = dates.length
    ? `<dl class="result-dates">${dates.map(([label, value]) =>
        `<div class="result-date"><dt>${label}</dt><dd>${escapeHTML(value)}</dd></div>`).join('')}</dl>`
    : '';

  return `<div class="result-row">
  <div class="result-meta">
    <a class="result-id" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener">${escapeHTML(id)}</a>
    <div class="result-pocs">${formatCount(links.length)} linked PoC${links.length === 1 ? '' : 's'}</div>
    ${dateHtml}
    <a class="mitre" href="https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}" target="_blank" rel="noopener">MITRE ↗</a>
  </div>
  <div class="result-body">
    <p class="result-desc${open ? ' is-open' : ''}">${escapeHTML(entry.desc || '')}</p>
    <button type="button" class="expander" data-toggle-desc="${escapeHTML(id)}">${open ? '↑ collapse' : '↓ full description'}</button>
    <div class="poc-list">
      ${visible.map(pocRow).join('')}
      <button type="button" class="poc-more" data-toggle-poc="${escapeHTML(id)}">${more}</button>
    </div>
  </div>
</div>`;
}

function renderResults(elapsed) {
  const results = state.results;
  el.trending.hidden = true;
  el.results.hidden = false;

  if (!results.length) {
    el.results.innerHTML = `<div class="empty">
      <div class="empty-head">No CVE matched <b>${escapeHTML(state.query)}</b></div>
      <div class="empty-hint">Try a CVE ID, a vendor, or a product name. Prefix a term with <code>-</code> to exclude it.</div>
    </div>`;
    return;
  }

  const shown = results.slice(0, state.shown);
  const pocTotal = results.reduce((sum, r) => sum + (r.poc || []).length, 0);
  const remaining = results.length - shown.length;
  const footer = remaining > 0
    ? `<button type="button" class="poc-more" data-more-results>+ ${formatCount(remaining)} more matching CVEs</button>`
    : '';

  el.results.innerHTML = `<div class="card-head">
      <h2>Results</h2>
      <span class="card-count">${formatCount(results.length)} CVE${results.length === 1 ? '' : 's'} · ${formatCount(pocTotal)} PoCs</span>
    </div>
    <div class="col-head"><span>CVE</span><span>DESCRIPTION / POC LINKS</span></div>
    ${shown.map(resultRow).join('')}${footer}`;

  if (elapsed != null) {
    el.status.textContent = `matched in ${Math.max(1, Math.round(elapsed))}ms`;
  }
}

function trendRow(item) {
  const popular = item.stars >= 500 ? ' is-popular' : '';
  return `<div class="trend-row">
    <span class="trend-stars${popular}">${formatStars(item.stars)} ★</span>
    <span class="trend-age">${escapeHTML(longAge(item._pushed))}</span>
    <a class="trend-name" href="${escapeHTML(item.url)}" target="_blank" rel="noopener">${escapeHTML(item.name)}</a>
    <span class="trend-desc">${escapeHTML(item.desc || '')}</span>
  </div>`;
}

function renderTrending() {
  el.results.hidden = true;
  el.trending.hidden = false;

  const ranked = trending.slice();
  if (state.mode === 'TRENDING') {
    // Stars weighted against how long the repository has existed, so a
    // fast-climbing new PoC outranks an older one with a bigger absolute count.
    const rank = r => r.stars / Math.pow((r._created == null ? 8760 : r._created) + 6, 0.45);
    ranked.sort((a, b) => rank(b) - rank(a));
  } else {
    ranked.sort((a, b) => (a._pushed == null ? Infinity : a._pushed) - (b._pushed == null ? Infinity : b._pushed));
  }
  const rows = ranked.slice(0, TREND_ROWS);

  el.trendTitle.textContent = state.mode === 'TRENDING'
    ? 'Trending Proof-of-Concepts'
    : 'Recently updated Proof-of-Concepts';

  el.trendNote.textContent = state.mode === 'TRENDING'
    ? 'stars gained relative to repository age'
    : `newest commit first · ${formatCount(trending.length)} repositories`;

  el.trendRows.innerHTML = rows.length
    ? rows.map(trendRow).join('')
    : '<div class="trend-row"><span class="trend-desc">No recent PoCs.</span></div>';

  document.querySelectorAll('.toggle button').forEach(button => {
    button.setAttribute('aria-pressed', String(button.dataset.mode === state.mode));
  });
}

function idleStatus() {
  if (!indexMeta) return '';
  return `${formatCount(indexMeta.total_cves)} CVEs · ${formatCount(indexMeta.with_pocs)} with PoCs`;
}

function render() {
  if (!state.query) {
    el.status.textContent = state.ready ? idleStatus() : 'loading index…';
    renderTrending();
    return;
  }
  if (!state.ready) {
    el.results.hidden = false;
    el.trending.hidden = true;
    el.status.textContent = 'loading index…';
    el.results.innerHTML = `<div class="empty">
      <div class="empty-head">Loading the CVE index…</div>
      <div class="empty-hint">The full index is a single download; results appear as soon as it lands.</div>
    </div>`;
    return;
  }
  const started = performance.now();
  state.results = runSearch(state.query);
  renderResults(performance.now() - started);
}

/* ---- wiring ------------------------------------------------------------ */

el.input.addEventListener('input', () => {
  state.query = el.input.value.trim();
  state.shown = PAGE_SIZE;
  render();
});

document.querySelector('.search').addEventListener('submit', event => event.preventDefault());

document.querySelector('.toggle').addEventListener('click', event => {
  const button = event.target.closest('button[data-mode]');
  if (!button) return;
  state.mode = button.dataset.mode;
  renderTrending();
});

el.results.addEventListener('click', event => {
  const desc = event.target.closest('[data-toggle-desc]');
  const poc = event.target.closest('[data-toggle-poc]');
  const more = event.target.closest('[data-more-results]');
  if (desc) {
    const id = desc.dataset.toggleDesc;
    state.descOpen.has(id) ? state.descOpen.delete(id) : state.descOpen.add(id);
  } else if (poc) {
    const id = poc.dataset.togglePoc;
    state.pocOpen.has(id) ? state.pocOpen.delete(id) : state.pocOpen.add(id);
  } else if (more) {
    state.shown += PAGE_SIZE;
  } else {
    return;
  }
  renderResults(null);
});

async function loadJSON(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`${url} (${response.status})`);
  return response.json();
}

(async () => {
  try {
    const meta = await loadJSON('/trending_poc.json', { cache: 'no-store' });
    indexMeta = meta;
    trending = (meta.items || []).map(item => Object.assign({}, item, {
      _pushed: hoursSince(item.pushed),
      _created: hoursSince(item.created)
    }));
    const minutes = Math.max(0, Math.round((Date.now() - Date.parse(meta.generated)) / 60000));
    el.refreshed.textContent = minutes < 60
      ? `index refreshed ${minutes} minute${minutes === 1 ? '' : 's'} ago`
      : `index refreshed ${Math.round(minutes / 60)} hour${Math.round(minutes / 60) === 1 ? '' : 's'} ago`;
  } catch (err) {
    console.warn(err.message);
  }
  render();

  // The repository metadata is optional: without it the PoC rows simply lose
  // their star and age columns, which is the documented fallback.
  loadJSON('/repo_meta.json').then(data => {
    repoMeta = data || {};
    for (const entry of dataset) entry._ranked = null;
    if (state.query && state.ready) renderResults(null);
  }).catch(err => console.warn(err.message));

  try {
    dataset = prepareDataset(await loadJSON('/CVE_list.json'));
    state.ready = true;
    render();
  } catch (err) {
    console.warn(err.message);
    el.status.textContent = 'index unavailable';
  }
})();
