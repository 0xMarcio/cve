'use strict';

const REPLACE_STRINGS = ['HackTheBox - ', 'VulnHub - ', 'UHC - '];
const PAGE_SIZE = 50;
const POC_PREVIEW = 5;
const TREND_ROWS = 20;
const MIN_QUERY = 2;

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
let kev = {};
let ratings = {};
let epss = {};
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

// github.com serves more than repositories; an attachment or an advisory has
// no owner and no stars, and reads as nonsense in an owner / repo row.
const NOT_A_REPO = new Set(['user-attachments', 'advisories', 'security', 'orgs',
  'apps', 'marketplace', 'sponsors', 'topics', 'collections', 'settings', 'notifications']);

function repoFromUrl(url) {
  const match = /^https?:\/\/(?:www\.)?github\.com\/([^/#?]+)\/([^/#?]+)/i.exec(url || '');
  if (!match || NOT_A_REPO.has(match[1].toLowerCase())) return null;
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

/** How many of an entry's links carry every search term. */
function countLinkHits(entry, matchers) {
  let hits = 0;
  for (const url of entry.poc || []) {
    const text = url.toLowerCase();
    if (matchers.every(m => wordStart(text, m.raw) >= 0 || (m.loose && m.loose.test(text)))) {
      hits += 1;
      if (hits >= 999) break;
    }
  }
  return hits;
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
  results.pocTotal = 0;
  for (const entry of dataset) {
    let score = 0;
    let matched = true;
    let describes = false;
    for (const matcher of matchers) {
      const termScore = scoreEntry(entry, matcher);
      if (termScore === 0) { matched = false; break; }
      if (termScore >= 160) describes = true;
      score += termScore;
    }
    if (!matched) continue;
    if (negatives.some(m => scoreEntry(entry, m) > 0)) continue;

    if (adjacent) {
      const at = wordStart(entry._descText, adjacent);
      if (at >= 0) { score += 300 + leadBonus(at); describes = true; }
      else if (wordStart(pocText(entry), adjacent) >= 0) score += 100;
    }
    entry._score = score;
    // A term nobody's advisory text uses, "log4shell" for one, leaves every match tied
    // at the weakest tier, where newest-first is meaningless. How many of the
    // linked PoCs carry the term says far more than which CVE is newer.
    entry._hits = describes ? 0 : countLinkHits(entry, matchers);
    results.pocTotal += (entry.poc || []).length;
    results.push(entry);
  }

  results.sort((a, b) => {
    if (b._score !== a._score) return b._score - a._score;
    if (b._hits !== a._hits) return b._hits - a._hits;
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
  trendNote: document.querySelector('[data-trend-note]'),
  trendRows: document.querySelector('[data-trend-rows]'),
  statTotal: document.querySelector('[data-stat-total]'),
  statPocs: document.querySelector('[data-stat-pocs]'),
  statKev: document.querySelector('[data-stat-kev]'),
  refreshed: document.querySelector('[data-refreshed]')
};

const CURATED = [
  { match: '/nuclei-templates/', tag: 'NUCLEI', hint: 'Runnable nuclei detection template',
    label: url => url.split('/').pop() },
  { match: '/metasploit-framework/', tag: 'MSF', hint: 'Metasploit module',
    label: url => url.split('/modules/').pop().replace(/\.rb$/, '') },
  { match: 'exploit-db.com/exploits/', tag: 'EDB', hint: 'ExploitDB entry',
    label: url => 'exploit-db.com/' + url.split('/').pop() }
];

function pocRow(url) {
  const curated = CURATED.find(source => url.includes(source.match));
  if (curated) {
    return '<div class="poc-row"><span class="poc-name">' +
      `<span class="poc-tag is-${curated.tag.toLowerCase()}" title="${escapeHTML(curated.hint)}">${curated.tag}</span>` +
      `<a href="${escapeHTML(url)}" target="_blank" rel="noopener">${escapeHTML(curated.label(url))}</a>` +
      '</span><span class="poc-stars"></span><span class="poc-age"></span></div>';
  }
  const parsed = repoFromUrl(url);
  const href = escapeHTML(url);
  // A gist or an advisory has no owner and no stars; the star and age columns
  // stay empty rather than inventing a repository shape for it.
  if (!parsed) {
    return '<div class="poc-row"><span class="poc-name">' +
      `<a class="plain" href="${href}" target="_blank" rel="noopener">${escapeHTML(plainLinkLabel(url))}</a>` +
      '</span><span class="poc-stars"></span><span class="poc-age"></span></div>';
  }
  const meta = repoMeta[(parsed.owner + '/' + parsed.repo).toLowerCase()];
  const stars = meta ? meta[0] : null;
  const hours = meta ? hoursSince(meta[1]) : null;
  const popular = stars != null && stars >= 500 ? ' is-popular' : '';
  // The glyph stays dim at every value so the column reads as numbers.
  const starCell = stars == null ? '' : `${formatStars(stars)} <span class="star">★</span>`;
  return '<div class="poc-row">' +
    `<span class="poc-name">${escapeHTML(parsed.owner)}<span class="poc-sep"> / </span>` +
    `<a href="${href}" target="_blank" rel="noopener">${escapeHTML(parsed.repo)}</a></span>` +
    `<span class="poc-stars${popular}">${starCell}</span>` +
    `<span class="poc-age">${escapeHTML(shortAge(hours))}</span></div>`;
}

function compact(value) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Best links first. A repository named after the CVE is a proof of concept for
 *  it; a 5k-star scanner that merely mentions it is not, so stars only order
 *  repositories that are already about this CVE. Links with no star count keep
 *  their original order behind both: a reference has no repository to rank. */
function rankedLinks(entry) {
  if (entry._ranked) return entry._ranked;
  const id = compact(entry.cve);
  const scored = (entry.poc || []).map((url, index) => {
    const parsed = repoFromUrl(url);
    const meta = parsed && repoMeta[(parsed.owner + '/' + parsed.repo).toLowerCase()];
    return {
      url,
      index,
      dedicated: compact(url).includes(id) ? 1 : 0,
      stars: meta ? meta[0] : -1
    };
  });
  scored.sort((a, b) =>
    (b.dedicated - a.dedicated) || (b.stars - a.stars) || (a.index - b.index));
  // A nuclei template leads: of everything linked here it is the one entry that
  // runs as it stands, against a target, without reading somebody's code first.
  // Curated entries lead: a template, an ExploitDB entry and a Metasploit
  // module all run as they stand, without reading somebody's code first.
  entry._ranked = [
    ...(entry.nuclei || []), ...(entry.msf || []), ...(entry.edb || []),
    ...scored.map(item => item.url)
  ];
  return entry._ranked;
}

function resultRow(entry) {
  const id = entry.cve;
  const open = state.descOpen.has(id);
  const all = state.pocOpen.has(id);
  const links = rankedLinks(entry);
  const visible = all ? links : links.slice(0, POC_PREVIEW);
  // Nothing to expand means no control: a line reading "all repositories
  // shown" under a list of three is chrome that answers a question nobody has.
  const moreButton = links.length > POC_PREVIEW
    ? `<button type="button" class="poc-more" data-toggle-poc="${escapeHTML(id)}">` +
      `${all ? '↑ show fewer' : '+ ' + formatCount(links.length - POC_PREVIEW) + ' more'}</button>`
    : '';

  // Nuclei rates what it covers, so a row can say how bad the flaw is and how
  // likely it is to be exploited, not only that somebody wrote code for it.
  const rated = ratings[id] || {};
  const severityChip = rated.severity
    ? `<span class="chip chip-sev is-${escapeHTML(rated.severity)}"${rated.cvss_vector ? ` title="${escapeHTML(rated.cvss_vector)}"` : ''}>` +
      `${escapeHTML(rated.severity.toUpperCase())}${rated.cvss ? ' ' + rated.cvss : ''}</span>`
    : '';
  // FIRST's feed covers nearly the whole index; a template's own score is the
  // fallback for the handful it misses.
  const scored = epss[id] || (rated.epss != null ? [rated.epss, rated.epss_pct || 0] : null);
  const epssChip = scored
    ? `<span class="chip chip-epss${scored[0] >= 0.1 ? ' is-hot' : ''}" title="EPSS: estimated chance of exploitation in the next 30 days, ${Math.round(scored[1] * 100)}th percentile">` +
      `EPSS ${(scored[0] * 100).toFixed(scored[0] >= 0.1 ? 0 : 1)}%</span>`
    : '';

  const flagged = kev[id];
  const kevChip = flagged
    ? `<span class="chip chip-kev" title="Listed in CISA's Known Exploited Vulnerabilities catalogue on ${escapeHTML(flagged[0])}${flagged[1] ? ', used in ransomware campaigns' : ''}">` +
      `KEV${flagged[1] ? ' RANSOMWARE' : ''}</span>`
    : '';

  const dates = [];
  if (entry.published) dates.push(`published ${entry.published}`);
  if (entry.modified) dates.push(`modified ${entry.modified}`);
  const dateHtml = dates.length
    ? `<div class="result-dates">${dates.map(d => `<span>${escapeHTML(d)}</span>`).join('')}</div>`
    : '';

  return `<div class="result-row">
  <div class="result-meta">
    <a class="result-id" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener">${escapeHTML(id)}</a>
    <div class="result-pocs">${formatCount(links.length)} linked PoC${links.length === 1 ? '' : 's'}</div>
    ${dateHtml}
    <div class="chips">${kevChip}${severityChip}${epssChip}
      <a class="chip" href="https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}" target="_blank" rel="noopener">MITRE ↗</a>
    </div>
  </div>
  <div class="result-body">
    <p class="result-desc${open ? ' is-open' : ''}">${escapeHTML(entry.desc || '')}</p>
    <button type="button" class="expander" data-toggle-desc="${escapeHTML(id)}">${open ? '↑ collapse' : '↓ full description'}</button>
    <div class="poc-list">
      ${visible.map(pocRow).join('')}
      ${moreButton}
    </div>
  </div>
</div>`;
}

/** Hide the expander on descriptions that already fit; a button that does
 *  nothing when clicked is worse than no button. */
function pruneExpanders() {
  for (const row of el.results.querySelectorAll('.result-row')) {
    const desc = row.querySelector('.result-desc');
    const button = row.querySelector('.expander');
    if (!desc || !button) continue;
    if (!desc.classList.contains('is-open') && desc.scrollHeight <= desc.clientHeight + 1) {
      button.hidden = true;
    }
  }
}

function renderResults(elapsed) {
  const results = state.results;
  el.trending.hidden = true;
  el.results.hidden = false;

  if (!results.length) {
    el.results.innerHTML = `<div class="empty">No results for ${escapeHTML(state.query)}</div>`;
    return;
  }

  const shown = results.slice(0, state.shown);
  const pocTotal = results.pocTotal;
  const remaining = results.length - shown.length;
  const footer = remaining > 0
    ? `<button type="button" class="poc-more" style="padding:9px 16px" data-more-results>+ ${formatCount(remaining)} more matching CVEs</button>`
    : '';

  el.results.innerHTML = `<div class="panel-head">
      <h2>Results</h2>
      <span class="panel-count">${formatCount(results.length)} CVE${results.length === 1 ? '' : 's'} · ${formatCount(pocTotal)} PoCs</span>
    </div>
    <div class="col-head"><span>CVE</span><span>DESCRIPTION / POC LINKS</span></div>
    ${shown.map(resultRow).join('')}${footer}`;
  pruneExpanders();

  if (elapsed != null) {
    el.status.textContent = `matched in ${Math.max(1, Math.round(elapsed))}ms`;
  }
}

function trendRow(item) {
  const popular = item.stars >= 500 ? ' is-popular' : '';
  // The trending table flags the same catalogue the CVE rows do, so a row worth
  // reading first is visible without opening it.
  const flagged = item.cve && kev[item.cve]
    ? `<span class="trend-kev" title="Listed in CISA's Known Exploited Vulnerabilities catalogue">KEV</span>`
    : '';
  return `<div class="trend-row">
    <span class="trend-stars${popular}">${formatStars(item.stars)} <span class="star">★</span></span>
    <span class="trend-age">${escapeHTML(longAge(item._pushed))}</span>
    <span class="trend-name-cell">${flagged}<a class="trend-name" href="${escapeHTML(item.url)}" target="_blank" rel="noopener">${escapeHTML(item.name)}</a></span>
    <span class="trend-desc">${escapeHTML(item.desc || '')}</span>
  </div>`;
}

function renderTrending() {
  el.results.hidden = true;
  el.trending.hidden = false;

  const ranked = trending.slice();
  if (state.mode === 'TRENDING') {
    // Stars weighted against the age the row displays, so the order is legible
    // from the table itself: a fresh PoC pulling stars outranks a bigger one
    // that has been sitting still.
    const rank = r => r.stars / Math.pow((r._pushed == null ? 8760 : r._pushed) + 6, 0.45);
    ranked.sort((a, b) => rank(b) - rank(a));
  } else {
    ranked.sort((a, b) => (a._pushed == null ? Infinity : a._pushed) - (b._pushed == null ? Infinity : b._pushed));
  }
  const rows = ranked.slice(0, TREND_ROWS);

  el.trendNote.textContent = state.mode === 'TRENDING'
    ? 'stars weighted against time since the last commit'
    : 'newest commit first';

  el.trendRows.innerHTML = rows.length
    ? rows.map(trendRow).join('')
    : '<div class="trend-row"><span class="trend-desc">No recent PoCs.</span></div>';

  document.querySelectorAll('.switch button').forEach(button => {
    button.setAttribute('aria-pressed', String(button.dataset.mode === state.mode));
  });
}

function paintHeroStats() {
  if (!el.statTotal) return;
  if (indexMeta) {
    el.statTotal.textContent = formatCount(indexMeta.total_cves);
    el.statPocs.textContent = formatCount(indexMeta.with_pocs);
  }
  const flagged = Object.keys(kev).length;
  if (flagged) el.statKev.textContent = formatCount(flagged);
}

function idleStatus() {
  // The hero carries the totals now, so the field keeps its slot for timings.
  return '';
}

function render() {
  if (state.query.length < MIN_QUERY) {
    el.status.textContent = state.ready ? idleStatus() : 'loading index…';
    renderTrending();
    return;
  }
  if (!state.ready) {
    el.results.hidden = false;
    el.trending.hidden = true;
    el.status.textContent = 'loading index…';
    el.results.innerHTML = '<div class="empty">Loading the CVE index…</div>';
    return;
  }
  const started = performance.now();
  state.results = runSearch(state.query);
  renderResults(performance.now() - started);
}

/* ---- wiring ------------------------------------------------------------ */

// A full pass over the index costs ~200ms, so one per keystroke makes typing
// stutter. 160ms covers an ordinary typing cadence without the wait being felt;
// clearing the field stays instant.
let searchTimer = null;
el.input.addEventListener('input', () => {
  const next = el.input.value.trim();
  if (next === state.query) return;
  state.query = next;
  state.shown = PAGE_SIZE;
  clearTimeout(searchTimer);
  if (next.length < MIN_QUERY) {
    render();
    return;
  }
  searchTimer = setTimeout(render, 160);
});

document.querySelector('.search').addEventListener('submit', event => event.preventDefault());

// Typing anywhere on the page means typing into the search field. The keystroke
// is not swallowed: focusing during keydown lets the character land in the
// field it just moved to, so the first letter is never lost.
document.addEventListener('keydown', event => {
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  if (document.activeElement === el.input) {
    if (event.key === 'Escape') {
      el.input.value = '';
      el.input.dispatchEvent(new Event('input', { bubbles: true }));
      el.input.blur();
    }
    return;
  }
  const active = document.activeElement;
  const editing = active && (active.isContentEditable
    || ['INPUT', 'TEXTAREA', 'SELECT'].includes(active.tagName));
  if (editing) return;
  // A lone slash is the shortcut, so it focuses without typing itself.
  if (event.key === '/') {
    event.preventDefault();
    el.input.focus();
    return;
  }
  if (event.key.length !== 1 && event.key !== 'Backspace') return;
  el.input.focus();
});

// A pointer landing on the page is not a request to type, so the field is only
// focused up front where a keyboard is the likely input.
if (window.matchMedia('(min-width: 900px)').matches) el.input.focus();

document.querySelector('.switch').addEventListener('click', event => {
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
  paintHeroStats();
  render();

  // The repository metadata is optional: without it the PoC rows simply lose
  // their star and age columns, which is the documented fallback.
  loadJSON('/kev.json', { cache: 'no-cache' }).then(data => {
    kev = data || {};
    paintHeroStats();
    // A search already on screen owns the view; only repaint the idle table.
    if (!state.query) renderTrending();
    if (state.query && state.ready) renderResults(null);
  }).catch(err => console.warn(err.message));

  loadJSON('/nuclei.json', { cache: 'no-cache' }).then(data => {
    ratings = data || {};
    if (state.query && state.ready) renderResults(null);
  }).catch(err => console.warn(err.message));

  loadJSON('/epss.json', { cache: 'no-cache' }).then(data => {
    epss = data || {};
    if (state.query && state.ready) renderResults(null);
  }).catch(err => console.warn(err.message));

  loadJSON('/repo_meta.json', { cache: 'no-cache' }).then(data => {
    repoMeta = data || {};
    for (const entry of dataset) entry._ranked = null;
    if (state.query && state.ready) renderResults(null);
  }).catch(err => console.warn(err.message));

  try {
    dataset = prepareDataset(await loadJSON('/CVE_list.json', { cache: 'no-cache' }));
    state.ready = true;
    render();
  } catch (err) {
    console.warn(err.message);
    el.status.textContent = 'index unavailable';
  }
})();
