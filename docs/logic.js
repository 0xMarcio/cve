'use strict';

const REPLACE_STRINGS = ['HackTheBox - ', 'VulnHub - ', 'UHC - '];
const PAGE_SIZE = 50;
const POC_PREVIEW = 5;
const ADVISORY_PREVIEW = 3;
const TREND_ROWS = 20;
const MIN_QUERY = 2;
const POC_FIELDS = ['poc', 'nuclei', 'msf', 'edb', 'vulhub', 'collections'];
const FILTER_OPTIONS = {
  severity: [
    ['CRITICAL', 'CRITICAL'], ['HIGH', 'HIGH'], ['MEDIUM', 'MEDIUM'],
    ['LOW', 'LOW']
  ],
  source: [
    ['GITHUB', 'GITHUB'], ['GHSA', 'GHSA'], ['REFERENCE', 'REFERENCE'],
    ['NUCLEI', 'NUCLEI'], ['MSF', 'METASPLOIT'], ['EDB', 'EXPLOITDB'],
    ['VULHUB', 'VULHUB'], ['COLLECTIONS', 'COLLECTIONS']
  ]
};

const state = {
  query: '',
  mode: 'TRENDING',
  shown: PAGE_SIZE,
  descOpen: new Set(),
  pocOpen: new Set(),
  advisoryOpen: new Set(),
  kevOnly: false,
  filters: {
    severity: new Set(FILTER_OPTIONS.severity.map(([value]) => value)),
    source: new Set(FILTER_OPTIONS.source.map(([value]) => value))
  },
  ready: false,
  results: []
};

let dataset = [];
let repoMeta = {};
let kev = {};
let ratings = {};
let metadata = {};
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

/** 1st, 2nd, 3rd, 4th. A hard-coded "th" printed 51th on 21,100 CVEs. */
function ordinal(n) {
  const tens = n % 100;
  if (tens >= 11 && tens <= 13) return `${n}th`;
  return `${n}${['th', 'st', 'nd', 'rd'][n % 10] || 'th'}`;
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
    entry._pocText = entryLinks(entry).join(' ').toLowerCase();
  }
  return entry._pocText;
}

function entryLinks(entry) {
  if (entry._allLinks === undefined) {
    entry._allLinks = uniqueSourceLinks(POC_FIELDS.flatMap(field => entry[field] || []));
  }
  return entry._allLinks;
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
  for (const url of entryLinks(entry)) {
    const text = url.toLowerCase();
    if (matchers.every(m => wordStart(text, m.raw) >= 0 || (m.loose && m.loose.test(text)))) {
      hits += 1;
      if (hits >= 999) break;
    }
  }
  return hits;
}

function canonicalCvss(id) {
  const rows = ((metadata[id] || {}).cvss || []);
  if (!Array.isArray(rows) || !Array.isArray(rows[0])) return null;
  const row = rows[0];
  return {
    score: Number(row[1]),
    severity: String(row[2] || '').toUpperCase()
  };
}

function entrySeverity(entry) {
  const score = canonicalCvss(entry.cve);
  if (score && ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(score.severity)) {
    return score.severity;
  }
  const fallback = String((ratings[entry.cve] || {}).severity || '').toUpperCase();
  return ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(fallback) ? fallback : '';
}

function hasActiveFilters() {
  return state.kevOnly || Object.entries(state.filters).some(
    ([kind, filter]) => filter.size !== FILTER_OPTIONS[kind].length
  );
}

function entrySources(entry) {
  const sources = new Set();
  const fields = {
    NUCLEI: 'nuclei', MSF: 'msf', EDB: 'edb', VULHUB: 'vulhub', COLLECTIONS: 'collections'
  };
  for (const [source, field] of Object.entries(fields)) {
    if ((entry[field] || []).length) sources.add(source);
  }
  for (const url of entry.poc || []) {
    if (/^https?:\/\/(?:www\.)?github\.com\/advisories\/GHSA-/i.test(url)) {
      sources.add('GHSA');
    } else if (repoFromUrl(url)) {
      sources.add('GITHUB');
    } else {
      sources.add('REFERENCE');
    }
  }
  return sources;
}

function matchesMultiFilter(values, filter) {
  for (const value of filter) {
    if (values.has(value)) return true;
  }
  return false;
}

function matchesFilters(entry) {
  if (state.kevOnly && !kev[entry.cve]) return false;
  if (!matchesMultiFilter(entrySources(entry), state.filters.source)) return false;
  // ALL has to mean all. The options list only names the four scored bands, so
  // testing membership hid every CVE nobody has scored yet even with nothing
  // filtered: 41 of them were unreachable by search, including by exact ID.
  if (state.filters.severity.size === FILTER_OPTIONS.severity.length) return true;
  const severity = entrySeverity(entry);
  return severity ? matchesMultiFilter(new Set([severity]), state.filters.severity) : false;
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
    if (!matchesFilters(entry)) continue;
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
    results.pocTotal += entryLinks(entry).length;
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
    if (!cve) continue;
    for (const field of POC_FIELDS) {
      if (!Array.isArray(entry[field])) entry[field] = [];
    }
    if (!entryLinks(entry).length) continue;
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
  refreshed: document.querySelector('[data-refreshed]'),
  filterTriggers: {
    severity: document.querySelector('[data-filter-trigger="severity"]'),
    source: document.querySelector('[data-filter-trigger="source"]')
  },
  filterSummaries: {
    severity: document.querySelector('[data-filter-summary="severity"]'),
    source: document.querySelector('[data-filter-summary="source"]')
  },
  filterOptions: {
    severity: document.querySelector('[data-filter-options="severity"]'),
    source: document.querySelector('[data-filter-options="source"]')
  },
  kevOnly: document.querySelector('[data-filter-kev]'),
  clearFilters: document.querySelector('[data-clear-filters]')
};

const CURATED = [
  { match: 'github.com/advisories/GHSA-', tag: 'GHSA', hint: 'GitHub reviewed advisory with reproducible exploit material',
    label: url => url.split('/').pop() },
  { match: '/zan8in/afrog/', tag: 'AFROG', hint: 'Runnable afrog CVE template',
    label: url => decodeURIComponent(url.split('/').pop()) },
  { match: '/chaitin/xray/', tag: 'XRAY', hint: 'Runnable xray CVE template',
    label: url => decodeURIComponent(url.split('/').pop()) },
  { match: '/helloexp/0day/', tag: '0DAY', hint: 'CVE-specific exploit collection path',
    label: url => decodeURIComponent(url.split('/').pop()) },
  { match: '/tzwlhack/Vulnerability/', tag: 'POC', hint: 'CVE-specific reproduction guide',
    label: url => decodeURIComponent(url.split('/').pop()) },
  { match: '/nuclei-templates/', tag: 'NUCLEI', hint: 'Runnable nuclei detection template',
    label: url => url.split('/').pop() },
  { match: '/metasploit-framework/', tag: 'MSF', hint: 'Metasploit module',
    label: url => url.split('/modules/').pop().replace(/\.rb$/, '') },
  { match: 'exploit-db.com/exploits/', tag: 'EDB', hint: 'ExploitDB entry',
    label: url => 'exploit-db.com/' + url.split('/').pop() },
  { match: '/vulhub/vulhub/tree/', tag: 'VULHUB', hint: 'Runnable Vulhub environment',
    label: url => url.split('/tree/master/').pop() }
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
  // Curated entries lead: templates, exploit archives, modules and runnable
  // environments can be used as they stand without first reading a repository.
  entry._ranked = uniqueSourceLinks([
    ...(entry.nuclei || []), ...(entry.msf || []), ...(entry.edb || []), ...(entry.vulhub || []),
    ...(entry.collections || []),
    ...scored.map(item => item.url)
  ]);
  return entry._ranked;
}

function cvssTooltip(id) {
  const rows = ((metadata[id] || {}).cvss || []);
  if (!Array.isArray(rows)) return '';
  return rows.filter(Array.isArray).map(row => {
    const source = row[4] ? ` by ${row[4]}` : '';
    const assessment = row[5] ? ` (${row[5]})` : '';
    return `CVSS ${row[0]} ${row[1]} ${row[2]}${source}${assessment}\n${row[3] || ''}`.trim();
  }).join('\n\n');
}

function advisoryRow(item) {
  if (!Array.isArray(item) || !item[0]) return '';
  const url = String(item[0]);
  const tags = Array.isArray(item[1]) ? item[1].map(String) : [];
  const tag = tags.includes('Vendor Advisory') ? 'VENDOR' : tags.includes('Patch') ? 'PATCH' : 'ADVISORY';
  return '<div class="poc-row"><span class="poc-name">' +
    `<span class="poc-tag is-advisory" title="${escapeHTML(tags.join(', ') || 'Advisory')}">${tag}</span>` +
    `<a class="plain" href="${escapeHTML(url)}" target="_blank" rel="noopener">${escapeHTML(plainLinkLabel(url))}</a>` +
    '</span><span class="poc-stars"></span><span class="poc-age"></span></div>';
}

function normalizedLink(url) {
  const parsed = repoFromUrl(String(url || ''));
  if (parsed) return `github:${parsed.owner.toLowerCase()}/${parsed.repo.toLowerCase()}`;
  return String(url || '').replace(/\/$/, '');
}

function uniqueSourceLinks(urls) {
  const seen = new Set();
  return urls.filter(url => {
    const key = normalizedLink(url);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
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

  const advisoryOpen = state.advisoryOpen.has(id);
  const pocLinks = new Set(entryLinks(entry).map(normalizedLink));
  const advisories = ((metadata[id] || {}).advisories || [])
    .filter(item => Array.isArray(item) && !pocLinks.has(normalizedLink(item[0])));
  const shownAdvisories = advisoryOpen ? advisories : advisories.slice(0, ADVISORY_PREVIEW);
  const advisoryMore = advisories.length > ADVISORY_PREVIEW
    ? `<button type="button" class="poc-more" data-toggle-advisory="${escapeHTML(id)}">` +
      `${advisoryOpen ? '↑ show fewer' : '+ ' + formatCount(advisories.length - ADVISORY_PREVIEW) + ' more'}</button>`
    : '';
  const advisoryHtml = advisories.length
    ? `<div class="advisory-list"><div class="advisory-head">CREDIBLE ADVISORIES <span>${formatCount(advisories.length)}</span></div>` +
      `${shownAdvisories.map(advisoryRow).join('')}${advisoryMore}</div>`
    : '';

  // NVD is canonical and carries every CVSS generation. Nuclei remains a
  // fallback for a template scored before NVD or its CNA publishes a vector.
  const canonical = canonicalCvss(id);
  const fallback = ratings[id] || {};
  const severity = canonical ? canonical.severity : entrySeverity(entry);
  const cvss = canonical ? canonical.score : fallback.cvss;
  const tooltip = canonical ? cvssTooltip(id) : String(fallback.cvss_vector || '');
  const severityChip = severity
    ? `<span class="chip chip-sev is-${escapeHTML(severity.toLowerCase())}"${tooltip ? ` title="${escapeHTML(tooltip)}"` : ''}>` +
      `${escapeHTML(severity)}${cvss != null ? ' ' + escapeHTML(cvss) : ''}</span>`
    : '';
  // FIRST's feed covers nearly the whole index; a template's own score is the
  // fallback for the handful it misses.
  const scored = epss[id] || (fallback.epss != null ? [fallback.epss, fallback.epss_pct || 0] : null);
  const epssChip = scored
    ? `<span class="chip chip-epss${scored[0] >= 0.1 ? ' is-hot' : ''}" title="EPSS: estimated chance of exploitation in the next 30 days, ${ordinal(Math.round(scored[1] * 100))} percentile">` +
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
    <a class="result-id" href="/${encodeURIComponent(id)}">${escapeHTML(id)}</a>
    <div class="result-pocs">${formatCount(links.length)} linked PoC${links.length === 1 ? '' : 's'}</div>
    ${dateHtml}
    <div class="chips">${kevChip}${severityChip}${epssChip}
      <a class="chip" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener">NVD ↗</a>
      <a class="chip" href="https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}" target="_blank" rel="noopener">CVE.ORG ↗</a>
    </div>
  </div>
  <div class="result-body">
    <p class="result-desc${open ? ' is-open' : ''}">${escapeHTML(entry.desc || '')}</p>
    <button type="button" class="expander" data-toggle-desc="${escapeHTML(id)}">${open ? '↑ collapse' : '↓ full description'}</button>
    <div class="poc-list">
      ${visible.map(pocRow).join('')}
      ${moreButton}
    </div>
    ${advisoryHtml}
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
    const subject = state.query.length >= MIN_QUERY
      ? ` for ${escapeHTML(state.query)}`
      : ' for the active filters';
    el.results.innerHTML = `<div class="empty">No results${subject}</div>`;
    // The live region is the only account of this a screen reader gets, and
    // returning here left it reading "loading index…" over a page that had
    // already given up.
    if (elapsed != null) {
      el.status.textContent = `no results in ${Math.max(1, Math.round(elapsed))}ms`;
    }
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
      <span class="panel-count">${formatCount(results.length)} CVE${results.length === 1 ? '' : 's'} · ${formatCount(pocTotal)} PoC${pocTotal === 1 ? '' : 's'}</span>
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

/* ---- url state --------------------------------------------------------- */

// A result was unlinkable: every search lived in memory, so nobody could cite
// one and no crawler ever saw a second page. The query rides in ?q= now, which
// is also the route the SearchAction in index.html declares.
function readURLState() {
  const params = new URLSearchParams(location.search);
  const query = (params.get('q') || '').trim();
  if (query) {
    state.query = query;
    el.input.value = query;
  }
  if (params.get('kev') === '1') state.kevOnly = true;
}

// replaceState, not pushState: typing a query should not bury the back button
// under one history entry per keystroke.
let urlTimer = null;
function syncURL() {
  clearTimeout(urlTimer);
  urlTimer = setTimeout(() => {
    const params = new URLSearchParams();
    if (state.query.length >= MIN_QUERY) params.set('q', state.query);
    if (state.kevOnly) params.set('kev', '1');
    const search = params.toString();
    const next = search ? `${location.pathname}?${search}` : location.pathname;
    if (next !== location.pathname + location.search) history.replaceState(null, '', next);
  }, 300);
}

function render() {
  syncURL();
  if (state.query.length < MIN_QUERY && !hasActiveFilters()) {
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
  state.results = runSearch(state.query.length >= MIN_QUERY ? state.query : '');
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

function renderFilterOptions() {
  for (const [kind, options] of Object.entries(FILTER_OPTIONS)) {
    el.filterOptions[kind].innerHTML = options.map(([value, label]) =>
      `<label class="filter-option">` +
      `<input type="checkbox" data-filter-kind="${kind}" data-filter-value="${value}">` +
      `<span class="filter-check" aria-hidden="true"></span>` +
      `<span class="filter-option-label">${escapeHTML(label)}</span></label>`
    ).join('');
  }
}

function closeFilterMenus(except) {
  for (const kind of Object.keys(FILTER_OPTIONS)) {
    if (kind === except) continue;
    el.filterOptions[kind].hidden = true;
    el.filterTriggers[kind].setAttribute('aria-expanded', 'false');
  }
}

function filterTitle(kind) {
  const selected = [...state.filters[kind]];
  return selected.length === FILTER_OPTIONS[kind].length ? 'All values' : selected.join(', ');
}

function syncFilterControls() {
  for (const kind of Object.keys(FILTER_OPTIONS)) {
    const filter = state.filters[kind];
    const summary = filter.size === FILTER_OPTIONS[kind].length
      ? 'ALL'
      : filter.size === 1 ? [...filter][0] : `${filter.size} SELECTED`;
    el.filterSummaries[kind].textContent = summary;
    el.filterTriggers[kind].title = filterTitle(kind);
    for (const checkbox of el.filterOptions[kind].querySelectorAll('[data-filter-value]')) {
      checkbox.checked = filter.has(checkbox.dataset.filterValue);
    }
  }
  el.kevOnly.setAttribute('aria-pressed', String(state.kevOnly));
  el.clearFilters.hidden = !hasActiveFilters();
}

for (const kind of Object.keys(FILTER_OPTIONS)) {
  el.filterTriggers[kind].addEventListener('click', () => {
    const opening = el.filterOptions[kind].hidden;
    closeFilterMenus(kind);
    el.filterOptions[kind].hidden = !opening;
    el.filterTriggers[kind].setAttribute('aria-expanded', String(opening));
  });
  el.filterOptions[kind].addEventListener('change', event => {
    const checkbox = event.target.closest('[data-filter-value]');
    if (!checkbox) return;
    const filter = state.filters[kind];
    const value = checkbox.dataset.filterValue;
    if (checkbox.checked) filter.add(value);
    else filter.delete(value);
    state.shown = PAGE_SIZE;
    syncFilterControls();
    render();
  });
}

document.addEventListener('click', event => {
  if (!event.target.closest('.filter-menu')) closeFilterMenus();
});

el.kevOnly.addEventListener('click', () => {
  state.kevOnly = !state.kevOnly;
  state.shown = PAGE_SIZE;
  syncFilterControls();
  render();
});

el.clearFilters.addEventListener('click', () => {
  state.kevOnly = false;
  for (const [kind, filter] of Object.entries(state.filters)) {
    filter.clear();
    for (const [value] of FILTER_OPTIONS[kind]) filter.add(value);
  }
  state.shown = PAGE_SIZE;
  syncFilterControls();
  render();
});

renderFilterOptions();
syncFilterControls();

// Typing anywhere on the page means typing into the search field. The keystroke
// is not swallowed: focusing during keydown lets the character land in the
// field it just moved to, so the first letter is never lost.
document.addEventListener('keydown', event => {
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  const openFilter = Object.keys(FILTER_OPTIONS).find(kind =>
    el.filterTriggers[kind].getAttribute('aria-expanded') === 'true');
  if (event.key === 'Escape' && openFilter) {
    closeFilterMenus();
    el.filterTriggers[openFilter].focus();
    return;
  }
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
    || ['INPUT', 'TEXTAREA', 'SELECT', 'BUTTON'].includes(active.tagName));
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
  const advisory = event.target.closest('[data-toggle-advisory]');
  const more = event.target.closest('[data-more-results]');
  if (desc) {
    const id = desc.dataset.toggleDesc;
    state.descOpen.has(id) ? state.descOpen.delete(id) : state.descOpen.add(id);
  } else if (poc) {
    const id = poc.dataset.togglePoc;
    state.pocOpen.has(id) ? state.pocOpen.delete(id) : state.pocOpen.add(id);
  } else if (advisory) {
    const id = advisory.dataset.toggleAdvisory;
    state.advisoryOpen.has(id) ? state.advisoryOpen.delete(id) : state.advisoryOpen.add(id);
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
  readURLState();
  syncFilterControls();
  paintHeroStats();
  render();

  // The repository metadata is optional: without it the PoC rows simply lose
  // their star and age columns, which is the documented fallback.
  loadJSON('/kev.json', { cache: 'no-cache' }).then(data => {
    kev = data || {};
    el.kevOnly.disabled = false;
    paintHeroStats();
    if (state.ready && (state.query || hasActiveFilters())) render();
    else renderTrending();
  }).catch(err => console.warn(err.message));

  loadJSON('/cve_metadata.json', { cache: 'no-cache' }).then(data => {
    metadata = data || {};
    el.filterTriggers.severity.disabled = false;
    if (state.ready && (state.query || hasActiveFilters())) render();
  }).catch(err => console.warn(err.message));

  loadJSON('/nuclei.json', { cache: 'no-cache' }).then(data => {
    ratings = data || {};
    el.filterTriggers.severity.disabled = false;
    if (state.ready && (state.query || hasActiveFilters())) render();
  }).catch(err => console.warn(err.message));

  loadJSON('/epss.json', { cache: 'no-cache' }).then(data => {
    epss = data || {};
    if (state.ready && (state.query || hasActiveFilters())) renderResults(null);
  }).catch(err => console.warn(err.message));

  loadJSON('/repo_meta.json', { cache: 'no-cache' }).then(data => {
    repoMeta = data || {};
    for (const entry of dataset) entry._ranked = null;
    if (state.ready && (state.query || hasActiveFilters())) renderResults(null);
  }).catch(err => console.warn(err.message));

  try {
    dataset = prepareDataset(await loadJSON('/CVE_list.json', { cache: 'no-cache' }));
    state.ready = true;
    el.filterTriggers.source.disabled = false;
    render();
  } catch (err) {
    console.warn(err.message);
    el.status.textContent = 'index unavailable';
  }
})();
