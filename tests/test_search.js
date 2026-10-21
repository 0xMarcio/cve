'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { MessageChannel } = require('node:worker_threads');

const script = fs.readFileSync(path.join(__dirname, '../docs/logic.js'), 'utf8');

function startPage(t, { search = '', trending, kev = {}, repositories = {}, indexError = false, cvssError = false, entries }) {
  const elements = new Map();
  const calls = [];
  const document = {
    addEventListener() {},
    querySelectorAll: () => [],
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, {
        value: '',
        innerHTML: selector === '[data-trend-rows]' ? '<a href="/CVE-2026-1234">Prerendered PoC</a>' : '',
        addEventListener() {}, setAttribute() {}, querySelectorAll: () => []
      });
      return elements.get(selector);
    }
  };
  const context = vm.createContext({
    console: { warn() {} }, document, performance, MessageChannel, URLSearchParams, URL,
    location: { pathname: '/', search },
    window: { matchMedia: () => ({ matches: false }) },
    setTimeout() {}, clearTimeout() {},
    async fetch(url) {
      calls.push(url);
      if (url === '/CVE_list.json' && indexError) throw new Error('Index unavailable');
      if (url === '/cvss.json' && cvssError) throw new Error('CVSS unavailable');
      const data = url === '/trending_poc.json' ? await trending
        : url === '/kev.json' ? await kev
        : url === '/repo_meta.json' ? await repositories
        : url === '/CVE_list.json' ? entries || [{ cve: 'CVE-2026-1234', desc: 'widget', poc: ['https://github.com/owner/poc'] }]
          : {};
      return { ok: true, json: async () => data };
    }
  });
  vm.runInContext(script, context);
  t.after(() => vm.runInContext('yieldPort.port1.close(); yieldPort.port2.close();', context));
  return { elements, calls, context };
}

test('pending CVEs are searchable by identifier and PoC name without NVD metadata', async t => {
  const entries = ['CVE-2026-109618', 'CVE-2026-109619'].map(cve => ({
    cve, desc: 'Official CVE details are pending.', metadata_pending: true,
    poc: ['https://github.com/example/php2shell-poc']
  }));
  for (const query of ['CVE-2026-109618', 'CVE-2026-109619', 'php2shell']) {
    const { elements } = startPage(t, { search: `?q=${query}`, entries, trending: new Promise(() => {}) });
    await new Promise(setImmediate);
    const html = elements.get('[data-results]').innerHTML;
    assert.match(html, /CVE metadata pending/);
    assert.match(html, /https:\/\/github.com\/example\/php2shell-poc/);
    assert.match(html, new RegExp(query === 'php2shell' ? 'CVE-2026-109618' : query));
  }
});

test('repository security advisories have GHSA filtering without repository stars or dates', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const url = 'https://github.com/vendor/project/security/advisories/GHSA-1234';
  vm.runInContext('repoMeta = { "vendor/project": [5000, "2026-10-06"] };', context);
  const row = vm.runInContext(`pocRow(${JSON.stringify(url)})`, context);
  assert.match(row, /GHSA-1234/);
  assert.doesNotMatch(row, /★|5\.0k/);
  assert.equal(vm.runInContext(`entrySources({poc: [${JSON.stringify(url)}]}).has('GHSA')`, context), true);
  assert.equal(vm.runInContext(`repoFromUrl(${JSON.stringify(url)})`, context), null);
});

test('repository and artifact rows distinguish zero, missing metadata and non-repository links', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  vm.runInContext('repoMeta = { "owner/poc": [0, "2026-10-21"] };', context);
  for (const suffix of ['', '/blob/main/reproduce.py']) {
    const row = vm.runInContext(`pocRow('https://github.com/Owner/PoC${suffix}', true)`, context);
    assert.match(row, /0 <span class="star">★<\/span>/);
    assert.match(row, /Repository stars: owner\/poc/);
    assert.match(row, /Repository last push: 2026-10-21 UTC/);
  }
  const missing = vm.runInContext("pocRow('https://github.com/owner/missing')", context);
  assert.match(missing, /Repository stars: owner\/missing \(unavailable\)/);
  assert.match(missing, />N\/A<\/span>/);
  assert.doesNotMatch(missing, /★/);
  const external = vm.runInContext("trendRow({url:'https://www.exploit-db.com/exploits/12345', stars:5000, artifact:true}, true)", context);
  assert.match(external, /No GitHub repository/);
  assert.doesNotMatch(external, /★|5\.0k/);
  const today = new Date().toISOString().slice(0, 10);
  vm.runInContext(`repoMeta['owner/poc'][1] = '${today}'`, context);
  assert.match(vm.runInContext("repositoryCells('https://github.com/owner/poc')", context), />today<\/span>/);
});

test('late repository metadata reorders a long PoC list by stars regardless of CVE spelling', async t => {
  let finishMetadata;
  const repositories = new Promise(resolve => { finishMetadata = resolve; });
  const named = 'https://github.com/owner/CVE-2021-1675';
  const alias = 'https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527';
  const unknown = 'https://github.com/owner/unknown';
  const entries = [{ cve: 'CVE-2021-1675', desc: 'PrintNightmare',
    poc: [named, unknown, ...Array.from({length: 25}, (_, i) => `https://github.com/owner/CVE-2021-1675-${i}`), alias] }];
  const { context, elements } = startPage(t, { search: '?q=CVE-2021-1675', entries, repositories,
                                              trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  vm.runInContext("state.pocOpen.add('CVE-2021-1675'); renderResults(null)", context);
  finishMetadata({ 'owner/cve-2021-1675': [0, '2026-10-21'], 'nemo-wq/printnightmare-cve-2021-34527': [177, '2021-06-29'] });
  await new Promise(setImmediate);
  const links = Array.from(vm.runInContext('rankedLinks(dataset[0])', context));
  assert.equal(links.length, 28);
  assert.deepEqual(links.slice(0, 2), [alias, named]);
  assert.ok(links.indexOf(unknown) > 1);
  const html = elements.get('[data-results]').innerHTML;
  assert.ok(html.indexOf(`href="${alias}"`) < html.indexOf(`href="${named}"`));
  assert.match(html, /177 <span class="star">★/);
  assert.equal(vm.runInContext("state.pocOpen.has('CVE-2021-1675')", context), true);
});

test('an open tab refreshes one complete data snapshot without losing its search or expansion', async t => {
  let finishOldMetadata;
  const repositories = new Promise(resolve => { finishOldMetadata = resolve; });
  const original = { generated: '2026-10-21T10:00:00Z', with_pocs: 1, total_cves: 1, items: [], landed: [] };
  const { context, elements } = startPage(t, { search: '?q=widget&src=github&sort=newest', repositories, trending: original });
  await new Promise(setImmediate);
  vm.runInContext("state.pocOpen.add('CVE-2026-1234')", context);
  const feed = { ...original, generated: '2026-10-21T12:00:00Z' };
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: ['https://github.com/owner/current'] }];
  const data = { '/trending_poc.json': feed, '/CVE_list.json': entries,
    '/repo_meta.json': { 'owner/current': [42, '2026-10-21'] }, '/cvss.json': {},
    '/advisories.json': {}, '/nuclei.json': {}, '/kev.json': {}, '/epss.json': {} };
  context.fetch = async url => ({ ok: true, json: async () => data[url.split('?')[0]] });
  assert.equal(await vm.runInContext('refreshData(true)', context), true);
  finishOldMetadata({ 'owner/current': [1, '2020-01-01'] });
  await new Promise(setImmediate);
  assert.equal(vm.runInContext('state.query', context), 'widget');
  assert.equal(vm.runInContext('state.sort', context), 'NEWEST');
  assert.equal(vm.runInContext("[...state.filters.source].join(',')", context), 'GITHUB');
  assert.equal(vm.runInContext("state.pocOpen.has('CVE-2026-1234')", context), true);
  assert.equal(vm.runInContext("repoMeta['owner/current'][0]", context), 42);
  assert.match(elements.get('[data-results]').innerHTML, /42 <span class="star">★/);
  assert.doesNotMatch(elements.get('[data-results]').innerHTML, /href="https:\/\/github.com\/owner\/poc"/);
  assert.equal(await vm.runInContext('refreshData(true)', context), false);
});

test('failed or mixed-generation refreshes keep the previous searchable data', async t => {
  const original = { generated: '2026-10-21T10:00:00Z', with_pocs: 1, total_cves: 1, items: [], landed: [] };
  const { context } = startPage(t, { search: '?q=widget', trending: original });
  await new Promise(setImmediate);
  for (const failure of ['download', 'changed']) {
    let feeds = 0;
    context.fetch = async url => {
      const file = url.split('?')[0];
      if (failure === 'download' && file === '/repo_meta.json') throw new Error('Unavailable');
      const payload = file === '/trending_poc.json'
        ? { ...original, generated: ++feeds > 1 && failure === 'changed' ? 'newer' : 'new' }
        : file === '/CVE_list.json' ? [{ cve: 'CVE-2026-1234', desc: 'changed', poc: [] }] : {};
      return { ok: true, json: async () => payload };
    };
    assert.equal(await vm.runInContext('refreshData(true)', context), false);
    assert.equal(vm.runInContext('dataset[0].desc', context), 'widget');
    assert.equal(vm.runInContext('indexMeta.generated', context), original.generated);
  }
});

test('failed enrichment cannot silently apply bookmarked filters against empty data', async t => {
  const { context, elements } = startPage(t, {
    search: '?q=widget&kev=1&sev=critical', cvssError: true,
    kev: Promise.reject(new Error('KEV unavailable')), trending: new Promise(() => {})
  });
  await new Promise(setImmediate);
  assert.equal(vm.runInContext('state.kevOnly', context), true);
  assert.equal(vm.runInContext('state.filters.severity.size', context), 1);
  assert.match(elements.get('[data-results]').innerHTML, /href="\/CVE-2026-1234"/);
  assert.match(elements.get('[data-notices]').textContent, /KEV filter unavailable/);
  assert.match(elements.get('[data-notices]').textContent, /severity filter unavailable/);
  assert.equal(elements.get('[data-notices]').hidden, false);
});

test('requested filters recover after an outage without losing the bookmark or ignoring a clear', async t => {
  for (const cleared of [false, true]) {
    const entries = ['CVE-2026-1234', 'CVE-2026-1235'].map(cve => ({ cve, desc: 'widget', poc: ['https://github.com/owner/' + cve] }));
    const feed = { generated: '2026-10-21T10:00:00Z', with_pocs: 2, total_cves: 2, items: [], landed: [] };
    const { context, elements } = startPage(t, { search: '?q=widget&kev=1&sev=critical', entries, cvssError: true,
      kev: Promise.reject(new Error('Unavailable')), trending: feed });
    await new Promise(setImmediate);
    assert.match(elements.get('[data-results]').innerHTML, /href="\/CVE-2026-1235"/);
    if (cleared) vm.runInContext('state.kevOnly = false; state.filters.severity = new Set(FILTER_OPTIONS.severity.map(([value]) => value))', context);
    context.fetch = async url => ({ ok: true, json: async () => {
      const file = url.split('?')[0];
      return file === '/trending_poc.json' ? feed : file === '/CVE_list.json' ? entries
        : file === '/kev.json' ? { 'CVE-2026-1234': ['2026-10-21', false] }
        : file === '/cvss.json' ? { 'CVE-2026-1234': [['3.1', 9.8, 'CRITICAL', '', 'nvd', 'Primary']] } : {};
    }});
    assert.equal(await vm.runInContext('refreshData(true)', context), true);
    assert.equal(vm.runInContext('state.kevOnly', context), !cleared);
    assert.equal(vm.runInContext('state.filters.severity.size', context), cleared ? 4 : 1);
    assert.equal(elements.get('[data-results]').innerHTML.includes('href="/CVE-2026-1235"'), cleared);
    assert.equal(elements.get('[data-notices]').hidden, true);
  }
});

test('equal-star links use the same code-point ordering as static CVE pages', async t => {
  const urls = ['poc_1', 'poc1', 'poc-1'].map(name => 'https://github.com/owner/' + name);
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: urls }];
  const repositories = Object.fromEntries(urls.map(url => [url.slice('https://github.com/'.length), [10, '2026-10-21']]));
  const { context } = startPage(t, { entries, repositories, trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  assert.deepEqual(Array.from(vm.runInContext('rankedLinks(dataset[0])', context)), [...urls].sort());
});

test('missing repository metadata is visible and retried even without a newer publication', async t => {
  const feed = { generated: '2026-10-21T10:00:00Z', with_pocs: 1, total_cves: 1, items: [], landed: [] };
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: ['https://github.com/owner/poc'] }];
  const { context, elements } = startPage(t, { search: '?q=widget', entries, trending: feed,
    repositories: Promise.reject(new Error('Metadata temporarily unavailable')) });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-notices]').textContent, /repository metadata unavailable/);
  context.fetch = async url => ({ ok: true, json: async () => {
    const file = url.split('?')[0];
    return file === '/trending_poc.json' ? feed : file === '/CVE_list.json' ? entries
      : file === '/repo_meta.json' ? { 'owner/poc': [0, '2026-10-21'] } : {};
  }});
  assert.equal(await vm.runInContext('refreshData(true)', context), true);
  assert.match(elements.get('[data-results]').innerHTML, /0 <span class="star">★/);
  assert.doesNotMatch(elements.get('[data-notices]').textContent, /repository metadata unavailable/);
});

test('curated artifact paths survive search rendering without duplicate repository roots', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const base = 'https://github.com/google/security-research';
  const variants = ['lts', 'mitigation'].map(kind => `${base}/tree/master/pocs/linux/kernelctf/CVE-2024-26642_${kind}`);
  const template = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/Test.yaml?version=One#Request';
  const entry = { cve: 'CVE-2024-26642', poc: [base, 'https://github.com/example/poc', 'https://github.com/EXAMPLE/POC/blob/main/exploit.py'],
    collections: [...variants, variants[0].replace('google/security-research', 'GOOGLE/Security-Research')],
    nuclei: [template, template.replace('Test.yaml', 'test.yaml')] };
  context.variantEntry = entry;
  vm.runInContext(`metadata = { 'CVE-2024-26642': { advisories: [[${JSON.stringify(base)}, ['Exploit']]] } };`, context);
  for (const fn of ['entryLinks', 'rankedLinks']) {
    const links = Array.from(vm.runInContext(`${fn}(variantEntry)`, context));
    assert.equal(links.length, 5);
    for (const url of [...variants, template, template.replace('Test.yaml', 'test.yaml')]) assert.ok(links.includes(url), url);
    assert.ok(!links.includes(base));
  }
  const html = vm.runInContext('resultRow(variantEntry)', context);
  for (const url of variants) assert.ok(html.includes(`href="${url}"`));
  assert.doesNotMatch(html, /CREDIBLE ADVISORIES/);
  assert.equal(vm.runInContext(`normalizedLink(${JSON.stringify(variants[0])}) === normalizedLink(${JSON.stringify(base)})`, context), true);
});

test('a stalled trending feed does not block a bookmarked search', async t => {
  const { elements, calls } = startPage(t, { search: '?q=widget', trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  assert.ok(calls.includes('/CVE_list.json'));
  assert.equal(elements.get('[data-search]').value, 'widget');
  assert.match(elements.get('[data-results]').innerHTML, /href="\/CVE-2026-1234"/);
});

test('a bookmarked typo is corrected when indexing finishes without changing filters', async t => {
  const { elements, context } = startPage(t, {
    search: '?q=wdiget&src=github&kev=1&sort=newest',
    trending: new Promise(() => {}),
    kev: { 'CVE-2026-1234': ['2026-10-06', false] }
  });
  await new Promise(setImmediate);
  assert.equal(vm.runInContext('wordIndex.ready', context), true);
  assert.match(elements.get('[data-results]').innerHTML, /href="\/CVE-2026-1234"/);
  assert.match(elements.get('[data-status]').textContent, /widget for wdiget/);
  assert.equal(elements.get('[data-search]').value, 'wdiget');
  assert.equal(vm.runInContext('state.query', context), 'wdiget');
  assert.equal(vm.runInContext('state.sort', context), 'NEWEST');
  assert.equal(vm.runInContext('state.kevOnly', context), true);
  assert.equal(vm.runInContext("[...state.filters.source].join(',')", context), 'GITHUB');
});

test('newest sorts by publication date rather than identifier allocation order', async t => {
  const entries = [
    { cve: 'CVE-2026-99999', published: '2026-01-01', poc_observed: '2026-10-23' },
    { cve: 'CVE-2025-1234', published: '2026-10-21' },
    { cve: 'CVE-2026-88888', published: '2026-10-20' },
    { cve: 'CVE-2026-99998' },
    { cve: 'CVE-2026-1234', metadata_pending: true, poc_observed: '2026-10-22' }
  ].map(row => ({ ...row, desc: 'widget', poc: ['https://github.com/owner/' + row.cve] }));
  const { elements } = startPage(t, { search: '?q=widget&sort=newest', entries, trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const ids = [...elements.get('[data-results]').innerHTML.matchAll(/class="result-id" href="\/([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(ids, ['CVE-2026-1234', 'CVE-2025-1234', 'CVE-2026-88888', 'CVE-2026-99999', 'CVE-2026-99998']);
  assert.match(elements.get('[data-results]').innerHTML, /PoC observed 2026-10-22/);
});

test('a failed trending feed preserves the published homepage rows', async t => {
  const { elements } = startPage(t, { trending: Promise.reject(new Error('Feed unavailable')) });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-trend-rows]').innerHTML, /Prerendered PoC/);
});

test('an empty successful feed replaces stale homepage rows', async t => {
  const { elements } = startPage(t, { trending: { items: [], total_cves: 1, with_pocs: 1, generated: '2026-10-06' } });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-trend-rows]').innerHTML, /No recent PoCs/);
});

test('an index failure stays visible when the optional trending feed arrives later', async t => {
  let finishTrending;
  const trending = new Promise(resolve => { finishTrending = resolve; });
  const { elements } = startPage(t, { search: '?q=widget', trending, indexError: true });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-results]').innerHTML, /could not be loaded/);
  assert.equal(elements.get('[data-results]').hidden, false);
  finishTrending({ items: [], total_cves: 1, with_pocs: 1, generated: '2026-10-06' });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-results]').innerHTML, /could not be loaded/);
  assert.equal(elements.get('[data-results]').hidden, false);
  assert.equal(elements.get('[data-status]').textContent, 'index unavailable');
});

test('late KEV data cannot hide a bookmarked search failure', async t => {
  let finishKev;
  const kev = new Promise(resolve => { finishKev = resolve; });
  const { elements } = startPage(t, {
    search: '?q=widget', trending: new Promise(() => {}), kev, indexError: true
  });
  await new Promise(setImmediate);
  finishKev({ 'CVE-2026-1234': ['2026-10-06', false] });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-results]').innerHTML, /could not be loaded/);
  assert.equal(elements.get('[data-results]').hidden, false);
  assert.equal(elements.get('[data-trending]').hidden, true);
});

for (const sort of ['relevance', 'newest']) {
  test(`late EPSS data refreshes results while respecting ${sort} sort`, async t => {
    const elements = new Map();
    const document = {
      addEventListener() {},
      querySelectorAll: () => [],
      querySelector(selector) {
        if (!elements.has(selector)) {
          elements.set(selector, {
            value: '',
            innerHTML: '',
            addEventListener() {},
            setAttribute() {},
            querySelectorAll: () => []
          });
        }
        return elements.get(selector);
      }
    };
    let finishEpss;
    const pendingEpss = new Promise(resolve => { finishEpss = resolve; });
    const records = ['CVE-2025-1234', 'CVE-2024-1234'].map(cve => ({
      cve,
      desc: 'widget remote execution',
      poc: [`https://github.com/owner/${cve}`]
    }));
    const context = vm.createContext({
      console,
      document,
      performance,
      MessageChannel,
      URLSearchParams,
      location: { pathname: '/', search: `?q=widget&sort=${sort}` },
      window: { matchMedia: () => ({ matches: false }) },
      setTimeout() {},
      clearTimeout() {},
      async fetch(url) {
        const data = url === '/epss.json' ? await pendingEpss
          : url === '/CVE_list.json' ? records
          : url === '/trending_poc.json'
            ? { items: [], generated: '2026-10-06', total_cves: 2, with_pocs: 2 }
            : {};
        return { ok: true, json: async () => data };
      }
    });
    vm.runInContext(script, context);
    t.after(() => vm.runInContext('yieldPort.port1.close(); yieldPort.port2.close();', context));
    const resultIds = () => [...elements.get('[data-results]').innerHTML
      .matchAll(/class="result-id" href="\/([^"]+)"/g)].map(match => match[1]);

    await new Promise(setImmediate);
    assert.deepEqual(resultIds(), ['CVE-2025-1234', 'CVE-2024-1234']);

    finishEpss({ 'CVE-2025-1234': [0.01, 0.1], 'CVE-2024-1234': [0.99, 0.999] });
    await new Promise(setImmediate);
    assert.deepEqual(resultIds(), sort === 'relevance'
      ? ['CVE-2024-1234', 'CVE-2025-1234']
      : ['CVE-2025-1234', 'CVE-2024-1234']);
    assert.match(elements.get('[data-results]').innerHTML, /EPSS 99%/);
  });
}
