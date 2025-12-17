(function(){
  let datasetPromise = null;
  let pocSet = null;
  let descSet = null;

  function fetchDataset() {
    if (datasetPromise) return datasetPromise;
    const candidates = [
      new URL('/CVE_list.json', window.location.origin).href,
      new URL('CVE_list.json', window.location.href).href,
      new URL('../CVE_list.json', window.location.href).href
    ];
    datasetPromise = (async () => {
      for (const url of candidates) {
        try {
          const res = await fetch(url, { cache: 'no-store' });
          if (!res.ok) continue;
          const data = await res.json();
          return Array.isArray(data) ? data : [];
        } catch (err) {
          console.warn('Dataset fetch failed', err);
        }
      }
      return [];
    })();
    return datasetPromise;
  }

  async function ensureSets() {
    if (pocSet && descSet) return { pocSet, descSet };
    const dataset = await fetchDataset();
    pocSet = new Set();
    descSet = new Set();
    dataset.forEach(item => {
      const cve = (item.cve || '').toUpperCase();
      const desc = (item.desc || '').trim();
      const hasPoc = Array.isArray(item.poc) && item.poc.length > 0;
      if (hasPoc) pocSet.add(cve);
      if (desc) descSet.add(cve);
    });
    return { pocSet, descSet };
  }

  function bindColumnFilters() {
    const filterInputs = document.querySelectorAll('[data-filter-table]');
    filterInputs.forEach(input => {
      const tableId = input.dataset.filterTable;
      const table = document.getElementById(tableId);
      if (!table) return;
      input.addEventListener('input', () => {
        const term = input.value.trim().toLowerCase();
        for (const row of table.querySelectorAll('tbody tr')) {
          const text = row.innerText.toLowerCase();
          row.style.display = text.includes(term) ? '' : 'none';
        }
      });
    });
  }

  async function filterTablesByData() {
    const { pocSet, descSet } = await ensureSets();
    const currentYear = new Date().getUTCFullYear();
    const isRecent = (text) => {
      const m = /CVE-(\d{4})-/i.exec(text || '');
      return m ? parseInt(m[1], 10) >= currentYear - 1 : false;
    };
    document.querySelectorAll('table[data-require-poc], table[data-require-desc]').forEach(table => {
      for (const row of Array.from(table.querySelectorAll('tbody tr'))) {
        const link = row.querySelector('a');
        const idText = (link ? link.textContent : row.textContent || '').trim().toUpperCase();
        const needsPoc = table.hasAttribute('data-require-poc');
        const needsDesc = table.hasAttribute('data-require-desc');
        const hasPoc = pocSet.has(idText);
        const hasDesc = descSet.has(idText);
        if ((needsPoc && !hasPoc) || (needsDesc && !hasDesc) || !isRecent(idText)) {
          row.remove();
        }
      }
    });
  }

  function truncate(text, limit = 160) {
    if (!text) return '';
    return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
  }

  function parseRelativeDays(label) {
    if (!label) return Infinity;
    const lower = label.toLowerCase();
    if (lower.includes('hour') || lower.includes('minute') || lower.includes('just')) return 0;
    const match = lower.match(/(\d+)\s*day/);
    return match ? parseInt(match[1], 10) : Infinity;
  }

  function cveYear(text) {
    const m = /cve-(\d{4})-/i.exec(text || '');
    return m ? parseInt(m[1], 10) : null;
  }

  function parseTrendingMarkdown(text) {
    const rows = [];
    const regex = /^\|\s*(\d+)\s*⭐\s*\|\s*([^|]+)\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|\s*(.*?)\|$/;
    text.split('\n').forEach(line => {
      const trimmed = line.trim();
      const m = regex.exec(trimmed);
      if (!m) return;
      const stars = parseInt(m[1], 10);
      const updated = m[2].trim();
      const name = m[3].trim();
      const url = m[4].trim();
      const desc = m[5].trim();
      const ageDays = parseRelativeDays(updated);
      rows.push({ stars, updated, name, url, desc, ageDays });
    });
    return rows;
  }

  async function renderTrending() {
    const container = document.querySelector('[data-trending]');
    const tbody = document.getElementById('trending-body');
    if (!container || !tbody) return;

    try {
      const res = await fetch('/README.md', { cache: 'no-store' });
      if (!res.ok) throw new Error('failed to load README');
      const text = await res.text();
      const entries = parseTrendingMarkdown(text)
        .filter(item => item.ageDays <= 4)
        .filter(item => {
          const currentYear = new Date().getUTCFullYear();
          const yr = cveYear(item.name);
          return yr !== null && yr >= currentYear - 1;
        })
        .sort((a, b) => b.stars - a.stars)
        .slice(0, 20);

      if (entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="muted">No recent PoCs with stars yet.</td></tr>';
        return;
      }

      tbody.innerHTML = entries.map(item => {
        return `<tr>
          <td>${item.stars}⭐</td>
          <td>${item.updated}</td>
          <td><a href="${item.url}" target="_blank" rel="noreferrer">${item.name}</a></td>
          <td class="mono">${truncate(item.desc)}</td>
        </tr>`;
      }).join('');
    } catch (err) {
      console.warn('Trending render failed', err);
      tbody.innerHTML = '<tr><td colspan="4" class="muted">Unable to load trending PoCs.</td></tr>';
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    bindColumnFilters();
    filterTablesByData();
    renderTrending();
  });
})();
