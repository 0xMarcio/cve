(function(){
  let datasetPromise = null;
  let pocSet = null;

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

  async function ensurePocSet() {
    if (pocSet) return pocSet;
    const dataset = await fetchDataset();
    pocSet = new Set(
      dataset
        .filter(item => Array.isArray(item.poc) && item.poc.length > 0)
        .map(item => (item.cve || '').toUpperCase())
    );
    return pocSet;
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

  async function filterTablesByPoc() {
    const set = await ensurePocSet();
    document.querySelectorAll('table[data-require-poc]').forEach(table => {
      for (const row of Array.from(table.querySelectorAll('tbody tr'))) {
        const link = row.querySelector('a');
        const idText = (link ? link.textContent : row.textContent || '').trim().toUpperCase();
        if (!set.has(idText)) {
          row.remove();
        }
      }
    });
  }

  function truncate(text, limit = 140) {
    if (!text) return '';
    return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
  }

  async function renderTrending() {
    const container = document.querySelector('[data-trending]');
    const tbody = document.getElementById('trending-body');
    if (!container || !tbody) return;

    const data = await fetchDataset();
    const trending = data
      .filter(item => item && item.cve && Array.isArray(item.poc) && item.poc.length > 0)
      .map(item => ({ cve: item.cve, desc: item.desc || 'No description available.', poc: item.poc }))
      .sort((a, b) => {
        const delta = (b.poc?.length || 0) - (a.poc?.length || 0);
        if (delta !== 0) return delta;
        return (b.cve || '').localeCompare(a.cve || '');
      })
      .slice(0, 12);

    if (trending.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" class="muted">No PoCs found yet.</td></tr>';
      return;
    }

    tbody.innerHTML = trending.map(item => {
      const pocCount = item.poc ? item.poc.length : 0;
      const safeDesc = truncate(item.desc, 160);
      return `<tr>
        <td class="cve-cell"><a href="/cve/?id=${item.cve}">${item.cve}</a></td>
        <td>${pocCount}</td>
        <td>${safeDesc}</td>
      </tr>`;
    }).join('');
  }

  document.addEventListener('DOMContentLoaded', () => {
    bindColumnFilters();
    filterTablesByPoc();
    renderTrending();
  });
})();
