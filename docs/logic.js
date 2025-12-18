const searchResultFormat = '<tr><td class="cveNum">$cve</td><td class="desc">$description $poc</td></tr>';
const totalLimit = 10000;
const replaceStrings = ['HackTheBox - ', 'VulnHub - ', 'UHC - '];
const colorUpdate = document.body;

function getSearchRoot() {
    return document.querySelector('[data-search-root]');
}

function getTrendingSection() {
    return document.querySelector('[data-trending-section]');
}

function getTrendingBody() {
    return document.getElementById('trending-body');
}

function escapeHTML(str) {
    return str.replace(/[&<>"']/g, match => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[match]));
}

function normalizeSearchTerm(value) {
    return value.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function convertLinksToList(links) {
    if (links.length === 0) {
        return '';
    }
    let htmlOutput = `<div class="poc-container"><ul>`;
    const displayLimit = 5;
    links.slice(0, displayLimit).forEach(link => {
        htmlOutput += `<li><a target="_blank" href="${link}">${link}</a></li>`;
    });
    htmlOutput += `</ul>`;
    if (links.length > displayLimit) {
        htmlOutput += `
            <ul class="dropdown" style="display:none;">
                ${links.slice(displayLimit).map(link => `<li><a target="_blank" href="${link}">${link}</a></li>`).join('')}
            </ul>
            <button class="dropdown-btn" onclick="toggleDropdown(this)">Show More</button>`;
    }
    htmlOutput += `</div>`;
    return htmlOutput;
}

function toggleDropdown(button) {
    const dropdown = button.previousElementSibling;
    if (dropdown.style.display === "none") {
        dropdown.style.display = "block";
        button.textContent = "Show Less";
    } else {
        dropdown.style.display = "none";
        button.textContent = "Show More";
    }
}
window.toggleDropdown = toggleDropdown;

function getCveLink(cveId) {
    return `<a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank"><b>${cveId}</b></a>`;
}

function prepareDataset(raw) {
    if (!Array.isArray(raw)) return [];
    const descKeyCleaned = (entry) => {
        const base = entry.desc || '';
        return replaceStrings.reduce((desc, str) => desc.replace(str, ''), base);
    };
    return raw
      .filter(entry => {
        const cve = (entry.cve || '').trim();
        return cve && Array.isArray(entry.poc) && entry.poc.length > 0;
      })
      .map(entry => {
        const descCleaned = descKeyCleaned(entry);
        const pocText = (entry.poc || []).join(' ');
        const searchText = `${entry.cve || ''} ${descCleaned} ${pocText}`.toLowerCase();
        const searchTextNormalized = normalizeSearchTerm(searchText);
        return { ...entry, _searchText: searchText, _searchTextNormalized: searchTextNormalized };
      });
}

const controls = {
    oldColor: '',
    displayResults(results, resultsTableHideable) {
        results.style.display = '';
        resultsTableHideable.classList.remove('hide');
    },
    hideResults(results, resultsTableHideable) {
        results.style.display = 'none';
        resultsTableHideable.classList.add('hide');
    },
    doSearch(match, dataset) {
        const terms = match.match(/-?"[^"]+"|-?\S+/g) || [];
        const cleaned = terms.map(term => term.replace(/^(-?)"/, '$1').replace(/"$/, ''));
        const posmatch = cleaned.filter(term => term && term[0] !== '-');
        const negmatch = cleaned
            .filter(term => term && term[0] === '-')
            .map(term => term.substring(1))
            .filter(Boolean);

        return dataset.filter(e => {
            const combinedText = e._searchText || '';
            const combinedNormalized = e._searchTextNormalized || '';

            const positiveMatch = posmatch.every(word => {
                const raw = word.toLowerCase();
                if (combinedText.includes(raw)) return true;
                const normalized = normalizeSearchTerm(raw);
                return normalized ? combinedNormalized.includes(normalized) : false;
            });
            const negativeMatch = negmatch.some(word => {
                const raw = word.toLowerCase();
                if (combinedText.includes(raw)) return true;
                const normalized = normalizeSearchTerm(raw);
                return normalized ? combinedNormalized.includes(normalized) : false;
            });

            return positiveMatch && !negativeMatch;
        });
    },
    updateResults(loc, results, noResults, resultsTableHideable) {
        if (results.length === 0) {
            noResults.style.display = '';
            noResults.textContent = 'No results found — try another vendor, product, or CVE id.';
            resultsTableHideable.classList.add('hide');
        } else if (results.length > totalLimit) {
            noResults.style.display = '';
            resultsTableHideable.classList.add('hide');
            noResults.textContent = 'Error: ' + results.length + ' results were found, try being more specific';
            this.setColor(colorUpdate, 'too-many-results');
        } else {
            loc.innerHTML = '';

            noResults.style.display = 'none';
            resultsTableHideable.classList.remove('hide');

            const html = results.map(r => {
                const desc = r.desc || '';
                return searchResultFormat
                    .replace('$cve', getCveLink(r.cve))
                    .replace('$description', escapeHTML(desc))
                    .replace('$poc', convertLinksToList(r.poc || []));
            }).join('');
            loc.innerHTML = html;
        }
    },
    setColor(loc, indicator) {
        if (this.oldColor === indicator) return;
        loc.className = loc.className.replace(/\bcolor-\S+/g, '');
        loc.classList.add('color-' + indicator);
        this.oldColor = indicator;
    }
};

window.controls = controls;

document.addEventListener('DOMContentLoaded', () => {
    const root = getSearchRoot();
    const trendingSection = getTrendingSection();
    const trendingBody = getTrendingBody();
    if (!root) return;

    const results = root.querySelector('[data-results]');
    const searchValue = root.querySelector('input.search');
    const form = root.querySelector('form.searchForm');
    const resultsTableHideable = root.querySelector('.results-table');
    const resultsTable = root.querySelector('tbody.results');
    const noResults = root.querySelector('div.noResults');

    document.body.classList.add('fade');

    if (!results || !searchValue || !form || !resultsTableHideable || !resultsTable || !noResults) {
        console.warn('Search container missing expected elements');
        return;
    }

    let currentSet = [];
    let debounceTimer;

    function renderTrending(items) {
        if (!trendingBody) return;
        if (!items || items.length === 0) {
            trendingBody.innerHTML = '<tr><td colspan="4">No recent PoCs.</td></tr>';
            return;
        }
        const rows = items.slice(0, 20).map(item => {
            const stars = item.stars ?? '';
            const updated = escapeHTML(item.updated || '');
            const name = escapeHTML(item.name || '');
            const url = item.url || '#';
            const desc = escapeHTML(item.desc || '');
            return `<tr><td>${stars}</td><td>${updated}</td><td><a href="${url}" target="_blank">${name}</a></td><td class="mono">${desc}</td></tr>`;
        }).join('');
        trendingBody.innerHTML = rows;
    }

    async function loadTrending() {
        if (!trendingBody) return;
        try {
            const res = await fetch('/trending_poc.json', { cache: 'no-store' });
            if (!res.ok) {
                throw new Error(`Failed to load trending (${res.status})`);
            }
            const data = await res.json();
            const items = Array.isArray(data) ? data : (data.items || []);
            renderTrending(items);
        } catch (err) {
            console.warn(err.message);
        }
    }

    function doSearch(event) {
        const val = searchValue.value.trim();

        if (val !== '') {
            controls.displayResults(results, resultsTableHideable);
            if (trendingSection) {
                trendingSection.style.display = 'none';
            }
            currentSet = window.controls.doSearch(val, window.dataset || []);

            if (currentSet.length < totalLimit) {
                window.controls.setColor(colorUpdate, currentSet.length === 0 ? 'no-results' : 'results-found');
            }

            window.controls.updateResults(resultsTable, currentSet, noResults, resultsTableHideable);
        } else {
            controls.hideResults(results, resultsTableHideable);
            window.controls.setColor(colorUpdate, 'no-search');
            noResults.style.display = 'none';
            if (trendingSection) {
                trendingSection.style.display = '';
            }
        }

        if (event.type === 'submit') {
            event.preventDefault();
        }
    }

    const cveListCandidates = [
        new URL('/CVE_list.json', window.location.origin).href,
        new URL('CVE_list.json', window.location.href).href,
        new URL('../CVE_list.json', window.location.href).href
    ];

    (async () => {
        for (const url of cveListCandidates) {
            try {
                const res = await fetch(url, { cache: 'no-store' });
                if (!res.ok) {
                    throw new Error(`Failed to load ${url} (${res.status})`);
                }
                const data = await res.json();
                window.dataset = prepareDataset(data);
                currentSet = window.dataset;
                controls.hideResults(results, resultsTableHideable);
                noResults.style.display = 'none';
                window.controls.setColor(colorUpdate, 'no-search');
                return;
            } catch (err) {
                console.warn(err.message);
            }
        }
        window.dataset = [];
        noResults.textContent = 'Unable to load CVE list';
        noResults.style.display = '';
        controls.setColor(colorUpdate, 'no-results');
    })();

    form.addEventListener('submit', doSearch);

    searchValue.addEventListener('input', event => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => doSearch(event), 200);
    });

    loadTrending();
});
