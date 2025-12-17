const searchResultFormat = '<tr><td class="cveNum">$cve</td><td class="desc">$description $poc</td></tr>';
const totalLimit = 10000;
const replaceStrings = ['HackTheBox - ', 'VulnHub - ', 'UHC - '];
const colorUpdate = document.body;

function getSearchRoot() {
    return document.querySelector('[data-search-root]');
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
    return `<a href="/cve/?id=${cveId}"><b>${cveId}</b></a>`;
}

function prepareDataset(raw) {
    if (!Array.isArray(raw)) return [];
    const currentYear = new Date().getUTCFullYear();
    const isRecent = (cve) => {
        const match = /^CVE-(\d{4})-/i.exec(cve || '');
        if (!match) return false;
        const year = parseInt(match[1], 10);
        return year >= currentYear - 1;
    };
    const descKeyCleaned = (entry) => {
        const base = entry.desc || '';
        return replaceStrings.reduce((desc, str) => desc.replace(str, ''), base);
    };
    return raw
      .filter(entry => {
        const desc = (entry.desc || '').trim();
        return desc && Array.isArray(entry.poc) && entry.poc.length > 0 && isRecent(entry.cve || '');
      })
      .map(entry => {
        const descCleaned = descKeyCleaned(entry);
        const searchText = `${entry.cve || ''} ${descCleaned}`.toLowerCase();
        return { ...entry, _searchText: searchText };
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
        const words = match.toLowerCase().split(' ').filter(Boolean);
        const posmatch = words.filter(word => word[0] !== '-');
        const negmatch = words.filter(word => word[0] === '-').map(word => word.substring(1));

        return dataset.filter(e => {
            const combinedText = e._searchText || '';

            const positiveMatch = posmatch.every(word => combinedText.includes(word));
            const negativeMatch = negmatch.some(word => combinedText.includes(word));

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

    function doSearch(event) {
        const val = searchValue.value.trim();

        if (val !== '') {
            controls.displayResults(results, resultsTableHideable);
            currentSet = window.controls.doSearch(val, window.dataset || []);

            if (currentSet.length < totalLimit) {
                window.controls.setColor(colorUpdate, currentSet.length === 0 ? 'no-results' : 'results-found');
            }

            window.controls.updateResults(resultsTable, currentSet, noResults, resultsTableHideable);
        } else {
            controls.hideResults(results, resultsTableHideable);
            window.controls.setColor(colorUpdate, 'no-search');
            noResults.style.display = 'none';
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
});
