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

function normalizeToSpaces(value) {
    return value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

function buildLooseRegex(value) {
    const compact = value.toLowerCase().replace(/[^a-z0-9]+/g, '');
    if (compact.length < 4) {
        return null;
    }
    const escaped = compact.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = escaped.split('').join('[^a-z0-9]*');
    return new RegExp(pattern);
}

function buildMatcher(term) {
    const raw = term.toLowerCase().trim();
    if (!raw) return null;
    const isPhrase = /\s/.test(raw);
    const normalized = raw.replace(/[^a-z0-9]+/g, '');
    return {
        raw,
        normalized,
        isPhrase,
        phrase: isPhrase ? normalizeToSpaces(raw) : '',
        loose: !isPhrase && normalized.length >= 4 ? buildLooseRegex(raw) : null
    };
}

function linkItem(link) {
    const safe = escapeHTML(link);
    return `<li><a target="_blank" rel="noopener" href="${safe}">${safe}</a></li>`;
}

function convertLinksToList(links) {
    if (links.length === 0) {
        return '';
    }
    let htmlOutput = `<div class="poc-container"><ul>`;
    const displayLimit = 5;
    links.slice(0, displayLimit).forEach(link => {
        htmlOutput += linkItem(link);
    });
    htmlOutput += `</ul>`;
    if (links.length > displayLimit) {
        htmlOutput += `
            <ul class="dropdown" style="display:none;">
                ${links.slice(displayLimit).map(linkItem).join('')}
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

function descSpace(entry) {
    if (entry._descSpace === undefined) {
        entry._descSpace = normalizeToSpaces(entry._descText);
    }
    return entry._descSpace;
}

function prepareDataset(raw) {
    if (!Array.isArray(raw)) return [];
    const dataset = [];
    for (const entry of raw) {
        const cve = (entry.cve || '').trim();
        if (!cve || !Array.isArray(entry.poc) || entry.poc.length === 0) continue;
        const parts = cve.split('-');
        entry._cveText = cve.toLowerCase();
        entry._descText = replaceStrings
            .reduce((desc, str) => desc.replace(str, ''), entry.desc || '')
            .toLowerCase();
        entry._year = parseInt(parts[1], 10) || 0;
        entry._num = parseInt(parts[2], 10) || 0;
        dataset.push(entry);
    }
    return dataset;
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
    scoreEntry(entry, matcher) {
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
    },
    doSearch(match, dataset) {
        const terms = match.match(/-?"[^"]+"|-?\S+/g) || [];
        const cleaned = terms.map(term => term.replace(/^(-?)"/, '$1').replace(/"$/, ''));
        const positive = cleaned.filter(term => term && term[0] !== '-');
        const posmatch = positive.map(buildMatcher).filter(Boolean);
        // Unquoted words are matched independently, so "active directory" also
        // hits a description holding "active session" and "working directory".
        // Reward the words appearing together to keep those below real matches.
        const adjacent = positive.length > 1 ? positive.join(' ').toLowerCase() : '';
        const negmatch = cleaned
            .filter(term => term && term[0] === '-')
            .map(term => term.substring(1))
            .filter(Boolean)
            .map(buildMatcher)
            .filter(Boolean);

        const results = [];

        for (const entry of dataset) {
            let score = 0;
            let matched = true;

            for (const matcher of posmatch) {
                const termScore = this.scoreEntry(entry, matcher);
                if (termScore === 0) {
                    matched = false;
                    break;
                }
                score += termScore;
            }

            if (!matched) continue;

            const hasNegative = negmatch.some(matcher => this.scoreEntry(entry, matcher) > 0);
            if (hasNegative) continue;

            if (adjacent) {
                const at = wordStart(entry._descText, adjacent);
                if (at >= 0) {
                    score += 300 + leadBonus(at);
                } else if (wordStart(pocText(entry), adjacent) >= 0) {
                    score += 100;
                }
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

            const html = results.map(r =>
                '<tr><td class="cveNum">' + getCveLink(r.cve) +
                '</td><td class="desc">' + escapeHTML(r.desc || '') + ' ' +
                convertLinksToList(r.poc || []) + '</td></tr>'
            ).join('');
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

    let datasetReady = false;
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
            return `<tr><td>${stars}⭐</td><td>${updated}</td><td><a href="${url}" target="_blank">${name}</a></td><td class="mono">${desc}</td></tr>`;
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
            // Typing before the CVE list lands would otherwise report no results.
            if (!datasetReady) {
                resultsTableHideable.classList.add('hide');
                noResults.style.display = '';
                noResults.textContent = 'Loading CVE data…';
                if (event && event.type === 'submit') {
                    event.preventDefault();
                }
                return;
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

        if (event && event.type === 'submit') {
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
                const res = await fetch(url);
                if (!res.ok) {
                    throw new Error(`Failed to load ${url} (${res.status})`);
                }
                const data = await res.json();
                window.dataset = prepareDataset(data);
                currentSet = window.dataset;
                datasetReady = true;
                if (searchValue.value.trim() !== '') {
                    doSearch();
                } else {
                    controls.hideResults(results, resultsTableHideable);
                    noResults.style.display = 'none';
                    window.controls.setColor(colorUpdate, 'no-search');
                }
                return;
            } catch (err) {
                console.warn(err.message);
            }
        }
        window.dataset = [];
        datasetReady = true;
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
