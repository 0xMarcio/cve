const searchResultFormat = '<tr><td class="cveNum">$cve</td><td align="left">$description $poc</td></tr>';
const totalLimit = 10000;
const replaceStrings = ['HackTheBox - ', 'VulnHub - ', 'UHC - '];
const results = document.querySelector('div.results');
const searchValue = document.querySelector('input.search');
const form = document.querySelector('form.searchForm');
const resultsTableHideable = document.querySelector('.results-table');
const resultsTable = document.querySelector('tbody.results');
const noResults = document.querySelector('div.noResults');
const colorUpdate = document.body;

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
    let htmlOutput = `<hr><div class="poc-container"><ul>`;
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



function getCveLink(cveId) {
    return `<a target="_blank" href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}"><b>${cveId}</b></a>`;
}

const controls = {
    oldColor: '',
    displayResults() {
        results.style.display = '';
        resultsTableHideable.classList.remove('hide');
    },
    hideResults() {
        results.style.display = 'none';
        resultsTableHideable.classList.add('hide');
    },
    doSearch(match, dataset) {
        const words = match.toLowerCase().split(' ');
        const posmatch = words.filter(word => word[0] !== '-');
        const negmatch = words.filter(word => word[0] === '-').map(word => word.substring(1));

        return dataset.filter(e => {
            const description = replaceStrings.reduce((desc, str) => desc.replace(str, ''), e.desc).toLowerCase();
            const combinedText = (e.cve + description).toLowerCase();

            const positiveMatch = posmatch.every(word => combinedText.includes(word));
            const negativeMatch = negmatch.some(word => combinedText.includes(word));

            return positiveMatch && !negativeMatch;
        });
    },
    updateResults(loc, results) {
        if (results.length === 0) {
            noResults.style.display = '';
            noResults.textContent = 'No Results Found';
            resultsTableHideable.classList.add('hide');
        } else if (results.length > totalLimit) {
            noResults.style.display = '';
            resultsTableHideable.classList.add('hide');
            noResults.textContent = 'Error: ' + results.length + ' results were found, try being more specific';
            this.setColor(colorUpdate, 'too-many-results');
        } else {
            loc.innerHTML = ''; // Clear existing rows

            noResults.style.display = 'none';
            resultsTableHideable.classList.remove('hide');

            const fragment = document.createDocumentFragment();
            results.forEach(r => {
                const el = searchResultFormat
                    .replace('$cve', getCveLink(r.cve))
                    .replace('$description', escapeHTML(r.desc))
                    .replace('$poc', convertLinksToList(r.poc));
                const wrapper = document.createElement('table');
                wrapper.innerHTML = el;
                fragment.appendChild(wrapper.querySelector('tr'));
            });
            loc.appendChild(fragment);
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
    document.body.classList.add('fade');

    let currentSet = [];
    let debounceTimer;

    function doSearch(event) {
        const val = searchValue.value.trim();

        if (val !== '') {
            controls.displayResults();
            currentSet = window.controls.doSearch(val, window.dataset);

            if (currentSet.length < totalLimit) {
                window.controls.setColor(colorUpdate, currentSet.length === 0 ? 'no-results' : 'results-found');
            }

            window.controls.updateResults(resultsTable, currentSet);
        } else {
            controls.hideResults();
            window.controls.setColor(colorUpdate, 'no-search');
            noResults.style.display = 'none';
        }

        if (event.type === 'submit') {
            event.preventDefault();
        }
    }

    fetch('./CVE_list.json')
        .then(res => res.json())
        .then(data => {
            window.dataset = data;
            currentSet = window.dataset;
            window.controls.updateResults(resultsTable, window.dataset);
            doSearch({ type: 'none' });
        });

    form.addEventListener('submit', doSearch);

    searchValue.addEventListener('input', event => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => doSearch(event), 300);
    });
});
