var searchResultFormat = '<tr><td class="cveNum"><b>$cve</b></td><td align="left">$description<hr>$poc</td></tr>';
var totalLimit = 500;
var replaceStrings = ['HackTheBox - ', 'VulnHub - ', 'UHC - '];
const results = document.querySelector('div.results');
const searchValue = document.querySelector('input.search');
const form = document.querySelector('form.searchForm');
const resultsTableHideable = document.querySelector('.results-table');
const resultsTable = document.querySelector('tbody.results');
const noResults = document.querySelector('div.noResults');
const colorUpdate = document.body;

function escapeHTML(str) {
    return str.replace(/[&<>"']/g, function (match) {
        const escapeChars = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return escapeChars[match];
    });
}

function convertLinksToList(content) {
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = content;

    const links = tempDiv.querySelectorAll('a');
    if (links.length === 0) {
        return content;
    }

    const list = document.createElement('ul');
    links.forEach(link => {
        const listItem = document.createElement('li');
        listItem.appendChild(link.cloneNode(true));
        list.appendChild(listItem);
    });

    // Remove all original links from the tempDiv
    links.forEach(link => link.parentNode.removeChild(link));

    // Append the newly created list to tempDiv
    tempDiv.appendChild(list);

    return tempDiv.innerHTML;
}

function convertToList(content) {
    // Create a temporary div to manipulate the content
    const tempDiv = document.createElement('div');
    // Remove all <br> tags
    content = content.replace(/<br\s*\/?>/gi, '');
    tempDiv.innerHTML = content;

    const list = document.createElement('ul');
    Array.from(tempDiv.childNodes).forEach(node => {
        const listItem = document.createElement('li');
        if (node.nodeType === Node.TEXT_NODE) {
            listItem.textContent = node.textContent.trim();
        } else if (node.nodeType === Node.ELEMENT_NODE && node.tagName === 'A') {
            listItem.appendChild(node.cloneNode(true));
        }
        list.appendChild(listItem);
    });

    return list.outerHTML;
}


var controls = {
    oldColor: '',
    displayResults: function() {
        results.style.display = '';
        resultsTableHideable.classList.remove('hide');
    },
    hideResults: function() {
        results.style.display = 'none';
        resultsTableHideable.classList.add('hide');
    },
    doSearch: function(match, dataset) {
        let results = [];
        let words = match.toLowerCase().split(' ');
        let posmatch = words.filter(word => word[0] !== '-');
        let negmatch = words.filter(word => word[0] === '-').map(word => word.substring(1));

        dataset.forEach(e => {
            let description = replaceStrings.reduce((desc, str) => desc.replace(str, ''), e.description).toLowerCase();
            let combinedText = (e.cve + e.poc + description).toLowerCase();

            let positiveMatch = posmatch.every(word => combinedText.includes(word));
            let negativeMatch = negmatch.some(word => combinedText.includes(word));

            if (positiveMatch && !negativeMatch) {
                results.push(e);
            }
        });

        return results;
    },
    updateResults: function(loc, results) {
        if (results.length == 0) {
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

            let fragment = document.createDocumentFragment();
            results.forEach(r => {
                let el = searchResultFormat
                    .replace('$cve', r.cve)
                    .replace('$description', escapeHTML(r.description) )
                    //.replace('$poc', convertLinksToList(r.poc));
                    .replace('$poc', convertToList(r.poc));
                let wrapper = document.createElement('table');
                wrapper.innerHTML = el;
                fragment.appendChild(wrapper.querySelector('tr'));
            });
            loc.appendChild(fragment);
        }
    },
    setColor: function(loc, indicator) {
        if (this.oldColor == indicator) return;
        loc.className = loc.className.replace(/\bcolor-\S+/g, '');
        loc.classList.add('color-' + indicator);
        this.oldColor = indicator;
    }
};

window.controls = controls;

document.addEventListener('DOMContentLoaded', function() {

    document.body.classList.add('fade');

    var currentSet = [];
    var debounceTimer;

    function doSearch(event) {
        var val = searchValue.value.trim();

        if (val !== '') {
            controls.displayResults();
            currentSet = window.dataset;
            currentSet = window.controls.doSearch(val, currentSet);

            if (currentSet.length < totalLimit) {
                window.controls.setColor(colorUpdate, currentSet.length == 0 ? 'no-results' : 'results-found');
            }

            window.controls.updateResults(resultsTable, currentSet);
        } else {
            controls.hideResults();
            window.controls.setColor(colorUpdate, 'no-search');
            noResults.style.display = 'none';
        }

        if (event.type == 'submit') {
            event.preventDefault();
        }
    }

    fetch('./pocs.json')
        .then(res => res.json())
        .then(data => {
            window.dataset = data;
            currentSet = window.dataset;
            window.controls.updateResults(resultsTable, window.dataset);
            doSearch({ type: 'none' });
        });

    form.addEventListener('submit', doSearch);

    searchValue.addEventListener('input', function(event) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => doSearch(event), 300);
    });
});
