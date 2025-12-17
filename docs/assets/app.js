(function() {
  const qs = (sel) => document.querySelector(sel);

  const initIndexSearch = () => {
    const input = document.querySelector("[data-index-search]");
    if (!input) return;
    const targetSel = input.getAttribute("data-target");
    const target = targetSel ? qs(targetSel) : null;
    const indexUrl = input.getAttribute("data-index-url");
    if (!target || !indexUrl) return;

    let cached = [];
    fetch(indexUrl)
      .then((resp) => resp.json())
      .then((data) => { cached = data.items || []; })
      .catch(() => { target.innerHTML = "<p class='muted small'>Index unavailable.</p>"; });

    const render = (term) => {
      if (!cached.length) return;
      const value = term.trim().toLowerCase();
      const results = cached.filter((row) => {
        if (!value) return false;
        return row.cve_id.toLowerCase().includes(value) ||
          (row.top_languages || []).join(" ").toLowerCase().includes(value) ||
          String(row.max_score || "").includes(value);
      }).slice(0, 40);

      if (!results.length) {
        target.innerHTML = "<p class='muted small'>No matches yet.</p>";
        return;
      }

      target.innerHTML = results.map((row) => {
        const langs = (row.top_languages || []).map((lang) => `<span class="pill tiny">${lang}</span>`).join(" ");
        return `<article class="card">
            <div class="card-title"><a href="/cve/${row.cve_id}.html">${row.cve_id}</a></div>
            <div class="meta-row">
              <span class="pill tier-high">${row.high_confidence} high</span>
              <span class="pill tier-medium">${row.medium_confidence} med</span>
              <span class="pill">${row.poc_count} PoCs</span>
            </div>
            <div class="muted small">Max score ${row.max_score || 0}</div>
            <div class="pill-row">${langs}</div>
          </article>`;
      }).join("");
    };

    input.addEventListener("input", (e) => render(e.target.value));
  };

  document.addEventListener("DOMContentLoaded", () => {
    initIndexSearch();
  });
})();
