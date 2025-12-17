(function () {
  function cardTemplate(item) {
    return `
      <article class="card">
        <div class="card-title"><a href="/cve/?id=${item.cve}">${item.cve}</a></div>
        <div class="card-meta">EPSS ${item.epss !== null && item.epss !== undefined ? item.epss.toFixed(3) : "0.000"} • ${item.percentile !== null && item.percentile !== undefined ? Math.round(item.percentile * 100) + "th pct" : ""}</div>
        <p>${item.summary || "No description."}</p>
        ${item.vendor ? `<div class="badge">${item.vendor}</div>` : ""}
        ${item.product ? `<div class="badge">${item.product}</div>` : ""}
      </article>
    `;
  }

  function renderCards(gridId, items) {
    const el = document.getElementById(gridId);
    if (!el) return;
    if (!items || items.length === 0) {
      el.innerHTML = '<p class="muted">No data available.</p>';
      return;
    }
    el.innerHTML = items.map(cardTemplate).join("");
  }

  function renderDiffTable(diff) {
    const tbody = document.getElementById("diff-table-body");
    if (!tbody) return;
    const kevCount = (diff.new_kev_entries || []).length;
    const kevExamples = (diff.new_kev_entries || []).slice(0, 5).map((row) => `<a href="/cve/?id=${row.cve}">${row.cve}</a>`).join(", ") || "None";

    const epssCount = (diff.new_high_epss || []).length;
    const epssExamples = (diff.new_high_epss || []).slice(0, 5).map((row) => `<a href="/cve/?id=${row.cve}">${row.cve}</a>`).join(", ") || "None";

    const moverCount = (diff.epss_movers || []).length;
    const moverExamples = (diff.epss_movers || []).slice(0, 5).map((row) => `<a href="/cve/?id=${row.cve}">${row.cve}</a> (${row.delta.toFixed(3)})`).join(", ") || "None";

    tbody.innerHTML = `
      <tr>
        <td>New KEV entries</td>
        <td>${kevCount}</td>
        <td>${kevExamples}</td>
      </tr>
      <tr>
        <td>New high EPSS</td>
        <td>${epssCount}</td>
        <td>${epssExamples}</td>
      </tr>
      <tr>
        <td>Top EPSS movers</td>
        <td>${moverCount}</td>
        <td>${moverExamples}</td>
      </tr>
    `;
  }

  async function loadHome() {
    try {
      const res = await fetch("/api/v1/joined_top.json", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        renderCards("kev-grid", (data.kev_top || []).slice(0, 15));
        renderCards("epss-grid", (data.high_epss || []).slice(0, 15));
      }
    } catch (err) {
      console.warn("Failed to load joined_top.json", err);
    }

    try {
      const res = await fetch("/api/v1/diff/latest.json", { cache: "no-store" });
      if (res.ok) {
        const diff = await res.json();
        renderDiffTable(diff);
      }
    } catch (err) {
      console.warn("Failed to load diff", err);
    }
  }

  document.addEventListener("DOMContentLoaded", loadHome);
})();
