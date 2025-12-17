(function () {
  const params = new URLSearchParams(window.location.search);
  const rawId = params.get("id") || params.get("cve");
  const cveId = rawId ? rawId.toUpperCase() : null;

  const titleEl = document.getElementById("cve-title");
  const summaryEl = document.getElementById("cve-summary");
  const metaEl = document.getElementById("cve-meta");
  const factsEl = document.getElementById("cve-facts");
  const pocRowsEl = document.getElementById("cve-poc-rows");
  const kevRowsEl = document.getElementById("kev-rows");

  const detailSection = document.getElementById("cve-details");
  const notFoundSection = document.getElementById("not-found");

  function setLoading(message) {
    titleEl.textContent = cveId || "CVE details";
    summaryEl.textContent = message;
  }

  function getDescriptionText(data) {
    const desc = (data?.description || "").trim();
    if (desc) return desc;
    const kevDesc = (data?.kev?.short_description || "").trim();
    if (kevDesc) return kevDesc;
    return "No description available.";
  }

  function hasKevData(kev) {
    if (!kev || typeof kev !== "object") return false;
    return Boolean(
      (kev.short_description && kev.short_description.trim()) ||
      kev.date_added ||
      kev.due_date ||
      kev.required_action ||
      kev.notes
    );
  }

  function renderFacts(data) {
    const pocCount = data.poc_count ?? (Array.isArray(data.poc_links) ? data.poc_links.length : Array.isArray(data.poc) ? data.poc.length : undefined);
    const items = [];
    const vendorValue = data.vendor || "Unknown vendor";
    const productValue = data.product || "Unknown product";
    const epssValue = typeof data.epss === "number" ? data.epss.toFixed(3) : "n/a";
    const percentileValue = typeof data.percentile === "number" ? `${Math.round(data.percentile * 100)}th` : "n/a";
    const pocValue = pocCount ?? 0;

    items.push({ label: "Vendor", value: vendorValue });
    items.push({ label: "Product", value: productValue });
    items.push({ label: "EPSS", value: epssValue });
    items.push({ label: "Percentile", value: percentileValue });
    items.push({ label: "PoCs", value: pocValue });
    if (hasKevData(data.kev)) items.push({ label: "KEV status", value: data.kev.date_added ? `Added ${data.kev.date_added}` : "Listed" });

    if (items.length === 0) {
      factsEl.innerHTML = `<div class="stat"><strong>—</strong><span>No overview data yet.</span></div>`;
      return;
    }

    factsEl.innerHTML = items
      .map((item) => `<div class="stat"><strong>${item.value}</strong><span>${item.label}</span></div>`)
      .join("");
  }

  function renderPocs(links) {
    pocRowsEl.innerHTML = "";
    if (!links || links.length === 0) {
      pocRowsEl.innerHTML = '<tr><td class="muted">No PoC links available.</td></tr>';
      return;
    }
    pocRowsEl.innerHTML = links
      .map((link) => `<tr><td><a href="${link}" target="_blank" rel="noreferrer">${link}</a></td></tr>`)
      .join("");
  }

  function renderMeta(data) {
    const pills = [];
    if (data.vendor) pills.push(`Vendor: ${data.vendor}`);
    if (data.product) pills.push(`Product: ${data.product}`);
    if (hasKevData(data.kev)) pills.push("On KEV list");

    metaEl.innerHTML = pills.map((text) => `<span class="pill">${text}</span>`).join("");
  }

  function renderKev(kev) {
    if (!hasKevData(kev)) {
      document.getElementById("kev-section").style.display = "none";
      return;
    }
    const rows = [];
    if (kev.short_description) rows.push(["Summary", kev.short_description]);
    if (kev.date_added) rows.push(["Date added", kev.date_added]);
    if (kev.due_date) rows.push(["Due", kev.due_date]);
    if (kev.required_action) rows.push(["Required action", kev.required_action]);
    if (kev.notes) rows.push(["Notes", kev.notes]);
    kevRowsEl.innerHTML = rows.map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`).join("");
    document.getElementById("kev-section").style.display = "";
  }

  async function fetchCveFromApi(id) {
    const res = await fetch(`/api/v1/cve/${id}.json`, { cache: "no-store" });
    if (!res.ok) throw new Error("notfound");
    return res.json();
  }

  async function fetchFromList(id) {
    const res = await fetch("/CVE_list.json", { cache: "no-store" });
    if (!res.ok) throw new Error("fallback-missing");
    const data = await res.json();
    const match = (data || []).find((row) => (row.cve || "").toUpperCase() === id);
    if (!match) throw new Error("fallback-notfound");
    return {
      cve: id,
      description: match.desc,
      poc_links: match.poc || [],
      poc_count: (match.poc || []).length,
    };
  }

  async function load() {
    if (!cveId) {
      setLoading("Provide ?id=CVE-YYYY-#### in the URL to view details.");
      notFoundSection.style.display = "";
      return;
    }

    setLoading("Loading CVE details…");
    try {
      const data = await fetchCveFromApi(cveId);
      titleEl.textContent = data.cve || cveId;
      const desc = getDescriptionText(data);
      summaryEl.textContent = desc;
      renderFacts(data);
      renderPocs(data.poc_links || data.poc || []);
      renderKev(data.kev);
      renderMeta(data);
      detailSection.style.display = "";
      notFoundSection.style.display = "none";
      return;
    } catch (err) {
      console.warn("API lookup failed, trying CVE_list.json", err);
    }

    try {
      const fallback = await fetchFromList(cveId);
      titleEl.textContent = fallback.cve;
      const desc = getDescriptionText(fallback);
      summaryEl.textContent = desc;
      renderFacts(fallback);
      renderPocs(fallback.poc_links || fallback.poc || []);
      renderKev(null);
      renderMeta(fallback);
      detailSection.style.display = "";
      notFoundSection.style.display = "none";
    } catch (err) {
      console.warn("CVE_list lookup failed", err);
      notFoundSection.style.display = "";
      detailSection.style.display = "none";
      metaEl.innerHTML = "";
      titleEl.textContent = cveId;
      summaryEl.textContent = "No data found for this CVE.";
    }
  }

  document.addEventListener("DOMContentLoaded", load);
})();
