(function () {
  function bindColumnFilters() {
    const filterInputs = document.querySelectorAll("[data-filter-table]");
    filterInputs.forEach((input) => {
      const table = document.getElementById(input.dataset.filterTable);
      if (!table) return;
      input.addEventListener("input", () => {
        const term = input.value.trim().toLowerCase();
        for (const row of table.querySelectorAll("tbody tr")) {
          const text = row.innerText.toLowerCase();
          row.style.display = text.includes(term) ? "" : "none";
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindColumnFilters();
  });
})();
