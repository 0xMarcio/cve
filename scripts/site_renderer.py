from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from utils import DOCS_DIR, TEMPLATES_DIR, ensure_dirs


def build_env() -> Environment:
    loader = FileSystemLoader(str(TEMPLATES_DIR))
    env = Environment(loader=loader, autoescape=select_autoescape(["html", "xml"]))
    env.trim_blocks = True
    env.lstrip_blocks = True
    return env


class SiteRenderer:
    def __init__(
        self,
        *,
        results: List[Dict],
        index_payload: Dict,
        top_payload: Dict,
        diff_payload: Dict | None = None,
    ) -> None:
        self.results = []
        for result in results:
            visible = [p for p in result.get("pocs", []) if p.get("confidence_tier") in {"high", "medium"}]
            if not visible:
                visible = result.get("pocs", [])
            self.results.append({**result, "visible_pocs": visible})
        self.index_payload = index_payload
        self.top_payload = top_payload
        self.diff_payload = diff_payload or {}
        self.env = build_env()
        ensure_dirs(
            DOCS_DIR,
            DOCS_DIR / "pocs",
            DOCS_DIR / "cve",
            DOCS_DIR / "diffs",
            DOCS_DIR / "assets",
        )

    def render(self, template_name: str, context: Dict, target: Path) -> None:
        html = self.env.get_template(template_name).render(**context)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(html, encoding="utf-8")

    def build(self) -> None:
        generated = self.index_payload.get("generated")
        summary = {
            "generated": generated,
            "total_cves": len(self.index_payload.get("items", [])),
            "total_pocs": sum(item.get("poc_count", 0) for item in self.index_payload.get("items", [])),
            "high_total": sum(item.get("high_confidence", 0) for item in self.index_payload.get("items", [])),
            "medium_total": sum(item.get("medium_confidence", 0) for item in self.index_payload.get("items", [])),
        }
        self.render(
            "pipeline_index.html",
            {
                "summary": summary,
                "top": self.top_payload.get("items", [])[:25],
                "diff": self.diff_payload or {},
            },
            DOCS_DIR / "index.html",
        )

        self.render(
            "pipeline_pocs.html",
            {
                "generated": generated,
                "index": self.index_payload.get("items", []),
                "top": self.top_payload.get("items", [])[:100],
            },
            DOCS_DIR / "pocs" / "index.html",
        )

        for result in self.results:
            self.render(
                "pipeline_cve.html",
                {"cve": result, "generated": generated},
                DOCS_DIR / "cve" / f"{result['cve_id']}.html",
            )

        if self.diff_payload:
            diff_date = self.diff_payload.get("generated")
            self.render(
                "pipeline_diff.html",
                {"diff": self.diff_payload, "generated": generated},
                DOCS_DIR / "diffs" / "index.html",
            )
            if diff_date:
                self.render(
                    "pipeline_diff.html",
                    {"diff": self.diff_payload, "generated": generated},
                    DOCS_DIR / "diffs" / f"{diff_date}.html",
                )
