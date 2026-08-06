#!/usr/bin/env python3
"""
build_dashboard.py
Takes tickets_enriched.json (produced by llm_enrich.py) and injects it into
dashboard_template.html, producing the final dashboard.html you open in a
browser.

Usage:
    python3 build_dashboard.py
Reads: ./tickets_enriched.json, ./dashboard_template.html
Writes: ./dashboard.html
"""

import json

with open("tickets_enriched.json") as f:
    tickets = json.load(f)

with open("dashboard_template.html") as f:
    html = f.read()

tickets_compact = json.dumps(tickets, separators=(",", ":"))
html = html.replace("__TICKETS_JSON__", tickets_compact)

with open("dashboard.html", "w") as f:
    f.write(html)

print(f"Wrote dashboard.html with {len(tickets)} tickets -- open it in your browser")
