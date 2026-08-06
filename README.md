# SOC alert triage tool — classification + AI-generated writeups + dashboard

A SOC tool with three parts: it **classifies** raw security logs into typed,
severity-rated alerts; it uses an **LLM to write** the plain-English
description and recommended action for each one; and it presents the result
in an interactive **dashboard** where an analyst can close or forward each
ticket.

## Pipeline

```
generate_logs.py  →  log_analyzer.py  →  llm_enrich.py  →  build_dashboard.py
   (raw logs)          (classify)        (AI writeup)        (viewable file)
```

```bash
python3 generate_logs.py        # -> logs/*.log
python3 log_analyzer.py          # -> tickets.json (classified, no description yet)

export ANTHROPIC_API_KEY="sk-ant-..."      # or OPENAI_API_KEY
pip install -r requirements.txt --break-system-packages
python3 llm_enrich.py             # -> tickets_enriched.json (description + action added)

python3 build_dashboard.py        # -> dashboard.html
```

Then just open `dashboard.html` in your browser.

## What each stage does

1. **`generate_logs.py`** — produces three realistic log files (firewall,
   auth, IDS) with known attack patterns embedded in normal background
   traffic: a port scan, an SSH brute-force, an IDS-detected malware C2
   beacon, a web exploitation attempt, and more.

2. **`log_analyzer.py`** — parses the logs and applies threshold-based rules
   to group related events into incidents, assigning each one a **severity**
   (critical/high/medium/low) and **category** (Port Scan, Brute Force,
   IDS Alert, etc.). This stage only classifies — it does not write any
   explanatory text.

3. **`llm_enrich.py`** — for each classified alert, sends the raw evidence
   and its assigned category/severity to an LLM and asks it to write a
   clear, evidence-grounded **description** of what happened and a specific
   **recommended action**. This is what replaces a human analyst (or a huge
   library of canned templates) having to write that text by hand.

4. **`build_dashboard.py`** — injects the finished ticket data into
   `dashboard_template.html`, producing a single self-contained
   `dashboard.html` you can open directly in a browser (no server needed).

## The dashboard

- Filter by severity, status, or category, or search by IP/user/keyword
- Expand any ticket to read its full AI-generated description, recommended
  action, and the raw log evidence it's based on
- **Close** a ticket, with optional analyst notes
- **Forward** a ticket to a team (Incident Response, Network, Endpoint/EDR,
  AppSec, Management), with optional notes
- Reopen a resolved ticket if needed

Note: ticket status changes (close/forward) are held in the browser tab's
memory only — reloading the page resets to the original queue, since this
is a standalone file with no backend to persist changes to.

## Regenerating

Re-run the four commands above in order any time you want a fresh batch of
logs and a freshly AI-written ticket queue. `llm_enrich.py` makes one API
call per alert (not repeated calls — there's no comparison/consistency
testing in this version), so a full run is fast and cheap.

## Extending it

- Add more detection rules to `log_analyzer.py` for more attack types
- Swap the synthetic logs for real ones — the parsers expect standard
  iptables/sshd/Suricata formats, so a new source just needs a new parser
  function following the same pattern
- Add persistence (a small local server or database) so dashboard status
  changes survive a page reload
- Try a different model in `llm_enrich.py` (swap `MODEL_ANTHROPIC` /
  `MODEL_OPENAI`) and compare the quality of the generated writeups
