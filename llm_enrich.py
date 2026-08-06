#!/usr/bin/env python3
"""
llm_enrich.py

Takes the classified tickets from log_analyzer.py (which already know their
severity, category, and evidence) and asks an LLM to write the analyst-facing
description and recommended action for each one -- the part a real SOC tool
would otherwise need a human to type out, or a huge library of canned
templates to approximate.

This is a writing/explanation task, not a judgement task: the LLM is told
what type of alert this is and how severe it's been classified, and asked to
explain it clearly and suggest what to do next. (This is different from the
research-style "blind triage" evaluation -- there's no ground truth being
hidden here, because the point of this script is to produce the ticket
queue itself, not to test the LLM's judgement against it.)

SETUP:
    export ANTHROPIC_API_KEY="sk-ant-..."      # or OPENAI_API_KEY
    pip install -r requirements.txt --break-system-packages
    python3 llm_enrich.py

Reads:  ./tickets.json (from log_analyzer.py)
Writes: ./tickets_enriched.json (same tickets, with description/recommended_action filled in)
"""

import os
import json
import time
import re

MODEL_ANTHROPIC = "claude-sonnet-4-6"
MODEL_OPENAI = "gpt-4o"

SYSTEM_PROMPT = """You are a SOC (Security Operations Centre) assistant that writes clear, \
accurate alert writeups for analysts. You will be given an alert that has \
already been classified (category and severity are already decided -- you \
are not being asked to judge that). Your job is only to explain it well and \
suggest what to do next.

Respond with ONLY a JSON object (no markdown fences, no preamble) with \
exactly these two fields:
{
  "description": "2-4 sentences in plain English explaining what this alert shows and why it matters, grounded specifically in the evidence given",
  "recommended_action": "1-2 sentences telling the analyst exactly what to do next, specific to this alert (not generic advice)"
}

Base everything only on the evidence provided. Do not invent details (IPs, \
timings, techniques) that aren't present in what you were given."""

USER_PROMPT_TEMPLATE = """Alert already classified as:
- Category: {category}
- Severity: {severity}
- Title: {title}

Metadata:
- Timestamp (first event): {timestamp}
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Associated user field (if any): {user}
- Total matching events: {event_count}

Raw log evidence ({n_shown} of {event_count} shown):
{evidence_block}

Write the description and recommended_action for this alert now."""


def build_user_prompt(ticket):
    evidence_block = "\n".join(ticket["evidence"])
    return USER_PROMPT_TEMPLATE.format(
        category=ticket["category"],
        severity=ticket["severity"],
        title=ticket["title"],
        timestamp=ticket["timestamp"],
        src_ip=ticket["src_ip"] or "n/a",
        dst_ip=ticket["dst_ip"] or "n/a",
        user=ticket["user"] or "n/a",
        event_count=ticket["event_count"],
        n_shown=len(ticket["evidence"]),
        evidence_block=evidence_block,
    )


def parse_json_response(text):
    cleaned = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def call_anthropic(client, model, user_prompt):
    resp = client.messages.create(
        model=model,
        max_tokens=400,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return "".join(b.text for b in resp.content if b.type == "text")


def call_openai(client, model, user_prompt):
    resp = client.chat.completions.create(
        model=model,
        max_tokens=400,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    return resp.choices[0].message.content


def fallback_text(ticket):
    """Used only if the LLM call fails or returns unparseable output, so the
    dashboard never has to show a blank ticket."""
    return {
        "description": (
            f"{ticket['category']} alert ({ticket['severity']} severity) involving "
            f"{ticket['event_count']} matching event(s)"
            + (f" from {ticket['src_ip']}" if ticket["src_ip"] else "")
            + (f" to {ticket['dst_ip']}" if ticket["dst_ip"] else "")
            + ". (Auto-generated description unavailable -- see raw evidence below.)"
        ),
        "recommended_action": "Review the raw evidence below and triage manually.",
    }


def main():
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    if anthropic_key:
        import anthropic
        client = anthropic.Anthropic(api_key=anthropic_key)
        model = MODEL_ANTHROPIC
        call_fn = lambda prompt: call_anthropic(client, model, prompt)
        print(f"Using Anthropic API, model={model}")
    elif openai_key:
        import openai
        client = openai.OpenAI(api_key=openai_key)
        model = MODEL_OPENAI
        call_fn = lambda prompt: call_openai(client, model, prompt)
        print(f"Using OpenAI API, model={model}")
    else:
        raise SystemExit(
            "No API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY before running.\n"
            "  export ANTHROPIC_API_KEY=sk-ant-...\n"
            "  export OPENAI_API_KEY=sk-...\n"
        )

    with open("tickets.json") as f:
        tickets = json.load(f)

    n_ok, n_fallback = 0, 0
    for i, ticket in enumerate(tickets, 1):
        print(f"Enriching {ticket['id']} ({i}/{len(tickets)})...")
        user_prompt = build_user_prompt(ticket)
        try:
            raw_text = call_fn(user_prompt)
            parsed = parse_json_response(raw_text)
        except Exception as e:
            print(f"  API error: {e}")
            parsed = None

        if parsed and "description" in parsed and "recommended_action" in parsed:
            ticket["description"] = parsed["description"]
            ticket["recommended_action"] = parsed["recommended_action"]
            n_ok += 1
        else:
            fb = fallback_text(ticket)
            ticket["description"] = fb["description"]
            ticket["recommended_action"] = fb["recommended_action"]
            n_fallback += 1

        time.sleep(0.3)

    with open("tickets_enriched.json", "w") as f:
        json.dump(tickets, f, indent=2)

    print(f"\nDone. {n_ok} enriched by the LLM, {n_fallback} used the fallback template.")
    print("Wrote tickets_enriched.json -- open dashboard.html to view the queue")


if __name__ == "__main__":
    main()
