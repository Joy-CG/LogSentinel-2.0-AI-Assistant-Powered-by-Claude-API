"""
triage.py — AI-powered SOC Alert Triage Assistant

Uses the Claude API to analyse a raw alert or log snippet and return:
  - Threat classification
  - Severity assessment
  - Step-by-step triage walkthrough
  - Recommended next actions
  - MITRE ATT&CK technique mappings
"""

import json
import urllib.request
import urllib.error

API_URL = "https://api.anthropic.com/v1/messages"
MODEL   = "claude-sonnet-4-20250514"

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst and incident responder.

When given a raw security alert, log entry, or suspicious event, you will:

1. THREAT CLASSIFICATION — Identify what type of attack or event this is
2. SEVERITY — Rate as CRITICAL / HIGH / MEDIUM / LOW with justification
3. TRIAGE STEPS — Walk through exactly what an analyst should investigate, step by step
4. RECOMMENDED ACTIONS — Concrete next steps (block IP, escalate, investigate host, etc.)
5. MITRE ATT&CK MAPPING — Map to relevant MITRE ATT&CK techniques with IDs (e.g. T1110 - Brute Force)
6. FALSE POSITIVE CHECK — List indicators that could make this a false positive

Format your response with clear headers using === SECTION === style.
Be specific, technical, and actionable. Write as if briefing a junior analyst."""


def triage_alert(alert_text: str, api_key: str, conversation_history: list) -> tuple[str, list]:
    """
    Send an alert to Claude for triage analysis.

    Args:
        alert_text:           The raw alert or log snippet to analyze.
        api_key:              Anthropic API key.
        conversation_history: List of previous messages for multi-turn chat.

    Returns:
        (response_text, updated_history)
    """
    if not api_key or not api_key.strip():
        return "ERROR: No API key configured. Click [ API KEY ] to set your Anthropic API key.", conversation_history

    # Add user message to history
    conversation_history = conversation_history + [
        {"role": "user", "content": alert_text}
    ]

    payload = {
        "model":      MODEL,
        "max_tokens": 2000,
        "system":     SYSTEM_PROMPT,
        "messages":   conversation_history,
    }

    try:
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         api_key.strip(),
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())

        response_text = data["content"][0]["text"]

        # Add assistant response to history
        conversation_history = conversation_history + [
            {"role": "assistant", "content": response_text}
        ]
        return response_text, conversation_history

    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
            msg = err.get("error", {}).get("message", body)
        except Exception:
            msg = body
        if e.code == 401:
            return f"ERROR: Invalid API key. Check your key at console.anthropic.com\n\n{msg}", conversation_history
        return f"ERROR {e.code}: {msg}", conversation_history
    except Exception as e:
        return f"ERROR: {e}", conversation_history


def load_api_key() -> str:
    """Load API key from local config file."""
    try:
        with open("triage_config.json") as f:
            return json.load(f).get("api_key", "")
    except Exception:
        return ""


def save_api_key(key: str) -> None:
    """Save API key to local config file."""
    with open("triage_config.json", "w") as f:
        json.dump({"api_key": key}, f)
