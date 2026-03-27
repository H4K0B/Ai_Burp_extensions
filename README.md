# AI Bug Hunter — Burp Suite extension (Jython)

Python extension for [Burp Suite](https://portswigger.net/burp) that sends summarized HTTP request/response pairs to the [Anthropic Messages API](https://docs.anthropic.com/en/api/messages) (`https://api.anthropic.com/v1/messages`) and shows structured bug-bounty style notes in a custom suite tab.

## Prerequisites

- Burp Suite (Professional or Community; Extender must be available).
- **Jython 2.7** JAR for Burp’s Python environment ([Jython standalone](https://www.jython.org/download) — use the 2.7.x installer JAR Burp expects).
- An **Anthropic API key** (from the Anthropic Console). The extension stores it in Burp’s extension settings via **Save API key** — it is not hardcoded and is not written to the Output log.

## Load the extension

1. Open Burp → **Extensions** → **Installed**.
2. Click **Add**.
3. **Extension type:** Python.
4. **Extension file:** choose `AI_BUG_HUNTER.py` from this folder.
5. If Burp asks for the Jython JAR, set it under **Extensions** → **Options** → **Python Environment** → **Location of Jython standalone JAR**.

After load, open the **AI Bug Hunter** tab (suite tabs row).

## Configure

1. Paste your API key and click **Save API key**.
2. **Model:** choose from dropdown (for example `claude-haiku-4-5-20251001`, `claude-sonnet-4-20250514`, `claude-opus-4-6`) or type any model ID your key supports (see [Anthropic model docs](https://docs.anthropic.com/en/docs/about-claude/models)).
3. **Deep profile:** pick `Access Control`, `Injection`, `Frontend JS`, or `Business Logic` before **Deep Analyze**.
4. **Automatic scanning:** when enabled, completed Repeater responses trigger analysis. This can be noisy/costly; disable when not needed.

## Usage

- **Right-click** a message in Proxy / Repeater / site map → **Send to AI Bug Hunter**.
- Or select a row, **right-click once** (to refresh the internal selection cache), then click **Analyze Selected Request** on the tab. If your Burp build exposes `getSelectedMessages()` on callbacks, the button works without the right-click step.
- Use **Deep Analyze** for stronger reasoning and profile-specific checks.
- Use **Manual prompt + Chat** to send your own prompt without selecting traffic.
- Use **Stop** to cancel in-flight AI requests.
- Use **Load History** to view saved analysis results in the UI.

The tab shows **Request URL** (with an orange **[SUSPICIOUS ENDPOINT]** prefix for paths containing `/api/`, `/admin`, `/upload`, or `/auth`), **Risk level** (parsed from the model’s final `RISK_LEVEL:` line), and the model output under **Summary / Vulnerabilities / Test Steps**.

## Limits and behavior

- Response bodies are capped at about **5 KB** for the prompt; large bodies are truncated with a note.
- Automatic scanning **skips** common static assets (by URL extension and `Content-Type` hints such as `image/*`).
- Backend LLM endpoints (e.g. `api.anthropic.com`) are skipped from analysis to avoid self-analysis noise.
- API calls run on a **background thread** so the Burp UI stays responsive.
- On automatic analysis failure, the tab is not overwritten; a short line is printed to Burp’s extension **Output** (no API key or full error body).
- History is saved as JSONL at `~/.ai_bug_hunter/analysis_history.jsonl` and also shown in the History panel.

## Share on GitHub (for other hunters)

1. Create a new GitHub repository (for example `ai-bug-hunter-burp`).
2. From this folder, run:

```bash
git init
git add .
git commit -m "Initial release: AI Bug Hunter Burp extension"
git branch -M main
git remote add origin https://github.com/<your-username>/<repo-name>.git
git push -u origin main
```

3. Add a short release note in GitHub:
   - what the extension does
   - how to load in Burp
   - required Jython + API key
   - legal/scope warning

## Collaboration suggestions

- Ask users to open issues with:
  - Burp version
  - Jython version
  - exact error text from Extender Output/Errors
  - reproducible steps
- Review pull requests for:
  - safety (no secrets/logging)
  - non-destructive testing guidance
  - Burp/Jython compatibility

## Files

| File | Purpose |
|------|--------|
| `AI_BUG_HUNTER.py` | Extension: `IBurpExtender`, `IHttpListener`, `ITab`, `IContextMenuFactory` |

## Legal / safety

Use only on systems you are authorized to test. The extension suggests **non-destructive** test ideas; you are responsible for compliance with program rules and applicable law.
