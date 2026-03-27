# -*- coding: utf-8 -*-
"""
AI Bug Hunter — Burp Suite extension (Jython / Burp Extender API).

Integrates with Anthropic Claude (Messages API) to suggest bug-bounty style
findings from HTTP traffic. API key is configured in the UI and persisted
via Burp's extension settings (never hardcoded).

Load: Extender -> Extensions -> Add -> Extension type: Python -> select this file.
Requires: Jython standalone JAR configured in Burp (Extender -> Options).
"""

from burp import IBurpExtender, IBurpExtenderCallbacks, IHttpListener, ITab
from burp import IParameter, IContextMenuFactory

from javax.swing import JPanel, JScrollPane, JTextArea, JButton, JCheckBox, JLabel
from javax.swing import SwingUtilities, BoxLayout, Box, JTextField, JPasswordField, JOptionPane, JSplitPane, JMenuItem
from javax.swing import JComboBox
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Font, Color, Dimension
from java.lang import Runnable, Thread, String, System
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader
from java.util import ArrayList

import json
import os
import re

from javax.net.ssl import HttpsURLConnection, SSLContext, X509TrustManager, HostnameVerifier

# ---------------------------------------------------------------------------
# Anthropic Messages API (HTTPS). Model ID: use a current Sonnet; change in UI if needed.
# ---------------------------------------------------------------------------
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
MODEL_CHOICES = [
    "claude-haiku-4-5-20251001",
    "claude-sonnet-4-20250514",
    "claude-opus-4-6",
]
MAX_RESPONSE_BODY_BYTES = 5120  # ~5KB cap for AI context
DEFAULT_TEMPERATURE = 0.2  # Lower = more deterministic/precise


class _TrustAllManager(X509TrustManager):
    """Optional TLS workaround for SSL-inspecting environments."""
    def checkClientTrusted(self, chain, authType):
        pass

    def checkServerTrusted(self, chain, authType):
        pass

    def getAcceptedIssuers(self):
        return []


class _TrustAllHostVerifier(HostnameVerifier):
    def verify(self, hostname, session):
        return True

# Static / binary-ish extensions — skip auto-scan (still analyzable manually).
STATIC_EXTENSIONS = frozenset([
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
    ".zip", ".gz", ".wasm",
])

# Bonus: suspicious path substrings (case-insensitive highlight in UI).
SUSPICIOUS_PATH_MARKERS = ("/api/", "/admin", "/upload", "/auth")


def _is_suspicious_url(url_string):
    """Return True if URL path suggests higher-value targets for bug bounty."""
    if not url_string:
        return False
    lower = url_string.lower()
    for marker in SUSPICIOUS_PATH_MARKERS:
        if marker.lower() in lower:
            return True
    return False


def _looks_like_static_request(url_string, content_type_header):
    """Heuristic: skip noisy static assets during automatic scanning."""
    if url_string:
        path = url_string.split("?", 1)[0].lower()
        for ext in STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True
    if content_type_header:
        ct = content_type_header.lower()
        if any(x in ct for x in ("image/", "font/", "video/", "audio/")):
            return True
    return False


def _is_backend_llm_url(url_string):
    """Skip analyzing LLM provider traffic (avoid self-analysis/noise)."""
    if not url_string:
        return False
    u = url_string.lower()
    if "api.anthropic.com" in u:
        return True
    # If user changed the API URL constant, also ignore that endpoint.
    try:
        api_u = ANTHROPIC_API_URL.lower()
        if api_u and u.startswith(api_u):
            return True
    except Exception:
        pass
    return False


def _bytes_to_unicode(data_bytes):
    """Convert Java byte[] (Burp message bodies) to Unicode for prompts and UI."""
    if data_bytes is None:
        return u""
    try:
        return unicode(data_bytes.tostring(), "utf-8", errors="replace")
    except Exception:
        try:
            return unicode(str(data_bytes), errors="replace")
        except Exception:
            return u""


def _safe_truncate_bytes(data_bytes, limit):
    """Decode up to `limit` bytes; append a clear note if truncated."""
    if data_bytes is None:
        return u""
    n = len(data_bytes)
    if n <= limit:
        return _bytes_to_unicode(data_bytes)
    cut = data_bytes[:limit]
    return _bytes_to_unicode(cut) + u"\n\n[... truncated at %d of %d bytes ...]" % (limit, n)


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    """
    Single extension class:
    - IBurpExtender: entrypoint (registerExtenderCallbacks).
    - IHttpListener: observe completed responses when auto-scan is ON.
    - ITab: suite tab UI (API key, model, output).
    - IContextMenuFactory: right-click action + refresh cached selection for the button.
    """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AI Bug Hunter (Claude)")

        # Persisted settings keys (API key is stored locally in Burp config — not logged).
        self._SETTING_API_KEY = "ai_bug_hunter.api_key"
        self._SETTING_MODEL = "ai_bug_hunter.model"
        self._SETTING_SCAN_ON = "ai_bug_hunter.scan_on"

        self._scan_enabled = self._load_bool(self._SETTING_SCAN_ON, False)
        self._model = callbacks.loadExtensionSetting(self._SETTING_MODEL) or DEFAULT_MODEL
        self._history_path = os.path.join(os.path.expanduser("~"), ".ai_bug_hunter", "analysis_history.jsonl")
        # Updated whenever the user opens a context menu on message(s); used if callbacks lack getSelectedMessages.
        self._last_selected_rr = None
        # Track in-flight request for "Stop" button.
        self._cancel_requested = False
        self._active_conn = None
        self._active_thread = None
        self._active_out = None
        self._active_stream = None
        self._active_reader = None

        self._build_ui()
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self._callbacks.printOutput("AI Bug Hunter: loaded. Set API key in tab; toggle scan as needed.")

    # -- Settings -----------------------------------------------------------
    def _load_bool(self, key, default):
        v = self._callbacks.loadExtensionSetting(key)
        if v is None:
            return default
        return v.lower() in ("true", "1", "yes")

    def _save_bool(self, key, value):
        self._callbacks.saveExtensionSetting(key, "true" if value else "false")

    # -- UI -----------------------------------------------------------------
    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBorder(EmptyBorder(8, 8, 8, 8))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))

        row1 = JPanel(BorderLayout())
        self._scan_toggle = JCheckBox("Automatic scanning (all tools)", self._scan_enabled)
        self._scan_toggle.addActionListener(lambda e: self._on_scan_toggle())
        row1.add(self._scan_toggle, BorderLayout.WEST)

        row2 = JPanel(BorderLayout(4, 0))
        row2.add(JLabel("API key:"), BorderLayout.WEST)
        self._api_key_field = JPasswordField(32)
        saved_key = self._callbacks.loadExtensionSetting(self._SETTING_API_KEY)
        if saved_key:
            self._api_key_field.setText(saved_key)
        row2.add(self._api_key_field, BorderLayout.CENTER)
        btn_save = JButton("Save API key", actionPerformed=lambda e: self._save_api_key())
        row2.add(btn_save, BorderLayout.EAST)

        row3 = JPanel(BorderLayout(4, 0))
        row3.add(JLabel("Model:"), BorderLayout.WEST)
        self._model_combo = JComboBox(MODEL_CHOICES)
        self._model_combo.setEditable(True)
        try:
            self._model_combo.setSelectedItem(self._model)
        except Exception:
            pass
        row3.add(self._model_combo, BorderLayout.CENTER)

        row4 = JPanel(BorderLayout(4, 0))
        row4.add(JLabel("Deep profile:"), BorderLayout.WEST)
        self._deep_profile = JComboBox(["Access Control", "Injection", "Frontend JS", "Business Logic"])
        self._deep_profile.setSelectedItem("Frontend JS")
        row4.add(self._deep_profile, BorderLayout.CENTER)

        row5 = JPanel()
        self._analyze_btn = JButton("Analyze Selected Request", actionPerformed=lambda e: self._analyze_selected())
        row5.add(self._analyze_btn)
        self._deep_btn = JButton("Deep Analyze", actionPerformed=lambda e: self._analyze_selected_deep())
        row5.add(self._deep_btn)
        self._stop_btn = JButton("Stop", actionPerformed=lambda e: self._cancel_active_request())
        self._stop_btn.setEnabled(False)
        row5.add(self._stop_btn)

        row6 = JPanel()
        self._history_load_btn = JButton("Load History", actionPerformed=lambda e: self._load_history_into_ui())
        row6.add(self._history_load_btn)
        self._history_clear_btn = JButton("Clear History View", actionPerformed=lambda e: self._clear_history_view())
        row6.add(self._history_clear_btn)

        row7 = JPanel(BorderLayout(4, 0))
        row7.add(JLabel("Manual prompt:"), BorderLayout.WEST)
        self._manual_prompt = JTextField("", 60)
        row7.add(self._manual_prompt, BorderLayout.CENTER)
        row7_btns = JPanel()
        self._chat_btn = JButton("Chat", actionPerformed=lambda e: self._chat_manual())
        row7_btns.add(self._chat_btn)
        self._chat_clear_btn = JButton("Clear", actionPerformed=lambda e: self._manual_prompt.setText(""))
        row7_btns.add(self._chat_clear_btn)
        row7.add(row7_btns, BorderLayout.EAST)

        top.add(row1)
        top.add(Box.createVerticalStrut(4))
        top.add(row2)
        top.add(Box.createVerticalStrut(4))
        top.add(row3)
        top.add(Box.createVerticalStrut(4))
        row4.setAlignmentX(0.0)
        top.add(row4)
        top.add(Box.createVerticalStrut(4))
        row5.setAlignmentX(0.0)
        top.add(row5)
        top.add(Box.createVerticalStrut(4))
        row6.setAlignmentX(0.0)
        top.add(row6)
        top.add(Box.createVerticalStrut(4))
        row7.setAlignmentX(0.0)
        top.add(row7)

        self._url_label = JLabel("Request URL: (none)")
        self._url_label.setFont(self._url_label.getFont().deriveFont(Font.BOLD))
        self._risk_label = JLabel("Risk level: —")
        self._risk_label.setFont(self._risk_label.getFont().deriveFont(Font.BOLD))

        meta = JPanel()
        meta.setLayout(BoxLayout(meta, BoxLayout.Y_AXIS))
        meta.add(self._url_label)
        meta.add(Box.createVerticalStrut(4))
        meta.add(self._risk_label)

        self._output_area = JTextArea()
        self._output_area.setEditable(False)
        self._output_area.setLineWrap(True)
        self._output_area.setWrapStyleWord(True)
        self._output_area.setFont(Font("Monospaced", Font.PLAIN, 12))

        scroll = JScrollPane(self._output_area)
        scroll.setPreferredSize(Dimension(800, 360))

        self._history_area = JTextArea()
        self._history_area.setEditable(False)
        self._history_area.setLineWrap(True)
        self._history_area.setWrapStyleWord(True)
        self._history_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._history_area.setText("History is saved to: %s\nClick 'Load History' to view recent records." % self._history_path)
        history_scroll = JScrollPane(self._history_area)
        history_scroll.setPreferredSize(Dimension(800, 160))

        content_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll, history_scroll)
        content_split.setResizeWeight(0.72)

        center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, meta, content_split)
        center_split.setResizeWeight(0.08)

        self._main_panel.add(top, BorderLayout.NORTH)
        self._main_panel.add(center_split, BorderLayout.CENTER)

        self._callbacks.addSuiteTab(self)

    def _chat_manual(self):
        """Send a user-written prompt to Claude (no HTTP selection required)."""
        prompt = u""
        try:
            prompt = unicode(self._manual_prompt.getText() or u"").strip()
        except Exception:
            prompt = u""
        if not prompt:
            self._output_area.setText(u"Manual prompt is empty.")
            return

        api_key = self._get_api_key()
        if not api_key:
            self._output_area.setText(u"Set and save your Anthropic API key first.")
            return

        model = self._get_model()
        # Mark as manual chat in history.
        http_block = u"(manual chat prompt)\n\nPROMPT:\n" + prompt
        self._run_api_async(http_block, u"(manual chat)", False, api_key, model, from_auto=False, deep_mode=False, deep_profile="Manual")

    def getTabCaption(self):
        return "AI Bug Hunter"

    def getUiComponent(self):
        return self._main_panel

    def _on_scan_toggle(self):
        self._scan_enabled = self._scan_toggle.isSelected()
        self._save_bool(self._SETTING_SCAN_ON, self._scan_enabled)

    def _save_api_key(self):
        key = self._read_api_key_field()
        self._callbacks.saveExtensionSetting(self._SETTING_API_KEY, key)
        self._callbacks.printOutput("AI Bug Hunter: API key saved to extension settings.")
        JOptionPane.showMessageDialog(self._main_panel, "API key saved.", "AI Bug Hunter", JOptionPane.INFORMATION_MESSAGE)

    def _get_api_key(self):
        k = self._read_api_key_field()
        if not k:
            k = (self._callbacks.loadExtensionSetting(self._SETTING_API_KEY) or "").strip()
        return k

    def _read_api_key_field(self):
        """Read JPasswordField safely in Jython and normalize pasted secrets."""
        try:
            chars = self._api_key_field.getPassword()  # Java char[]
            if chars is None:
                return u""
            key = unicode(String(chars)).strip()
        except Exception:
            try:
                key = unicode(self._api_key_field.getText() or "").strip()
            except Exception:
                return u""
        # Remove accidental wrapping quotes/backticks from copy-paste.
        if len(key) >= 2 and ((key[0] == '"' and key[-1] == '"') or (key[0] == "'" and key[-1] == "'") or (key[0] == "`" and key[-1] == "`")):
            key = key[1:-1].strip()
        return key

    def _get_model(self):
        m = u""
        try:
            sel = self._model_combo.getSelectedItem()
            if sel is not None:
                m = unicode(sel).strip()
        except Exception:
            m = u""
        if m:
            self._callbacks.saveExtensionSetting(self._SETTING_MODEL, m)
            self._model = m
        return self._model or DEFAULT_MODEL

    # -- Context menu: analyze this message ---------------------------------
    def createMenuItems(self, invocation):
        """Right-click entry point; robust across Burp tools/editors."""
        try:
            responses = invocation.getSelectedMessages()
            if responses and len(responses) > 0:
                self._last_selected_rr = responses[0]

            def _go(ev=None):
                msg = None
                # 1) Fresh selection from current invocation
                try:
                    cur = invocation.getSelectedMessages()
                    if cur and len(cur) > 0:
                        msg = cur[0]
                except Exception:
                    msg = None
                # 2) Burp callbacks selection (some views update this)
                if msg is None:
                    try:
                        sel = self._callbacks.getSelectedMessages()
                        if sel and len(sel) > 0:
                            msg = sel[0]
                    except Exception:
                        msg = None
                # 3) Last cached right-click target
                if msg is None:
                    msg = self._last_selected_rr

                if msg is None:
                    JOptionPane.showMessageDialog(
                        self._main_panel,
                        "No request/response selected. Open Repeater or Proxy history, select one item, then right-click again.",
                        "AI Bug Hunter",
                        JOptionPane.WARNING_MESSAGE,
                    )
                    return

                self._last_selected_rr = msg
                try:
                    self._output_area.setText(u"Queued from right-click menu…")
                except Exception:
                    pass
                self._analyze_http_message(msg, from_auto=False)

            mi = JMenuItem("Send to AI Bug Hunter", actionPerformed=_go)
            al = ArrayList()
            al.add(mi)
            return al
        except Exception:
            pass
        # Always return a menu item when possible for better UX.
        try:
            mi = JMenuItem("Send to AI Bug Hunter", actionPerformed=lambda e: self._analyze_selected())
            al = ArrayList()
            al.add(mi)
            return al
        except Exception:
            return None

    def _analyze_selected(self):
        """Analyze the current selection: tries Burp API first, else last context-menu target."""
        self._analyze_selected_common(deep_mode=False)

    def _analyze_selected_deep(self):
        """Deep mode: broader security review with stronger frontend/JS focus."""
        self._analyze_selected_common(deep_mode=True)

    def _analyze_selected_common(self, deep_mode):
        """Analyze current selection (normal or deep mode)."""
        deep_profile = self._get_deep_profile()
        selected = None
        try:
            selected = self._callbacks.getSelectedMessages()
        except Exception:
            selected = None
        if selected and len(selected) > 0:
            self._analyze_http_message(selected[0], from_auto=False, deep_mode=deep_mode, deep_profile=deep_profile)
            return
        if self._last_selected_rr is not None:
            self._analyze_http_message(self._last_selected_rr, from_auto=False, deep_mode=deep_mode, deep_profile=deep_profile)
            return
        JOptionPane.showMessageDialog(
            self._main_panel,
            "Select a request in Proxy / Repeater / Site map, right-click once (to refresh the selection cache), "
            "then click Analyze — or use the context menu item \"Send to AI Bug Hunter\".",
            "AI Bug Hunter",
            JOptionPane.WARNING_MESSAGE,
        )

    # -- IHttpListener: fire after each response (Burp already paired request+response) --
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        if not self._scan_enabled:
            return
        # Keep auto mode focused on user-driven testing traffic in Repeater.
        if toolFlag != self._callbacks.TOOL_REPEATER:
            return
        self._analyze_http_message(messageInfo, from_auto=True)

    # -- Core extraction + AI -----------------------------------------------
    def _analyze_http_message(self, messageInfo, from_auto, deep_mode=False, deep_profile="Frontend JS"):
        """
        Extract request/response summary, call Claude, update UI.
        from_auto: if True, skip static assets and avoid UI spam for failures.
        """
        try:
            http_service = messageInfo.getHttpService()
            req_bytes = messageInfo.getRequest()
            resp_bytes = messageInfo.getResponse()
            if req_bytes is None:
                if not from_auto:
                    self._output_area.setText(u"No request bytes found in selected item.")
                return

            req_info = self._helpers.analyzeRequest(http_service, req_bytes)
            url = req_info.getUrl()
            url_string = url.toString() if url else ""

            # Never analyze requests sent to the LLM backend itself.
            if _is_backend_llm_url(url_string):
                if not from_auto:
                    self._set_ui_busy(url_string, False, u"Skipped: backend AI API request (select your target request from Repeater).")
                return

            # Support right-click from request editors where response may not exist yet.
            if resp_bytes is not None:
                resp_info = self._helpers.analyzeResponse(resp_bytes)
                status_code = resp_info.getStatusCode()
                headers = resp_info.getHeaders()
                body_offset = resp_info.getBodyOffset()
                body_bytes = resp_bytes[body_offset:] if body_offset < len(resp_bytes) else []
                body_preview = _safe_truncate_bytes(body_bytes, MAX_RESPONSE_BODY_BYTES)
            else:
                status_code = 0
                headers = [u"(no response headers yet)"]
                body_preview = u"(no response captured yet; analyze after sending request in Repeater)"

            content_type = None
            for h in headers:
                if h.lower().startswith("content-type:"):
                    content_type = h.split(":", 1)[1].strip()
                    break

            if from_auto and _looks_like_static_request(url_string, content_type):
                return

            method = self._helpers.bytesToString(req_info.getMethod())
            req_headers = list(req_info.getHeaders())
            params_summary = self._format_parameters(req_info.getParameters())

            req_body_offset = req_info.getBodyOffset()
            req_body_bytes = req_bytes[req_body_offset:] if req_body_offset < len(req_bytes) else []
            req_body_preview = _safe_truncate_bytes(req_body_bytes, min(4096, len(req_body_bytes)))

            http_block = self._build_http_block(
                url_string,
                method,
                req_headers,
                params_summary,
                req_body_preview,
                status_code,
                headers,
                body_preview,
            )

            suspicious = _is_suspicious_url(url_string)
            api_key = self._get_api_key()
            if not api_key:
                if not from_auto:
                    self._set_ui_busy(url_string, suspicious, u"Set and save your Anthropic API key first.")
                return

            model = self._get_model()
            self._run_api_async(http_block, url_string, suspicious, api_key, model, from_auto, deep_mode, deep_profile)

        except Exception as ex:
            if not from_auto:
                self._output_area.setText(u"Error: %s" % unicode(ex))

    def _format_parameters(self, params):
        """Format IParameter list: name, type, value snippet."""
        lines = []
        if not params:
            return u"(no parsed parameters)"
        for p in params:
            try:
                name = self._helpers.bytesToString(p.getName())
                val = self._helpers.bytesToString(p.getValue())
                ptype = p.getType()
                pmap = {
                    IParameter.PARAM_URL: "GET",
                    IParameter.PARAM_BODY: "POST",
                    IParameter.PARAM_COOKIE: "COOKIE",
                }
                _pj = getattr(IParameter, "PARAM_JSON", None)
                if _pj is not None:
                    pmap[_pj] = "JSON"
                type_name = pmap.get(ptype, "OTHER")
                if len(val) > 200:
                    val = val[:200] + u"..."
                lines.append(u"[%s] %s=%s" % (type_name, name, val))
            except Exception:
                continue
        return u"\n".join(lines) if lines else u"(none)"

    def _build_http_block(self, url_string, method, req_headers, params_summary,
                          req_body_preview, status_code, resp_headers, body_preview):
        """Single text blob sent to the model (no secrets should be pasted by user)."""
        rh = u"\n".join(unicode(h) for h in req_headers)
        sh = u"\n".join(unicode(h) for h in resp_headers)
        return (
            u"=== REQUEST ===\n"
            u"URL: %s\nMethod: %s\n\nHeaders:\n%s\n\nParameters:\n%s\n\nBody (preview):\n%s\n\n"
            u"=== RESPONSE ===\nStatus: %s\n\nHeaders:\n%s\n\nBody (preview):\n%s"
            % (
                url_string,
                method,
                rh,
                params_summary,
                req_body_preview,
                unicode(status_code),
                sh,
                body_preview,
            )
        )

    def _build_user_prompt(self, http_block, deep_mode=False, deep_profile="Frontend JS"):
        # Core instructions match the product brief; extra headings keep the Burp tab readable.
        if deep_mode:
            profile_focus = {
                "Access Control": u"Prioritize authorization boundary validation, cross-tenant access, role bypass and IDOR sequence design.",
                "Injection": u"Prioritize input-to-sink tracing, parser boundary abuse, encoding confusion and server-side injection indicators.",
                "Frontend JS": u"Prioritize frontend trust boundaries, DOM/URL sinks, token/session storage usage and client-side auth logic flaws.",
                "Business Logic": u"Prioritize state machine flaws, workflow bypass, race windows, replay/idempotency and pricing/limit abuse checks.",
            }.get(deep_profile, u"Prioritize broad high-impact vulnerability analysis.")
            return (
                u"You are an elite bug bounty hunter and secure code reviewer.\n"
                u"Perform DEEP analysis of this HTTP transaction and inferred frontend JavaScript behaviors.\n\n"
                u"Deep profile: " + deep_profile + u"\n"
                u"Profile focus: " + profile_focus + u"\n\n"
                u"Focus on:\n\n"
                u"* IDOR and Broken Access Control\n* Business logic flaws and workflow bypasses\n"
                u"* Injection classes (SQL/NoSQL/template/command)\n* Authentication/session issues\n"
                u"* Client-side trust issues in frontend JS (token handling, role checks, DOM sinks)\n"
                u"* CORS/CSRF/JWT misconfigurations\n\n"
                u"For each finding include:\n\n"
                u"* Why the issue may exist\n* Evidence from HTTP data\n"
                u"* Safe validation steps in Burp Repeater\n"
                u"* Defensive test payload ideas (benign placeholders only; no weaponized payloads)\n"
                u"* Remediation guidance\n\n"
                u"Structure your reply under these headings (use exact titles):\n\n"
                u"## Summary\n## Vulnerabilities\n## Frontend JS Deep Notes\n## Safe Test Cases\n## Fix Recommendations\n\n"
                u"Precision rules:\n"
                u"- Use only evidence present in HTTP Data; if uncertain, label as hypothesis.\n"
                u"- For each finding include confidence: High/Medium/Low.\n"
                u"- Keep each finding concise and avoid duplicate points.\n"
                u"- No generic advice without tying to concrete request/response indicators.\n\n"
                u"On the final line only, output exactly one of:\n"
                u"RISK_LEVEL: High\nRISK_LEVEL: Medium\nRISK_LEVEL: Low\n\n"
                u"HTTP Data:\n"
                + http_block
            )
        return (
            u"You are an elite bug bounty hunter.\n"
            u"Analyze this HTTP request/response and identify potential vulnerabilities.\n\n"
            u"Focus on:\n\n"
            u"* IDOR\n* Broken Access Control\n* Business Logic Bugs\n"
            u"* Injection\n* Race Conditions\n* Authentication issues\n\n"
            u"For each finding:\n\n"
            u"* Explain why it's vulnerable\n* Provide a test case\n"
            u"* Suggest exploitation idea (no harmful payloads)\n\n"
            u"Structure your reply under these headings (use the exact titles):\n\n"
            u"## Summary\n## Vulnerabilities\n## Test Steps\n\n"
            u"Precision rules:\n"
            u"- Base conclusions strictly on provided HTTP Data.\n"
            u"- Mark uncertain items as hypothesis.\n"
            u"- Add confidence High/Medium/Low for each finding.\n"
            u"- Avoid repeating the same issue in multiple bullets.\n\n"
            u"On the final line only, output exactly one of:\n"
            u"RISK_LEVEL: High\nRISK_LEVEL: Medium\nRISK_LEVEL: Low\n\n"
            u"HTTP Data:\n"
            + http_block
        )

    def _parse_risk_level(self, text):
        if not text:
            return None
        m = re.search(r"RISK_LEVEL:\s*(High|Medium|Low)\s*$", text, re.MULTILINE | re.IGNORECASE)
        if m:
            return m.group(1).title()
        # Fallback: keywords
        tl = text.lower()
        if "risk_level: high" in tl:
            return "High"
        if "risk_level: medium" in tl:
            return "Medium"
        if "risk_level: low" in tl:
            return "Low"
        return None

    def _strip_trailing_risk_line(self, text):
        return re.sub(r"\nRISK_LEVEL:\s*(High|Medium|Low)\s*$", "", text, flags=re.IGNORECASE | re.MULTILINE)

    def _anthropic_request(self, api_key, model, user_text):
        """
        POST JSON to Anthropic Messages API using the JVM’s URLConnection (Jython-friendly).
        Returns (success, assistant_text_or_error_message). Never logs the API key.
        """
        payload = {
            "model": model,
            "max_tokens": 4096,
            "temperature": DEFAULT_TEMPERATURE,
            "messages": [{"role": "user", "content": user_text}],
        }
        body = json.dumps(payload, ensure_ascii=False)
        # Jython / Py2: dumps may return unicode; URLConnection needs raw UTF-8 bytes.
        if isinstance(body, unicode):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = body

        conn = None
        try:
            url = URL(ANTHROPIC_API_URL)
            conn = url.openConnection()
            self._active_conn = conn
            # Optional escape hatch for hosts with TLS interception/proxy cert issues.
            # Enabled by default for Burp/Jython compatibility on hostile TLS paths.
            # To disable explicitly: AI_BUG_HUNTER_INSECURE_TLS=false
            if isinstance(conn, HttpsURLConnection):
                insecure_tls = (os.environ.get("AI_BUG_HUNTER_INSECURE_TLS") or "true").strip().lower()
                if insecure_tls not in ("0", "false", "no"):
                    ctx = SSLContext.getInstance("TLS")
                    ctx.init(None, [_TrustAllManager()], None)
                    conn.setSSLSocketFactory(ctx.getSocketFactory())
                    conn.setHostnameVerifier(_TrustAllHostVerifier())
            conn.setRequestMethod("POST")
            conn.setDoOutput(True)
            conn.setConnectTimeout(60000)
            conn.setReadTimeout(120000)
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            conn.setRequestProperty("x-api-key", api_key)
            conn.setRequestProperty("anthropic-version", ANTHROPIC_VERSION)

            if self._cancel_requested:
                return False, u"Cancelled."

            out = conn.getOutputStream()
            self._active_out = out
            out.write(body_bytes)
            out.flush()
            out.close()
            self._active_out = None

            code = conn.getResponseCode()
            stream = conn.getErrorStream() if code >= 400 else conn.getInputStream()
            if stream is None:
                stream = conn.getInputStream()
            if stream is None:
                return False, u"Empty HTTP response stream (HTTP %s)." % code
            self._active_stream = stream
            reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
            self._active_reader = reader
            lines = []
            line = reader.readLine()
            while line is not None:
                if self._cancel_requested:
                    try:
                        reader.close()
                    except Exception:
                        pass
                    return False, u"Cancelled."
                lines.append(unicode(line))
                line = reader.readLine()
            reader.close()
            self._active_reader = None
            self._active_stream = None
            resp_text = u"\n".join(lines)

            if code != 200:
                # Do not print API key or full body to Burp console
                return False, u"API error HTTP %s: %s" % (code, resp_text[:500])

            try:
                data = json.loads(resp_text)
            except ValueError:
                return False, u"Invalid JSON from API."
            content = data.get("content", [])
            parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
            if not parts:
                return False, u"Unexpected API response shape."
            return True, u"\n".join(parts)
        except Exception as e:
            return False, u"Request failed: %s" % unicode(e)
        finally:
            self._active_out = None
            self._active_stream = None
            self._active_reader = None
            self._active_conn = None
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass

    def _run_api_async(self, http_block, url_string, suspicious, api_key, model, from_auto, deep_mode=False, deep_profile="Frontend JS"):
        user_prompt = self._build_user_prompt(http_block, deep_mode, deep_profile)
        self._cancel_requested = False

        class Worker(Runnable):
            def __init__(self, outer):
                self.outer = outer

            def run(self):
                ok, result = self.outer._anthropic_request(api_key, model, user_prompt)

                class Ui(Runnable):
                    def __init__(self, o, success, msg, u, susp, fa, dm, dp, m, hb):
                        self.o = o
                        self.success = success
                        self.msg = msg
                        self.u = u
                        self.susp = susp
                        self.fa = fa
                        self.dm = dm
                        self.dp = dp
                        self.m = m
                        self.hb = hb

                    def run(self):
                        try:
                            self.o._active_thread = None
                            self.o._stop_btn.setEnabled(False)
                            self.o._analyze_btn.setEnabled(True)
                            self.o._deep_btn.setEnabled(True)
                        except Exception:
                            pass
                        self.o._apply_ai_result(
                            self.success, self.msg, self.u, self.susp, self.fa,
                            self.dm, self.dp, self.m, self.hb
                        )

                SwingUtilities.invokeLater(
                    Ui(self.outer, ok, result, url_string, suspicious, from_auto, deep_mode, deep_profile, model, http_block)
                )

        t = Thread(Worker(self))
        self._active_thread = t
        try:
            self._stop_btn.setEnabled(True)
            self._analyze_btn.setEnabled(False)
            self._deep_btn.setEnabled(False)
        except Exception:
            pass
        t.start()

        if not from_auto:
            if deep_mode:
                self._set_ui_busy(url_string, suspicious, u"Calling Claude API (Deep Analyze: %s)…" % deep_profile)
            else:
                self._set_ui_busy(url_string, suspicious, u"Calling Claude API…")

    def _get_deep_profile(self):
        try:
            sel = self._deep_profile.getSelectedItem()
            if sel is None:
                return "Frontend JS"
            return unicode(sel)
        except Exception:
            return "Frontend JS"

    def _cancel_active_request(self):
        """Cancel in-flight API call (best-effort)."""
        self._cancel_requested = True
        try:
            if self._active_out is not None:
                try:
                    self._active_out.close()
                except Exception:
                    pass
            if self._active_reader is not None:
                try:
                    self._active_reader.close()
                except Exception:
                    pass
            if self._active_stream is not None:
                try:
                    self._active_stream.close()
                except Exception:
                    pass
            if self._active_conn is not None:
                try:
                    self._active_conn.disconnect()
                except Exception:
                    pass
            if self._active_thread is not None:
                try:
                    self._active_thread.interrupt()
                except Exception:
                    pass
        finally:
            try:
                self._stop_btn.setEnabled(False)
                self._analyze_btn.setEnabled(True)
                self._deep_btn.setEnabled(True)
            except Exception:
                pass
            try:
                self._output_area.setText(u"Cancelled.")
            except Exception:
                pass

    def _set_ui_busy(self, url_string, suspicious, note):
        prefix = u"[SUSPICIOUS ENDPOINT] " if suspicious else u""
        self._url_label.setText(prefix + "Request URL: " + (url_string or u"(unknown)"))
        if suspicious:
            self._url_label.setForeground(Color(0xC04000))
        else:
            self._url_label.setForeground(Color.BLACK)
        self._risk_label.setText("Risk level: …")
        self._risk_label.setForeground(Color.DARK_GRAY)
        self._output_area.setText(note)

    def _save_history_record(self, record):
        """Persist analysis output to local JSONL for future review."""
        try:
            folder = os.path.dirname(self._history_path)
            if folder and not os.path.exists(folder):
                os.makedirs(folder)
            line = json.dumps(record, ensure_ascii=False)
            if isinstance(line, unicode):
                line = line.encode("utf-8")
            f = open(self._history_path, "ab")
            try:
                f.write(line + "\n")
            finally:
                f.close()
            self._append_history_record_to_ui(record)
        except Exception as e:
            try:
                self._callbacks.printError("AI Bug Hunter: failed to save history: %s" % unicode(e))
            except Exception:
                pass

    def _append_history_record_to_ui(self, record):
        """Append a concise single-line summary in the History UI."""
        try:
            mode = record.get("mode", "")
            profile = record.get("deep_profile", "")
            risk = record.get("risk", "")
            url = record.get("url", "")
            ok = "OK" if record.get("success") else "ERR"
            short_url = url if len(url) <= 120 else (url[:117] + "...")
            mode_text = mode if mode != "deep" else ("deep/%s" % (profile or "default"))
            line = "[%s] %s | risk=%s | mode=%s | %s" % (ok, record.get("ts_ms", ""), risk, mode_text, short_url)
            existing = self._history_area.getText() or u""
            if existing and not existing.endswith("\n"):
                existing += "\n"
            self._history_area.setText(existing + unicode(line) + u"\n")
        except Exception:
            pass

    def _load_history_into_ui(self):
        """Load recent history records from disk into the History UI."""
        try:
            if not os.path.exists(self._history_path):
                self._history_area.setText("No history file yet. Run Analyze/Deep Analyze first.")
                return
            f = open(self._history_path, "rb")
            try:
                raw = f.read()
            finally:
                f.close()
            try:
                text = raw.decode("utf-8", "replace")
            except Exception:
                text = unicode(raw)
            lines = [ln for ln in text.splitlines() if ln.strip()]
            tail = lines[-120:] if len(lines) > 120 else lines
            rendered = []
            for ln in tail:
                try:
                    item = json.loads(ln)
                    mode = item.get("mode", "")
                    profile = item.get("deep_profile", "")
                    risk = item.get("risk", "")
                    url = item.get("url", "")
                    ok = "OK" if item.get("success") else "ERR"
                    short_url = url if len(url) <= 120 else (url[:117] + "...")
                    mode_text = mode if mode != "deep" else ("deep/%s" % (profile or "default"))
                    rendered.append("[%s] %s | risk=%s | mode=%s | %s" % (ok, item.get("ts_ms", ""), risk, mode_text, short_url))
                except Exception:
                    continue
            self._history_area.setText("\n".join(rendered) if rendered else "History exists but no readable records.")
        except Exception as e:
            self._history_area.setText("Failed to load history: %s" % unicode(e))

    def _clear_history_view(self):
        """Clear only the on-screen history panel (file stays intact)."""
        try:
            self._history_area.setText("History view cleared. File remains at: %s" % self._history_path)
        except Exception:
            pass

    def _apply_ai_result(self, success, message, url_string, suspicious, from_auto,
                         deep_mode=False, deep_profile="Frontend JS", model="", http_block=""):
        prefix = u"[SUSPICIOUS ENDPOINT] " if suspicious else u""
        self._url_label.setText(prefix + "Request URL: " + (url_string or u"(unknown)"))
        if suspicious:
            self._url_label.setForeground(Color(0xC04000))
        else:
            self._url_label.setForeground(Color.BLACK)

        risk = self._parse_risk_level(message) or "Unknown"
        raw_response = message or u""
        cleaned = self._strip_trailing_risk_line(raw_response).strip() if raw_response else u""
        mode_name = "deep" if deep_mode else "normal"
        record = {
            "ts_ms": int(System.currentTimeMillis()),
            "url": url_string or "",
            "suspicious": bool(suspicious),
            "success": bool(success),
            "risk": risk if success else "None",
            "mode": mode_name,
            "deep_profile": deep_profile if deep_mode else "",
            "model": model or "",
            "ai_response_raw": raw_response,
            "analysis": cleaned if success else u"",
            "error": raw_response if not success else u"",
            "http_data": http_block or u"",
        }
        self._save_history_record(record)

        if not success:
            if from_auto:
                # Avoid flashing the tab on every failed auto-scan; never log the API key or full error body.
                self._callbacks.printOutput("AI Bug Hunter: automatic analysis failed (see extension stderr if enabled).")
            else:
                self._risk_label.setText("Risk level: —")
                self._output_area.setText(message)
            return

        clean = cleaned

        self._risk_label.setText("Risk level: " + risk)
        if risk == "High":
            self._risk_label.setForeground(Color.RED)
        elif risk == "Medium":
            self._risk_label.setForeground(Color(0xFF8800))
        elif risk == "Low":
            self._risk_label.setForeground(Color(0x008800))
        else:
            self._risk_label.setForeground(Color.DARK_GRAY)

        self._output_area.setText(clean)
