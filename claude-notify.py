#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""
Claude Code Push Notifications via Hooks
==========================================
Uses Claude Code's native hook system to send push notifications
via ntfy with actionable buttons over Tailscale.

No PTY wrapping, no regex matching — Claude Code tells us directly.

Setup:
  1. Add hooks to .claude/settings.json (see SETTINGS below)
  2. Run the server: uv run claude-notify.py server --topic my-secret-topic
  3. Install ntfy app on phone, subscribe to your topic
  4. Use Claude Code normally — notifications just work

Architecture:
  Claude Code ──hook──▶ claude-notify.py --hook ──▶ server ──▶ ntfy ──▶ Phone
                                                      ▲                    │
                                                      └──── Tailscale ─────┘
"""

import sys
import os
import json
import time
import subprocess
import argparse
import logging
import threading
import contextlib
import copy
import difflib
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import platform
import fnmatch as _fnmatch
import hashlib

import requests

IS_WINDOWS = platform.system() == "Windows"


# ─── Terminal PID Discovery (Windows) ────────────────────────────────────────

_TERMINAL_EXES = frozenset({
    "mintty.exe", "windowsterminal.exe", "cmd.exe",
    "powershell.exe", "pwsh.exe", "conhost.exe",
    "alacritty.exe", "wezterm-gui.exe",
})


def _find_terminal_pid():
    """Walk up the process tree to find the terminal hosting this process.

    Uses the Toolhelp32 snapshot API via ctypes. Returns the PID of the
    first ancestor whose exe name is a known terminal, or None.
    Windows-only; returns None on other platforms.
    """
    if not IS_WINDOWS:
        return None

    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.windll.kernel32
    CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    Process32FirstW = kernel32.Process32FirstW
    Process32NextW = kernel32.Process32NextW
    CloseHandle = kernel32.CloseHandle

    try:
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == -1:
            return None

        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        # Build pid -> (parent_pid, exe_name) map
        proc_map = {}
        if Process32FirstW(snap, ctypes.byref(entry)):
            proc_map[entry.th32ProcessID] = (
                entry.th32ParentProcessID,
                entry.szExeFile.lower(),
            )
            while Process32NextW(snap, ctypes.byref(entry)):
                proc_map[entry.th32ProcessID] = (
                    entry.th32ParentProcessID,
                    entry.szExeFile.lower(),
                )
        CloseHandle(snap)

        # Walk up from our PID
        pid = os.getpid()
        visited = set()
        while pid in proc_map and pid not in visited:
            visited.add(pid)
            parent_pid, exe = proc_map[pid]
            if exe in _TERMINAL_EXES:
                return pid
            pid = parent_pid

        return None
    except Exception:
        return None


# ─── Configuration ────────────────────────────────────────────────────────────

NTFY_TOPIC = None  # Auto-generated if not provided
NTFY_SERVER = "https://ntfy.sh"
HTTP_PORT = 8787
TAILSCALE_IP = None  # Auto-detect if None
PERMISSION_TIMEOUT = 300  # seconds to wait for remote allow/deny

USER_CLAUDE_SETTINGS_PATH = os.path.expanduser("~/.claude/settings.json")
PROJECT_CLAUDE_SETTINGS_PATH = os.path.join(".claude", "settings.json")
MANAGED_HOOK_EVENTS = {
    "Notification": "notification",
    "PreToolUse": "pre_tool_use",
    "Stop": "stop",
}

def _generate_topic() -> str:
    """Generate a unique topic based on machine username and hostname."""
    seed = f"{os.getenv('USERNAME', os.getenv('USER', 'unknown'))}@{platform.node()}"
    suffix = hashlib.sha256(seed.encode()).hexdigest()[:12]
    return f"claude-ntfy-hook-{suffix}"


# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("claude-notify")

# ─── Tailscale ────────────────────────────────────────────────────────────────

def get_tailscale_ip():
    if TAILSCALE_IP:
        return TAILSCALE_IP
    try:
        cmd = ["tailscale.exe" if IS_WINDOWS else "tailscale", "ip", "-4"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        ip = result.stdout.strip().split("\n")[0]
        log.info(f"Tailscale IP: {ip}")
        return ip
    except FileNotFoundError:
        if IS_WINDOWS:
            ts = r"C:\Program Files\Tailscale\tailscale.exe"
            if os.path.exists(ts):
                result = subprocess.run([ts, "ip", "-4"], capture_output=True, text=True, timeout=5)
                return result.stdout.strip().split("\n")[0]
        log.error("Set TAILSCALE_IP manually or ensure tailscale CLI is in PATH.")
        raise SystemExit(1)


# ─── Notification ─────────────────────────────────────────────────────────────

def send_notification(title, message, actions=None, priority="default", tags="", markdown=True):
    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": tags,
        "Content-Type": "text/plain; charset=utf-8",
    }
    if markdown:
        headers["Markdown"] = "yes"
    if actions:
        parts = []
        for a in actions:
            s = f"http, {a['label']}, {a['url']}"
            if a.get("method", "GET") != "GET":
                s += f", method={a['method']}"
            parts.append(s)
        headers["Actions"] = "; ".join(parts)

    max_attempts = 3
    backoff_delays = [1, 3]  # seconds between retries

    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.post(
                f"{NTFY_SERVER}/{NTFY_TOPIC}",
                data=message.encode("utf-8"),
                headers=headers,
                timeout=10,
            )
            # Don't retry on success or client errors (except 429)
            if resp.status_code < 400 or (400 <= resp.status_code < 500 and resp.status_code != 429):
                log.info(f"Sent: {title}")
                return
            # 5xx or 429: worth retrying
            if attempt < max_attempts:
                delay = backoff_delays[attempt - 1]
                log.warning(f"Notification got {resp.status_code}, retrying in {delay}s (attempt {attempt}/{max_attempts})")
                time.sleep(delay)
            else:
                log.error(f"Notification failed after {max_attempts} attempts: HTTP {resp.status_code}")
        except (requests.ConnectionError, requests.Timeout) as e:
            if attempt < max_attempts:
                delay = backoff_delays[attempt - 1]
                log.warning(f"Notification failed ({e.__class__.__name__}), retrying in {delay}s (attempt {attempt}/{max_attempts})")
                time.sleep(delay)
            else:
                log.error(f"Notification failed after {max_attempts} attempts: {e}")
        except Exception as e:
            log.error(f"Notification failed: {e}")
            return


# ─── Permission Decision State ────────────────────────────────────────────────
# PreToolUse hooks block until we get a decision from the phone.

pending_decisions = {}  # request_id -> threading.Event
decision_results = {}   # request_id -> "approve" | "deny"
decision_lock = threading.Lock()
request_counter = 0

# ─── Plan Accept State ───────────────────────────────────────────────────────
# When Claude exits plan mode, we store the terminal PID so the phone can
# send an Enter keystroke to accept the plan.

_plan_accept_lock = threading.Lock()
_plan_accept_terminal_pid = None
_plan_accept_timestamp = 0.0
_PLAN_ACCEPT_STALENESS = 300  # seconds

# ─── Question Answer State ────────────────────────────────────────────────────
# When Claude asks a question, we store the terminal PID so the phone can
# send arrow-key + Enter to select an option.

_question_lock = threading.Lock()
_question_terminal_pid = None
_question_timestamp = 0.0


def _send_keys_to_terminal(terminal_pid, keys="{ENTER}"):
    """Send keystrokes to the terminal window via PowerShell SendKeys.

    Uses WScript.Shell COM object to activate the window by PID and send keys.
    Windows-only; returns False on other platforms or on failure.
    """
    if not IS_WINDOWS:
        return False

    ps_script = (
        "$wsh = New-Object -ComObject WScript.Shell; "
        f"$wsh.AppActivate({terminal_pid}); "
        "Start-Sleep -Milliseconds 100; "
        f"$wsh.SendKeys('{keys}')"
    )

    try:
        CREATE_NO_WINDOW = 0x08000000
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=5,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            log.info(f"Sent keys to terminal PID {terminal_pid}: {keys}")
            return True
        else:
            log.warning(f"SendKeys failed: {result.stderr.strip()}")
            return False
    except Exception as e:
        log.error(f"Failed to send keys: {e}")
        return False


def create_pending_decision() -> str:
    global request_counter
    with decision_lock:
        request_counter += 1
        rid = f"req-{request_counter}-{int(time.time())}"
        pending_decisions[rid] = threading.Event()
        return rid


def wait_for_decision(rid: str, timeout: float = PERMISSION_TIMEOUT) -> str:
    """Block until phone responds or timeout. Returns 'approve' or 'deny'."""
    event = pending_decisions.get(rid)
    if not event:
        return "approve"  # Fallback

    got_response = event.wait(timeout=timeout)

    with decision_lock:
        pending_decisions.pop(rid, None)
        result = decision_results.pop(rid, None)

    if not got_response or result is None:
        log.warning(f"Decision {rid} timed out — defaulting to deny")
        return "deny"
    return result


def resolve_decision(rid: str, decision: str):
    with decision_lock:
        decision_results[rid] = decision
        event = pending_decisions.get(rid)
        if event:
            event.set()
    log.info(f"Decision {rid}: {decision}")


# ─── Settings Hook Management ────────────────────────────────────────────────

def _script_path() -> str:
    return os.path.abspath(__file__).replace("\\", "/")


def _build_managed_hook_commands(server_url: str) -> dict[str, str]:
    hook_cmd = f"uv run {_script_path()}"
    return {
        event: f"{hook_cmd} --hook {hook_type} --server {server_url}"
        for event, hook_type in MANAGED_HOOK_EVENTS.items()
    }


def _build_hook_settings(server_url: str) -> dict:
    return {
        "hooks": {
            event: [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": command,
                        }
                    ],
                }
            ]
            for event, command in _build_managed_hook_commands(server_url).items()
        }
    }


def _load_settings_file(path: str) -> tuple[dict, str, bool]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        return {}, "", False

    if not raw.strip():
        return {}, raw, True

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse JSON in {path}: {exc}")

    if not isinstance(data, dict):
        raise SystemExit(f"Expected top-level JSON object in {path}")

    return data, raw, True


def _remove_managed_hook_entries(settings: dict):
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return

    script_path = _script_path()
    for event, hook_type in MANAGED_HOOK_EVENTS.items():
        blocks = hooks.get(event)
        if not isinstance(blocks, list):
            continue

        command_prefix = f"uv run {script_path} --hook {hook_type}"
        kept_blocks = []

        for block in blocks:
            if not isinstance(block, dict):
                kept_blocks.append(block)
                continue

            hook_list = block.get("hooks")
            if not isinstance(hook_list, list):
                kept_blocks.append(block)
                continue

            kept_hooks = []
            removed = False
            for hook in hook_list:
                if (
                    isinstance(hook, dict)
                    and hook.get("type") == "command"
                    and isinstance(hook.get("command"), str)
                    and hook["command"].startswith(command_prefix)
                ):
                    removed = True
                    continue
                kept_hooks.append(hook)

            if removed:
                if kept_hooks:
                    updated_block = dict(block)
                    updated_block["hooks"] = kept_hooks
                    kept_blocks.append(updated_block)
                continue

            kept_blocks.append(block)

        if kept_blocks:
            hooks[event] = kept_blocks
        else:
            hooks.pop(event, None)

    if not hooks:
        settings.pop("hooks", None)


def _add_managed_hooks(settings: dict, server_url: str):
    _remove_managed_hook_entries(settings)

    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
        settings["hooks"] = hooks

    for event, command in _build_managed_hook_commands(server_url).items():
        existing_blocks = hooks.get(event)
        if not isinstance(existing_blocks, list):
            existing_blocks = []
        existing_blocks.append(
            {
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "command": command,
                    }
                ],
            }
        )
        hooks[event] = existing_blocks


def _render_settings_json(settings: dict) -> str:
    return json.dumps(settings, indent=2) + "\n"


def _build_settings_diff(path: str, old_text: str, new_text: str) -> str:
    return "".join(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"{path} (current)",
            tofile=f"{path} (proposed)",
        )
    )


def run_hook_toggle(args):
    settings_path = os.path.expanduser(args.settings_file)
    current_settings, current_raw, exists = _load_settings_file(settings_path)

    if args.toggle == "remove" and not exists:
        print(f"No settings file found at {settings_path}; nothing to remove.")
        return

    updated_settings = copy.deepcopy(current_settings)
    if args.toggle == "add":
        server_url = args.server_url or f"http://{get_tailscale_ip()}:{HTTP_PORT}"
        _add_managed_hooks(updated_settings, server_url)
    else:
        _remove_managed_hook_entries(updated_settings)

    if updated_settings == current_settings:
        print("No hook changes required.")
        return

    old_text = current_raw
    if old_text and not old_text.endswith("\n"):
        old_text += "\n"
    new_text = _render_settings_json(updated_settings)

    diff = _build_settings_diff(settings_path, old_text, new_text)
    if diff:
        print(diff, end="")
    else:
        print("(No textual diff)")

    try:
        confirm = input(f"Apply '{args.toggle}' hook changes to {settings_path}? [y/N]: ").strip().lower()
    except EOFError:
        print("Cancelled; no input available for confirmation.")
        return
    if confirm not in {"y", "yes"}:
        print("Cancelled; no changes applied.")
        return

    settings_dir = os.path.dirname(settings_path)
    if settings_dir:
        os.makedirs(settings_dir, exist_ok=True)

    with open(settings_path, "w", encoding="utf-8") as f:
        f.write(new_text)

    print(f"Updated {settings_path}")


# ─── Permission Matching (reads from Claude Code settings.json) ──────────────

def _load_permissions() -> dict:
    """Load permission rules from Claude Code settings.json."""
    paths = [
        USER_CLAUDE_SETTINGS_PATH,
        PROJECT_CLAUDE_SETTINGS_PATH,
    ]
    merged = {"allow": [], "ask": [], "deny": []}
    for p in paths:
        try:
            with open(p) as f:
                perms = json.load(f).get("permissions", {})
                for key in merged:
                    merged[key].extend(perms.get(key, []))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    return merged


def _parse_rule(rule: str):
    """Parse a permission rule like 'Bash(rm *)' into (tool_pattern, arg_pattern)."""
    # Format: ToolName(arg pattern) or just ToolName or ToolName(*)
    if "(" in rule and rule.endswith(")"):
        tool_pat = rule[:rule.index("(")]
        arg_pat = rule[rule.index("(") + 1:-1]
    else:
        tool_pat = rule
        arg_pat = "*"
    return tool_pat, arg_pat


def _get_tool_text(tool: str, tool_input: dict) -> str:
    """Extract the matchable text from a tool call input."""
    if tool == "Bash":
        return tool_input.get("command", "")
    if tool in ("Read", "Write", "Edit"):
        return tool_input.get("file_path", "")
    if tool == "Glob":
        return tool_input.get("pattern", "")
    if tool == "Grep":
        return tool_input.get("pattern", "")
    if tool == "WebFetch":
        return tool_input.get("url", "")
    if tool == "WebSearch":
        return tool_input.get("query", "")
    return json.dumps(tool_input)


def _rule_matches(rule: str, tool: str, tool_text: str) -> bool:
    """Check if a permission rule matches a tool call."""
    tool_pat, arg_pat = _parse_rule(rule)
    # Match tool name (supports wildcards like mcp__*)
    if not _fnmatch.fnmatch(tool, tool_pat):
        return False
    # Match argument pattern
    if arg_pat == "*":
        return True
    # Handle special prefixes like domain:*
    if ":" in arg_pat:
        return True  # e.g. WebFetch(domain:*) — let Claude handle specifics
    return _fnmatch.fnmatch(tool_text, arg_pat)


def _needs_approval(tool: str, tool_input) -> bool:
    """Check Claude Code permission rules to see if this tool needs phone approval.

    Only returns True for tools matching 'ask' rules. Tools matching 'allow'
    or 'deny' are handled by Claude Code itself.
    """
    if not isinstance(tool_input, dict):
        return False

    perms = _load_permissions()
    tool_text = _get_tool_text(tool, tool_input)

    # Check 'ask' first — more specific rules should win over broad 'allow'
    for rule in perms["ask"]:
        if _rule_matches(rule, tool, tool_text):
            return True

    # If it matches an 'allow' rule, no approval needed
    for rule in perms["allow"]:
        if _rule_matches(rule, tool, tool_text):
            return False

    # No match — auto-approve (Claude Code handles its own defaults)
    return False


# ─── Tool Preview Formatting ─────────────────────────────────────────────────

def _format_tool_preview(tool: str, tool_input) -> str:
    """Return a concise, markdown-formatted summary of a tool call."""
    if not isinstance(tool_input, dict):
        s = str(tool_input)
        return s[:500] + "..." if len(s) > 500 else s

    if tool == "Bash":
        cmd = tool_input.get("command", "")
        desc = tool_input.get("description", "")
        lines = []
        if desc:
            lines.append(f"*{desc}*")
        if cmd:
            preview = cmd if len(cmd) <= 300 else cmd[:300] + "..."
            lines.append(f"```\n{preview}\n```")
        return "\n".join(lines) or "(empty command)"

    if tool == "Write":
        path = tool_input.get("file_path", "?")
        content = tool_input.get("content", "")
        line_count = content.count("\n") + 1
        return f"**{path}**\n{line_count} lines"

    if tool == "Edit":
        path = tool_input.get("file_path", "?")
        old = tool_input.get("old_string", "")
        new = tool_input.get("new_string", "")
        old_preview = old[:100] + "..." if len(old) > 100 else old
        new_preview = new[:100] + "..." if len(new) > 100 else new
        return f"**{path}**\n```diff\n- {old_preview}\n+ {new_preview}\n```"

    if tool == "Read":
        return f"**{tool_input.get('file_path', '?')}**"

    if tool in ("Glob", "Grep"):
        pattern = tool_input.get("pattern", "?")
        path = tool_input.get("path", ".")
        return f"`{pattern}` in `{path}`"

    if tool == "WebFetch":
        return tool_input.get("url", "?")

    if tool == "WebSearch":
        return f"*{tool_input.get('query', '?')}*"

    if tool == "Task":
        desc = tool_input.get("description", "")
        agent = tool_input.get("subagent_type", "")
        return f"**[{agent}]** {desc}" if agent else desc

    # Fallback: compact JSON
    s = json.dumps(tool_input, indent=2)
    return f"```\n{s[:500]}\n```" if len(s) > 500 else f"```\n{s}\n```"


# ─── Transcript Context Extraction ────────────────────────────────────────────

def _read_file_tail(filepath, max_bytes=65536):
    """Read the last max_bytes of a file, skipping any partial first line."""
    try:
        size = os.path.getsize(filepath)
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # skip partial first line
            return f.read()
    except (OSError, IOError):
        return ""


def _truncate(text, max_len=300):
    """Truncate text with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 1] + "\u2026"


def _format_ask_question(ask_input):
    """Format an AskUserQuestion tool input for mobile notification.

    Returns (title, body) or (None, None) if input is empty.
    """
    questions = ask_input.get("questions", [])
    if not questions:
        return None, None

    q = questions[0]
    header = q.get("header", "")
    question_text = q.get("question", "")
    options = q.get("options", [])

    lines = []
    if question_text:
        lines.append(question_text)
    for opt in options:
        label = opt.get("label", "")
        desc = opt.get("description", "")
        if desc:
            lines.append(f"- **{label}**: {desc}")
        else:
            lines.append(f"- {label}")

    title = f"Claude asks: {header}" if header else "Claude asks a question"
    body = "\n".join(lines)
    return title, body


def _extract_context_summary(transcript_path, notification_type):
    """Extract context from the transcript for a richer notification.

    Returns dict with 'title', 'message', 'tags', 'priority' keys,
    or empty dict if no context found.
    """
    tail = _read_file_tail(transcript_path)
    if not tail:
        return {}

    lines = tail.strip().split("\n")

    ask_question = None
    tool_call = None
    assistant_text = None
    exit_plan = False

    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        if entry.get("type") not in ("assistant", "progress"):
            continue

        message = entry.get("message", {})
        content = message.get("content", [])
        if not isinstance(content, list):
            continue

        for block in reversed(content):
            if not isinstance(block, dict):
                continue

            if (block.get("type") == "tool_use"
                    and block.get("name") == "AskUserQuestion"
                    and ask_question is None):
                ask_question = block.get("input", {})

            elif (block.get("type") == "tool_use"
                    and block.get("name") == "ExitPlanMode"):
                exit_plan = True

            elif (block.get("type") == "tool_use"
                    and tool_call is None):
                tool_call = {
                    "name": block.get("name", ""),
                    "input": block.get("input", {}),
                }

            elif block.get("type") == "text" and assistant_text is None:
                text = block.get("text", "").strip()
                if text:
                    assistant_text = text

        # Stop after first entry with useful content
        if ask_question or tool_call or assistant_text or exit_plan:
            break

    return _format_context(notification_type, ask_question, tool_call, assistant_text, exit_plan)


def _format_context(notification_type, ask_question, tool_call, assistant_text, exit_plan=False):
    """Route to the appropriate formatter based on notification type and context."""
    if exit_plan:
        return {
            "title": "Claude has a plan",
            "message": _truncate(assistant_text or "Plan ready for review.", 500),
            "tags": "clipboard",
            "priority": "high",
            "is_plan_approval": True,
        }

    if notification_type == "elicitation_dialog" and ask_question:
        title, body = _format_ask_question(ask_question)
        if title:
            options = [opt.get("label", "") for opt in ask_question.get("questions", [{}])[0].get("options", [])]
            return {
                "title": title,
                "message": _truncate(body, 500),
                "tags": "question",
                "priority": "high",
                "is_question": True,
                "options": options,
            }

    if notification_type == "idle_prompt" and assistant_text:
        return {
            "title": "Claude is waiting",
            "message": _truncate(assistant_text, 300),
            "tags": "hourglass",
            "priority": "default",
        }

    # For any notification type, try to show something useful as fallback
    if ask_question:
        title, body = _format_ask_question(ask_question)
        if title:
            options = [opt.get("label", "") for opt in ask_question.get("questions", [{}])[0].get("options", [])]
            return {
                "title": title,
                "message": _truncate(body, 500),
                "tags": "question",
                "priority": "high",
                "is_question": True,
                "options": options,
            }

    if assistant_text:
        return {
            "title": "Claude needs attention",
            "message": _truncate(assistant_text, 300),
            "tags": "speech_balloon",
            "priority": "default",
        }

    if tool_call:
        name = tool_call.get("name", "unknown")
        return {
            "title": f"Claude is using {name}",
            "message": _truncate(str(tool_call.get("input", "")), 200),
            "tags": "speech_balloon",
            "priority": "default",
        }

    return {}


# ─── HTTP Server ──────────────────────────────────────────────────────────────

class ActionHandler(BaseHTTPRequestHandler):
    base_url = ""

    def do_POST(self):
        global _plan_accept_terminal_pid, _plan_accept_timestamp
        global _question_terminal_pid, _question_timestamp
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""

        # ── Hook endpoints (called by hook scripts) ───────────────────────

        if path == "/hook/notification":
            data = json.loads(body) if body else {}
            ntype = data.get("notification_type", "")
            message = data.get("message", "")
            context = data.get("context_summary", {})

            if context:
                # Use enriched context from transcript
                title = context.get("title", data.get("title", "Claude Code"))
                message = context.get("message", message)
                tags = context.get("tags", "speech_balloon")
                priority = context.get("priority", "default")
            else:
                # Fallback to generic message
                title = data.get("title", "Claude Code")
                if ntype == "permission_prompt":
                    tags, priority = "bell", "high"
                elif ntype == "idle_prompt":
                    tags, priority = "hourglass", "default"
                else:
                    tags, priority = "speech_balloon", "default"

            actions = None

            # Plan approval: store terminal PID and add Accept button
            if context.get("is_plan_approval"):
                terminal_pid = data.get("terminal_pid")
                if terminal_pid:
                    with _plan_accept_lock:
                        _plan_accept_terminal_pid = terminal_pid
                        _plan_accept_timestamp = time.time()
                    actions = [
                        {"label": "Accept Plan", "url": f"{self.base_url}/plan/accept", "method": "POST"},
                    ]

            # Question: store terminal PID and add option buttons
            elif context.get("is_question"):
                terminal_pid = data.get("terminal_pid")
                options = context.get("options", [])
                if terminal_pid and options:
                    with _question_lock:
                        _question_terminal_pid = terminal_pid
                        _question_timestamp = time.time()
                    actions = []
                    for i, opt in enumerate(options[:3]):  # ntfy max 3 actions
                        actions.append({
                            "label": opt,
                            "url": f"{self.base_url}/question/select/{i}",
                            "method": "POST",
                        })

            send_notification(
                title=title,
                message=message,
                priority=priority,
                tags=tags,
                actions=actions,
            )
            self._respond(200, "{}")

        elif path == "/hook/stop":
            data = json.loads(body) if body else {}
            message = data.get("last_assistant_message", "")
            # Trim to a readable preview
            if len(message) > 400:
                message = message[:400] + "..."
            send_notification(
                title="Claude Code finished",
                message=message or "Task complete.",
                priority="default",
                tags="white_check_mark",
            )
            self._respond(200, "{}")

        elif path == "/hook/pre_tool_use":
            data = json.loads(body) if body else {}
            tool = data.get("tool_name", "unknown")
            tool_input = data.get("tool_input", {})

            # Auto-approve tools that don't need phone confirmation
            if not _needs_approval(tool, tool_input):
                self._respond(200, json.dumps({"decision": "approve"}), "application/json")
                return

            # This tool needs approval — notify phone and wait
            rid = create_pending_decision()
            message = _format_tool_preview(tool, tool_input)

            send_notification(
                title=f"Permission: {tool}",
                message=message,
                priority="urgent",
                tags="lock",
                actions=[
                    {"label": "Allow", "url": f"{self.base_url}/decide/{rid}/approve", "method": "POST"},
                    {"label": "Deny", "url": f"{self.base_url}/decide/{rid}/deny", "method": "POST"},
                ],
            )

            # Block until phone responds
            decision = wait_for_decision(rid)
            self._respond(200, json.dumps({"decision": decision}), "application/json")

        # ── Phone action endpoints (called by ntfy action buttons) ────────

        elif path == "/plan/accept":
            with _plan_accept_lock:
                terminal_pid = _plan_accept_terminal_pid
                timestamp = _plan_accept_timestamp
                _plan_accept_terminal_pid = None  # one-shot: clear immediately

            if not terminal_pid:
                self._respond(200, "\u26a0\ufe0f No pending plan to accept")
                return

            if time.time() - timestamp > _PLAN_ACCEPT_STALENESS:
                self._respond(200, "\u23f0 Plan accept expired (>5 min)")
                return

            if _send_keys_to_terminal(terminal_pid):
                self._respond(200, "\u2705 Plan accepted!")
            else:
                self._respond(200, "\u274c Failed to send Enter to terminal")

        elif path.startswith("/question/select/"):
            try:
                index = int(path.split("/")[-1])
            except ValueError:
                self._respond(400, "Bad request")
                return

            with _question_lock:
                terminal_pid = _question_terminal_pid
                timestamp = _question_timestamp
                _question_terminal_pid = None  # one-shot: clear immediately

            if not terminal_pid:
                self._respond(200, "\u26a0\ufe0f No pending question")
                return

            if time.time() - timestamp > _PLAN_ACCEPT_STALENESS:
                self._respond(200, "\u23f0 Question expired (>5 min)")
                return

            keys = "{DOWN}" * index + "{ENTER}"
            if _send_keys_to_terminal(terminal_pid, keys):
                self._respond(200, f"\u2705 Selected option {index + 1}")
            else:
                self._respond(200, "\u274c Failed to send selection")

        elif path.startswith("/decide/"):
            parts = path.split("/")
            # /decide/{rid}/{decision}
            if len(parts) == 4:
                rid, decision = parts[2], parts[3]
                resolve_decision(rid, decision)
                emoji = "\u2705" if decision == "approve" else "\u274c"
                self._respond(200, f"{emoji} {decision}")
            else:
                self._respond(400, "Bad request")

        elif path == "/health":
            self._respond(200, "ok")

        else:
            self._respond(404, "Not found")

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, "ok")
        else:
            self._respond(404, "Not found")

    def _respond(self, code, msg, content_type="text/plain"):
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(msg.encode())
        except (ConnectionResetError, BrokenPipeError):
            log.warning("Client disconnected before response was sent")

    def log_message(self, *a):
        pass


# ─── Hook Script Mode ─────────────────────────────────────────────────────────
# When called with --hook, this script acts as the hook handler.
# It reads JSON from stdin, POSTs to the server, and returns the response.

_LOCK_PATH = os.path.join(os.path.expanduser("~"), ".claude-ntfy-hook.lock")


@contextlib.contextmanager
def _startup_lock():
    """Acquire an OS-level file lock to serialize server auto-start.

    Yields True if the lock was acquired (caller should check & spawn),
    or False if another process already holds it (caller should just wait).
    The lock is released when the context exits.
    """
    fd = None
    acquired = False
    try:
        fd = os.open(_LOCK_PATH, os.O_CREAT | os.O_RDWR)
        if IS_WINDOWS:
            import msvcrt
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError:
                acquired = False
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError:
                acquired = False
        yield acquired
    finally:
        if fd is not None:
            if acquired:
                if IS_WINDOWS:
                    import msvcrt
                    try:
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                # fcntl locks auto-release on close
            os.close(fd)


def _server_is_running(server_url: str) -> bool:
    """Quick health check to see if the server is up."""
    try:
        return requests.get(f"{server_url}/health", timeout=2).status_code == 200
    except Exception:
        return False


def _auto_start_server(server_url: str):
    """Spawn the server in the background if it's not already running.

    Uses an OS-level file lock to prevent multiple hook processes from
    each spawning a server on cold start.
    """
    # Fast path — no lock needed if already running
    if _server_is_running(server_url):
        return

    with _startup_lock() as acquired:
        if acquired:
            # Re-check inside the lock (another process may have started it)
            if _server_is_running(server_url):
                return

            parsed = urlparse(server_url)
            port = parsed.port or HTTP_PORT

            topic = NTFY_TOPIC or _generate_topic()
            script_path = os.path.abspath(__file__).replace("\\", "/")
            log_file = os.path.join(os.path.expanduser("~"), ".claude-ntfy-hook.log")
            cmd = [
                sys.executable, script_path, "server",
                "--port", str(port),
                "--topic", topic,
                "--ntfy-server", NTFY_SERVER,
            ]

            if IS_WINDOWS:
                CREATE_NEW_CONSOLE = 0x00000010
                subprocess.Popen(cmd, creationflags=CREATE_NEW_CONSOLE)
            else:
                subprocess.Popen(cmd, start_new_session=True)

            # Wait for it to come up
            for _ in range(10):
                time.sleep(0.5)
                if _server_is_running(server_url):
                    msg = f"Auto-started server\n  topic: {topic}\n  log:   {log_file}"
                    print(msg, file=sys.stderr)
                    return

            print("Warning: server did not start in time", file=sys.stderr)
        else:
            # Another hook process is handling startup — just wait for the server
            for _ in range(15):
                time.sleep(0.5)
                if _server_is_running(server_url):
                    return
            print("Warning: server did not start in time (waited for lock holder)", file=sys.stderr)


def run_as_hook(hook_type: str, server_url: str):
    """Called by Claude Code as a hook. Reads stdin, calls server, returns response."""
    input_data = json.loads(sys.stdin.read()) if not sys.stdin.isatty() else {}

    # Auto-start the server if it's not running
    _auto_start_server(server_url)

    # Enrich notification data with transcript context
    if hook_type == "notification":
        transcript_path = input_data.get("transcript_path", "")
        if transcript_path and os.path.isfile(transcript_path):
            try:
                context = _extract_context_summary(
                    transcript_path,
                    input_data.get("notification_type", ""),
                )
                if context:
                    input_data["context_summary"] = context
                    # For plan approvals and questions, find the terminal PID
                    # so the server can send keystrokes from the phone
                    if context.get("is_plan_approval") or context.get("is_question"):
                        terminal_pid = _find_terminal_pid()
                        if terminal_pid:
                            input_data["terminal_pid"] = terminal_pid
            except Exception:
                pass  # Fall back to generic message

    # Only pre_tool_use needs to block waiting for phone response
    timeout = PERMISSION_TIMEOUT + 10 if hook_type == "pre_tool_use" else 15

    try:
        resp = requests.post(
            f"{server_url}/hook/{hook_type}",
            json=input_data,
            timeout=timeout,
        )
        # For pre_tool_use: exit code 2 = block, exit code 0 = allow
        if hook_type == "pre_tool_use":
            result = resp.json() if resp.text else {}
            decision = result.get("decision", "approve")
            if decision == "deny":
                print("Denied from phone", file=sys.stderr)
                sys.exit(2)
            # Approved — exit 0
            print(resp.text)
        else:
            print(resp.text)
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        # On error, don't block Claude Code
        if hook_type == "pre_tool_use":
            print(json.dumps({"decision": "approve"}))
        else:
            print("{}")


# ─── Server Mode ──────────────────────────────────────────────────────────────

def run_server(args):
    global NTFY_TOPIC, NTFY_SERVER, TAILSCALE_IP

    NTFY_TOPIC = args.topic
    NTFY_SERVER = args.ntfy_server
    if args.ts_ip:
        TAILSCALE_IP = args.ts_ip

    ts_ip = get_tailscale_ip()
    base_url = f"http://{ts_ip}:{args.port}"
    ActionHandler.base_url = base_url

    # Persist topic to a file for easy reference
    topic_file = os.path.join(os.path.expanduser("~"), ".claude-ntfy-hook-topic")
    with open(topic_file, "w") as f:
        f.write(NTFY_TOPIC)

    log.info("=" * 60)
    log.info("Claude Code Notification Server")
    log.info(f"  ntfy topic:   {NTFY_TOPIC}")
    log.info(f"  Callback URL: {base_url}")
    log.info(f"  Timeout:      {PERMISSION_TIMEOUT}s")
    log.info("=" * 60)

    # Print the settings.json config for the user
    settings = _build_hook_settings(base_url)

    log.info("")
    log.info("Add this to your .claude/settings.json:")
    log.info("")
    log.info(json.dumps(settings, indent=2))
    log.info("")

    # Send test notification
    send_notification(
        title="Claude Notify server started",
        message=f"Listening on {base_url}\nReady for hooks.",
        priority="low",
        tags="rocket",
    )

    try:
        server = ThreadingHTTPServer(("0.0.0.0", args.port), ActionHandler)
    except OSError as e:
        log.warning(f"Cannot bind port {args.port}: {e} — another instance is likely running")
        raise SystemExit(0)

    log.info(f"Listening on :{args.port} — Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Claude Code ntfy notifications via hooks")
    sub = parser.add_subparsers(dest="mode")

    # Server mode (default)
    srv = sub.add_parser("server", help="Run the notification server")
    default_topic = NTFY_TOPIC or _generate_topic()
    srv.add_argument("--topic", default=default_topic, help=f"ntfy topic (default: {default_topic})")
    srv.add_argument("--port", type=int, default=HTTP_PORT, help="HTTP port")
    srv.add_argument("--ntfy-server", default=NTFY_SERVER, help="ntfy server URL")
    srv.add_argument("--ts-ip", default=None, help="Tailscale IP override")

    # Settings toggle mode
    hooks = sub.add_parser("hooks", help="Add or remove claude-notify hooks in settings.json")
    hooks.add_argument("toggle", choices=["add", "remove"], help="Whether to add or remove managed hooks")
    hooks.add_argument(
        "--settings-file",
        default=USER_CLAUDE_SETTINGS_PATH,
        help=f"Path to Claude settings file (default: {USER_CLAUDE_SETTINGS_PATH})",
    )
    hooks.add_argument(
        "--server-url",
        default=None,
        help="Server URL embedded in added hook commands (default: auto-detected Tailscale IP)",
    )
    # Hook mode (called by Claude Code)
    parser.add_argument("--hook", choices=["notification", "pre_tool_use", "stop"],
                        help="Run as hook handler (called by Claude Code)")
    parser.add_argument("--server", default=f"http://localhost:{HTTP_PORT}",
                        help="Server URL when running as hook")

    args = parser.parse_args()

    if args.hook:
        run_as_hook(args.hook, args.server)
    elif args.mode == "hooks":
        run_hook_toggle(args)
    elif args.mode == "server" or args.mode is None:
        # Default to server mode — fill in defaults when no subcommand given
        args.topic = getattr(args, "topic", None) or _generate_topic()
        args.port = getattr(args, "port", HTTP_PORT)
        args.ntfy_server = getattr(args, "ntfy_server", NTFY_SERVER)
        args.ts_ip = getattr(args, "ts_ip", None)
        run_server(args)


if __name__ == "__main__":
    main()
