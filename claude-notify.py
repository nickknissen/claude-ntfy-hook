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
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from datetime import datetime
import platform
import re

import requests

IS_WINDOWS = platform.system() == "Windows"

# ─── Configuration ────────────────────────────────────────────────────────────

NTFY_TOPIC = None  # Auto-generated if not provided
NTFY_SERVER = "https://ntfy.sh"
HTTP_PORT = 8787
TAILSCALE_IP = None  # Auto-detect if None
PERMISSION_TIMEOUT = 300  # seconds to wait for remote allow/deny

import fnmatch as _fnmatch
import hashlib


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
    headers = {"Title": title, "Priority": priority, "Tags": tags}
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

    try:
        requests.post(
            f"{NTFY_SERVER}/{NTFY_TOPIC}",
            data=message.encode("utf-8"),
            headers=headers,
            timeout=10,
        )
        log.info(f"Sent: {title}")
    except Exception as e:
        log.error(f"Notification failed: {e}")


# ─── Permission Decision State ────────────────────────────────────────────────
# PreToolUse hooks block until we get a decision from the phone.

pending_decisions = {}  # request_id -> threading.Event
decision_results = {}   # request_id -> "approve" | "deny"
decision_lock = threading.Lock()
request_counter = 0


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


# ─── Permission Matching (reads from Claude Code settings.json) ──────────────

def _load_permissions() -> dict:
    """Load permission rules from Claude Code settings.json."""
    paths = [
        os.path.expanduser("~/.claude/settings.json"),
        os.path.join(".claude", "settings.json"),
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


# ─── HTTP Server ──────────────────────────────────────────────────────────────

class ActionHandler(BaseHTTPRequestHandler):
    base_url = ""

    def do_POST(self):
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""

        # ── Hook endpoints (called by hook scripts) ───────────────────────

        if path == "/hook/notification":
            data = json.loads(body) if body else {}
            ntype = data.get("notification_type", "")
            message = data.get("message", "")

            # Pick tag/priority based on notification type
            if ntype == "permission_prompt":
                tags, priority = "bell", "high"
            elif ntype == "idle_prompt":
                tags, priority = "hourglass", "default"
            else:
                tags, priority = "speech_balloon", "default"

            send_notification(
                title=data.get("title", "Claude Code"),
                message=message,
                priority=priority,
                tags=tags,
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

def _server_is_running(server_url: str) -> bool:
    """Quick health check to see if the server is up."""
    try:
        return requests.get(f"{server_url}/health", timeout=2).status_code == 200
    except Exception:
        return False


def _auto_start_server(server_url: str):
    """Spawn the server in the background if it's not already running."""
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

    # Spawn the server in its own visible terminal window
    if IS_WINDOWS:
        CREATE_NEW_CONSOLE = 0x00000010
        subprocess.Popen(
            cmd,
            creationflags=CREATE_NEW_CONSOLE,
        )
    else:
        subprocess.Popen(
            cmd,
            start_new_session=True,
        )

    # Wait for it to come up
    for _ in range(10):
        time.sleep(0.5)
        if _server_is_running(server_url):
            msg = f"Auto-started server\n  topic: {topic}\n  log:   {log_file}"
            print(msg, file=sys.stderr)
            return

    print("Warning: server did not start in time", file=sys.stderr)


def run_as_hook(hook_type: str, server_url: str):
    """Called by Claude Code as a hook. Reads stdin, calls server, returns response."""
    input_data = json.loads(sys.stdin.read()) if not sys.stdin.isatty() else {}

    # Auto-start the server if it's not running
    _auto_start_server(server_url)

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
    # Forward slashes so uv/shell doesn't eat Windows backslashes
    script_path = os.path.abspath(__file__).replace("\\", "/")
    hook_cmd = f"uv run {script_path}"

    settings = {
        "hooks": {
            "Notification": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{hook_cmd} --hook notification --server {base_url}",
                        }
                    ],
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{hook_cmd} --hook pre_tool_use --server {base_url}",
                        }
                    ],
                }
            ],
            "Stop": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{hook_cmd} --hook stop --server {base_url}",
                        }
                    ],
                }
            ],
        }
    }

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

    server = ThreadingHTTPServer(("0.0.0.0", args.port), ActionHandler)
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

    # Hook mode (called by Claude Code)
    parser.add_argument("--hook", choices=["notification", "pre_tool_use", "stop"],
                        help="Run as hook handler (called by Claude Code)")
    parser.add_argument("--server", default=f"http://localhost:{HTTP_PORT}",
                        help="Server URL when running as hook")

    args = parser.parse_args()

    if args.hook:
        run_as_hook(args.hook, args.server)
    elif args.mode == "server" or args.mode is None:
        # Default to server mode — fill in defaults when no subcommand given
        args.topic = getattr(args, "topic", None) or _generate_topic()
        args.port = getattr(args, "port", HTTP_PORT)
        args.ntfy_server = getattr(args, "ntfy_server", NTFY_SERVER)
        args.ts_ip = getattr(args, "ts_ip", None)
        run_server(args)


if __name__ == "__main__":
    main()
