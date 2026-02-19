# claude-ntfy-hook

Push notifications for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) on your phone via [ntfy](https://ntfy.sh), with interactive **Allow/Deny** buttons for tool approval over [Tailscale](https://tailscale.com).

No PTY wrapping, no regex matching — uses Claude Code's native [hook system](https://docs.anthropic.com/en/docs/claude-code/hooks).

```
Claude Code ──hook──▶ claude-notify.py --hook ──▶ server ──▶ ntfy ──▶ Phone
                                                    ▲                    │
                                                    └──── Tailscale ─────┘
```

## Features

- **Phone notifications** when Claude Code finishes, needs input, or requests tool permission
- **Allow/Deny from your phone** — approve or block tool calls remotely via ntfy action buttons
- **Reads your Claude Code permissions** — only prompts for tools in your `ask` list, auto-approves everything else
- **Auto-starts the server** — the hook spawns the server in the background if it's not running
- **Markdown-formatted** notifications with tool-specific previews (commands, file paths, diffs)
- **Works on Windows, macOS, and Linux**

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (Python package runner)
- [Tailscale](https://tailscale.com) on both your machine and phone
- [ntfy app](https://ntfy.sh) on your phone

## Quick Start

### 1. Start the server

```bash
uv run claude-notify.py server
```

The server will:
- Auto-detect your Tailscale IP
- Generate a unique ntfy topic (based on your username and hostname)
- Print the `settings.json` hook configuration to copy
- Send a test notification to verify everything works

### 2. Subscribe on your phone

Open the ntfy app and subscribe to the topic shown in the server output (e.g. `claude-ntfy-hook-a1b2c3d4e5f6`).

### 3. Add hooks to Claude Code

Copy the hook configuration printed by the server into your `~/.claude/settings.json`. It will look like:

```json
{
  "hooks": {
    "Notification": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "uv run /path/to/claude-notify.py --hook notification --server http://<tailscale-ip>:8787"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "uv run /path/to/claude-notify.py --hook pre_tool_use --server http://<tailscale-ip>:8787"
          }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "uv run /path/to/claude-notify.py --hook stop --server http://<tailscale-ip>:8787"
          }
        ]
      }
    ]
  }
}
```

### 4. Use Claude Code normally

You'll receive notifications when:

| Event | Notification |
|---|---|
| **Tool needs approval** | Urgent push with Allow/Deny buttons |
| **Claude finishes** | Summary of Claude's last message |
| **Permission prompt** | Claude is waiting for input |
| **Idle** | Claude has been idle for 60+ seconds |

## Permission Integration

The hook reads your `permissions` from `~/.claude/settings.json` and only sends phone notifications for tools matching your `ask` rules. Everything in `allow` is auto-approved silently, and `deny` is handled by Claude Code itself.

```json
{
  "permissions": {
    "allow": ["Edit(*)", "Bash(git *)"],
    "ask": ["Bash(rm *)", "Bash(git push *)"],
    "deny": ["Read(.env)"]
  }
}
```

With this config:
- `git status` → auto-approved, no notification
- `rm -rf /tmp/foo` → phone notification with Allow/Deny
- `git push origin main` → phone notification with Allow/Deny

## Server Options

```
uv run claude-notify.py server [OPTIONS]

Options:
  --topic TOPIC          ntfy topic (auto-generated if not provided)
  --port PORT            HTTP port (default: 8787)
  --ntfy-server URL      ntfy server URL (default: https://ntfy.sh)
  --ts-ip IP             Tailscale IP override (auto-detected if not provided)
```

## How It Works

1. Claude Code fires a hook event (PreToolUse, Notification, or Stop)
2. The hook script (`--hook` mode) reads the event JSON from stdin
3. It checks if the server is running, auto-starts it if needed
4. Posts the event to the server over Tailscale
5. For `PreToolUse` with `ask` rules: server sends an ntfy notification with Allow/Deny action buttons, then blocks waiting for a response
6. You tap Allow or Deny on your phone → ntfy posts back to the server over Tailscale
7. Server unblocks and returns the decision to the hook script
8. Hook exits with code 0 (allow) or code 2 (block)

## License

MIT
