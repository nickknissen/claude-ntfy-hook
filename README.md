# claude-ntfy-hook

Approve or deny Claude Code tool calls from your phone.

Uses [ntfy](https://ntfy.sh) for push notifications and [Tailscale](https://tailscale.com) for secure callbacks — all wired up through Claude Code's native [hook system](https://docs.anthropic.com/en/docs/claude-code/hooks). No PTY wrapping, no regex matching.

```
Claude Code ──hook──> claude-notify.py --hook ──> server ──> ntfy ──> Phone
                                                    ^                   |
                                                    +--- Tailscale -----+
```

## What You Get

- **Allow/Deny from your phone** — tap a button on a push notification to approve or block a tool call
- **Accept plans remotely** — tap "Accept Plan" to approve Claude's plan from your phone (Windows)
- **Smart filtering** — reads your Claude Code `ask`/`allow`/`deny` rules, only bothers you when it matters
- **Context-aware notifications** — parses the Claude transcript to show actual question text, plan details, and tool previews instead of generic messages
- **Zero setup server** — auto-starts in its own terminal window the first time a hook fires
- **Reliable delivery** — retries failed notifications with exponential backoff (handles ntfy outages, network blips, rate limits)
- **Rich notifications** — markdown-formatted previews of commands, file paths, and diffs
- **Stop notifications** — get pinged when Claude finishes with a summary of what it said
- **Cross-platform** — Windows, macOS, and Linux

## Prerequisites

- [uv](https://docs.astral.sh/uv/) — runs the script with dependencies, no install needed
- [Tailscale](https://tailscale.com) — on both your machine and phone
- [ntfy](https://ntfy.sh) — app on your phone (free)

## Setup

### 1. Run the server once to get your config

```bash
uv run claude-notify.py server
```

This will:
- Auto-detect your Tailscale IP
- Generate a unique ntfy topic (`claude-ntfy-hook-<hash>`)
- Print the exact `settings.json` hooks config to copy
- Send a test notification to verify the connection

### 2. Subscribe on your phone

Open the ntfy app and subscribe to the topic from the server output. You can always find it again:

```bash
cat ~/.claude-ntfy-hook-topic
```

### 3. Add hooks to Claude Code

Paste the config from step 1 into `~/.claude/settings.json`:

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

### 4. Done

Use Claude Code normally. The server auto-starts when needed — you don't have to keep it running manually.

| What happens | What you see on your phone |
|---|---|
| Claude wants to run `rm -rf /tmp/foo` | Push notification with **Allow** / **Deny** buttons |
| Claude asks a question | The actual question text and options |
| Claude has a plan for approval | Plan summary with an **Accept Plan** button |
| Claude finishes a task | Summary of its last message |
| Claude is waiting for input | Notification that it needs attention |

## Permission Integration

The hook reads your `permissions` from `~/.claude/settings.json` and only sends phone prompts for tools in your `ask` list. Everything else is handled silently.

```json
{
  "permissions": {
    "allow": ["Edit(*)", "Bash(git *)"],
    "ask": ["Bash(rm *)", "Bash(git push *)"],
    "deny": ["Read(.env)"]
  }
}
```

| Command | Result |
|---|---|
| `git status` | Auto-approved, no notification |
| `rm -rf /tmp/foo` | Phone notification with Allow/Deny |
| `git push origin main` | Phone notification with Allow/Deny |
| `cat .env` | Blocked by Claude Code, hook never fires |

## Server Options

```
uv run claude-notify.py server [OPTIONS]

  --topic TOPIC          ntfy topic (auto-generated if omitted)
  --port PORT            HTTP port (default: 8787)
  --ntfy-server URL      ntfy server (default: https://ntfy.sh)
  --ts-ip IP             Override Tailscale IP auto-detection
```

## How It Works

1. Claude Code fires a hook (PreToolUse, Notification, or Stop)
2. The hook script checks if the server is running — auto-starts it if not (with file locking to prevent races)
3. For Notification hooks, the script reads the Claude transcript to extract context (question text, plan details, last assistant message)
4. Posts the event to the server over your Tailscale network
5. For tools in your `ask` list: sends an ntfy push with Allow/Deny action buttons and blocks
6. You tap a button on your phone — ntfy POSTs back to the server over Tailscale
7. Server unblocks, hook exits with code 0 (allow) or 2 (block)
8. Claude Code proceeds or stops accordingly

If ntfy is temporarily unavailable, notifications are retried up to 3 times with exponential backoff (1s, 3s) before giving up.

## License

[MIT](LICENSE)
