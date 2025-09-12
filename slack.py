#!/usr/bin/env python3
"""
slack_bot_tool.py

Actions:
  --check_valid          : verify token with a benign API call
  --check_valid_bulk     : verify MANY tokens from --tokens-file (newline/CR/CRLF separated)
  --get_channels         : list channels the bot can see
  --get_messages         : last 10 messages (requires --channel)
  --get_rights           : summarize rights in context of a channel (requires --channel)
  --dump_messages        : dump channel messages to file over a timeframe (requires --channel)
                           optional: --timeframe <weeks> (default: 1)

Channel can be provided as channel ID (e.g., C0123..., G0123...) or by name (e.g., general).
"""

import argparse
import os
import sys
import time
import json
import re
from datetime import datetime, timedelta, timezone
import requests

API_BASE = "https://slack.com/api"

def slack_call(token, method, params=None, http_method="GET"):
    """Call Slack Web API with basic 429 handling."""
    url = f"{API_BASE}/{method}"
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(5):
        if http_method == "GET":
            r = requests.get(url, headers=headers, params=params or {}, timeout=30)
        else:
            # Slack prefers application/x-www-form-urlencoded for many endpoints,
            # but JSON works for most read ops too. We'll default to form to be safe.
            r = requests.post(
                url,
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data=params or {},
                timeout=30,
            )
        if r.status_code == 429:
            retry = int(r.headers.get("Retry-After", "1"))
            time.sleep(retry)
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError("Slack API rate limited too many times")

def get_bot_user_id(token):
    data = slack_call(token, "auth.test", http_method="POST")
    if not data.get("ok"):
        raise RuntimeError(f"auth.test failed: {data}")
    return data["user_id"]

def list_channels(token, types="public_channel,private_channel"):
    """Return list of channels the token can see. Each item includes id + name + is_private, etc."""
    channels = []
    cursor = None
    while True:
        params = {"limit": 1000, "types": types}
        if cursor:
            params["cursor"] = cursor
        data = slack_call(token, "conversations.list", params, http_method="GET")
        if not data.get("ok"):
            raise RuntimeError(f"conversations.list failed: {data}")
        channels.extend(data.get("channels", []))
        cursor = (data.get("response_metadata") or {}).get("next_cursor")
        if not cursor:
            break
    return channels

def resolve_channel_id(token, channel_arg):
    """Resolve channel id from ID or name ('general')."""
    if not channel_arg:
        raise ValueError("--channel is required")
    # If it looks like an ID, use as-is
    if re.match(r"^[CGD][A-Z0-9]{8,}$", channel_arg):
        return channel_arg, channel_arg
    # Otherwise, search by name
    wanted = channel_arg.lstrip("#").lower()
    for ch in list_channels(token):
        name = ch.get("name") or ch.get("name_normalized") or ""
        if name.lower() == wanted:
            return ch["id"], name
    raise ValueError(f"Channel '{channel_arg}' not found. Use channel ID or name.")

def get_channel_info(token, channel_id):
    data = slack_call(token, "conversations.info", {"channel": channel_id}, http_method="GET")
    if not data.get("ok"):
        raise RuntimeError(f"conversations.info failed: {data}")
    return data["channel"]

def is_bot_member(token, channel_id, bot_user_id):
    """Check membership by scanning members (paged)."""
    cursor = None
    while True:
        params = {"channel": channel_id, "limit": 1000}
        if cursor:
            params["cursor"] = cursor
        data = slack_call(token, "conversations.members", params, http_method="GET")
        if not data.get("ok"):
            # If we can't list members (scope), fallback to info field if present
            info = get_channel_info(token, channel_id)
            return bool(info.get("is_member"))
        members = data.get("members", [])
        if bot_user_id in members:
            return True
        cursor = (data.get("response_metadata") or {}).get("next_cursor")
        if not cursor:
            break
    return False

def get_token_scopes(token):
    """Return dict with 'scopes' & 'accepted_scopes' via auth.scopes (works with bot tokens)."""
    data = slack_call(token, "auth.scopes", http_method="GET")
    if not data.get("ok"):
        # fallback: empty set
        return {"scopes": [], "accepted_scopes": []}
    return {"scopes": data.get("scopes", []), "accepted_scopes": data.get("accepted_scopes", [])}

def get_last_messages(token, channel_id, limit=10):
    params = {"channel": channel_id, "limit": limit, "include_all_metadata": True}
    data = slack_call(token, "conversations.history", params, http_method="GET")
    if not data.get("ok"):
        raise RuntimeError(f"conversations.history failed: {data}")
    return data.get("messages", [])

def iter_history(token, channel_id, oldest_ts=None):
    """Yield messages from latest backwards, paging until oldest reached."""
    cursor = None
    while True:
        params = {"channel": channel_id, "limit": 1000, "include_all_metadata": True}
        if cursor:
            params["cursor"] = cursor
        if oldest_ts:
            params["oldest"] = f"{oldest_ts:.6f}"
        data = slack_call(token, "conversations.history", params, http_method="GET")
        if not data.get("ok"):
            raise RuntimeError(f"conversations.history failed: {data}")
        msgs = data.get("messages", [])
        for m in msgs:
            yield m
        cursor = (data.get("response_metadata") or {}).get("next_cursor")
        if not cursor or not msgs:
            break

def dump_messages(token, channel_id, channel_label, weeks=1):
    # timeframe oldest
    now = datetime.now(timezone.utc)
    oldest = now - timedelta(weeks=max(1, weeks))
    oldest_ts = oldest.timestamp()

    out_name = f"{channel_label}_dump_{weeks}w.jsonl"
    # sanitize filename
    out_name = re.sub(r"[^A-Za-z0-9._-]", "_", out_name)

    count = 0
    with open(out_name, "w", encoding="utf-8") as f:
        for msg in iter_history(token, channel_id, oldest_ts=oldest_ts):
            f.write(json.dumps(msg, ensure_ascii=False) + "\n")
            count += 1
    return out_name, count

# --------- NEW: bulk token helpers ---------

def _read_tokens_file(path):
    """Read tokens from file (newline/CR/CRLF). Blank lines and lines starting with # are ignored."""
    toks = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh.read().splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            toks.append(s)
    return toks

def _mask_token(t):
    """Mask a token for safer logging: keep first 6 and last 4 chars when long enough."""
    if not t:
        return ""
    if len(t) <= 12:
        return t[0:2] + "***"
    return f"{t[:6]}...{t[-4:]}"

def main():
    p = argparse.ArgumentParser(description="Slack bot token helper")
    # NOTE: --token is NOT required globally (bulk mode uses --tokens-file instead)
    p.add_argument("--token", help="Slack bot token (xoxb-...)")
    
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--check_valid", action="store_true", help="Check token validity")
    g.add_argument("--check_valid_bulk", action="store_true", help="Check MANY tokens from --tokens-file")
    g.add_argument("--get_channels", action="store_true", help="List channels")
    g.add_argument("--get_messages", action="store_true", help="Get last 10 messages from --channel")
    g.add_argument("--get_rights", action="store_true", help="Show rights context for --channel")
    g.add_argument("--dump_messages", action="store_true", help="Dump messages from --channel over timeframe")
    
    p.add_argument(
        "--channel_types",
        default="public_channel,private_channel",
        help=("Comma-separated conversation types for conversations.list "
              "(e.g. public_channel,private_channel,im,mpim). "
              "Default: public_channel,private_channel"),
    )

    # NEW: bulk input/output options
    p.add_argument("--tokens-file", help="Path to file with one token per line (used with --check_valid_bulk)")
    p.add_argument("--out", help="Write bulk results to this JSONL file (one JSON object per line)")
    p.add_argument("--show-tokens", action="store_true", help="Include raw tokens in output (default masks them)")

    p.add_argument("--channel", help="Channel ID (C?/G?/D?) or name (e.g. general) when required")
    p.add_argument("--timeframe", type=int, default=1, help="Weeks of history for --dump_messages (default 1)")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON output where applicable")

    args = p.parse_args()

    try:
        # ------- single-token check -------
        if args.check_valid:
            if not args.token:
                raise ValueError("--token is required for --check_valid")
            data = slack_call(args.token, "auth.test", http_method="POST")
            print(json.dumps(data, indent=2) if args.pretty else json.dumps(data))
            return

        # ------- bulk token check -------
        if args.check_valid_bulk:
            if not args.tokens_file:
                raise ValueError("--tokens-file is required for --check_valid_bulk")
            tokens = _read_tokens_file(args.tokens_file)
            if not tokens:
                raise ValueError(f"No tokens found in {args.tokens_file}")

            # Prepare output sink (stdout or JSONL file)
            outfh = None
            try:
                if args.out:
                    outfh = open(args.out, "w", encoding="utf-8")

                for tok in tokens:
                    result = {"ok": False}
                    try:
                        resp = slack_call(tok, "auth.test", http_method="POST")
                        # Slack returns ok:false with error string for invalid tokens (HTTP 200)
                        result = {
                            "ok": bool(resp.get("ok")),
                            "error": resp.get("error"),
                            "team": resp.get("team"),
                            "team_id": resp.get("team_id"),
                            "user_id": resp.get("user_id"),
                            "url": resp.get("url"),
                        }
                    except Exception as e:
                        result = {"ok": False, "error": str(e)}

                    # token display (masked by default)
                    if args.show_tokens:
                        result["token"] = tok
                    else:
                        result["token_masked"] = _mask_token(tok)

                    line = json.dumps(result, ensure_ascii=False)
                    if outfh:
                        outfh.write(line + "\n")
                    else:
                        print(line)
            finally:
                if outfh:
                    outfh.close()
            # Done
            return

        # ------- everything below requires a single token -------
        if not args.token:
            raise ValueError("--token is required for this action")

        token = args.token

        if args.get_channels:
            chans = list_channels(token, args.channel_types)
            out = [{"id": c["id"], "name": c.get("name"), "is_private": c.get("is_private")} for c in chans]
            print(json.dumps(out, indent=2) if args.pretty else json.dumps(out))
            return

        if args.get_messages:
            if not args.channel:
                raise ValueError("--channel is required for --get_messages")
            ch_id, ch_label = resolve_channel_id(token, args.channel)
            msgs = get_last_messages(token, ch_id, limit=10)
            print(json.dumps(msgs, indent=2) if args.pretty else json.dumps(msgs))
            return

        if args.get_rights:
            if not args.channel:
                raise ValueError("--channel is required for --get_rights")
            ch_id, ch_label = resolve_channel_id(token, args.channel)
            bot_id = get_bot_user_id(token)
            scopes = get_token_scopes(token)
            info = get_channel_info(token, ch_id)
            member = is_bot_member(token, ch_id, bot_id)

            token_scopes = set(scopes.get("scopes", []))
            can_read = (
                "channels:history" in token_scopes
                or "groups:history" in token_scopes
                or "conversations.history:read" in token_scopes
                or "conversations.history" in token_scopes
            )
            can_post = ("chat:write" in token_scopes or "chat:write.public" in token_scopes) and member

            result = {
                "channel": {"id": ch_id, "name": info.get("name"), "is_private": info.get("is_private")},
                "bot_user_id": bot_id,
                "is_member": member,
                "scopes": sorted(token_scopes),
                "inferred_rights": {
                    "can_read_history": bool(can_read and member) if info.get("is_private") else bool(can_read),
                    "can_post_messages": bool(can_post),
                },
            }
            print(json.dumps(result, indent=2) if args.pretty else json.dumps(result))
            return

        if args.dump_messages:
            if not args.channel:
                raise ValueError("--channel is required for --dump_messages")
            ch_id, ch_label = resolve_channel_id(token, args.channel)
            out_name, count = dump_messages(token, ch_id, ch_label, weeks=args.timeframe)
            result = {"output_file": out_name, "messages_written": count}
            print(json.dumps(result, indent=2) if args.pretty else json.dumps(result))
            return

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
