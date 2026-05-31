
#!/usr/bin/env python3
"""
IRCv3 Source Code Analyzer

Analyzes a source code file for IRCv3 protocol support, identifies
which IRCv3 features are implemented vs. missing, and assigns a
support percentile score.

Usage: python ircv3analyzer.py <source_file.py>
"""

import re
import sys
import ast
from pathlib import Path

# --─ IRCv3 Capability & Feature Registry ----------------------------------─

IRCV3_FEATURES = {
    # -- Core IRCv3.1 --
    "cap": {
        "name": "CAP (Capability Negotiation)",
        "spec": "ircv3.1",
        "patterns": [r"\bCAP\b", r"cap_ls", r"cap_req", r"cap_ack", r"cap_nak",
                     r"cap_end", r"cap_list", r"cap_new", r"cap_del",
                     r"capability.*negot", r"cap_negotiation"],
        "commands": ["CAP LS", "CAP REQ", "CAP ACK", "CAP NAK", "CAP END",
                     "CAP LIST", "CAP NEW", "CAP DEL"],
    },
    "sasl": {
        "name": "SASL Authentication",
        "spec": "ircv3.1",
        "patterns": [r"[\"\']SASL[\"\']", r"sasl", r"AUTHENTICATE",
                     r"authenticate", r"sasl_auth", r"sasl_mechanism"],
        "commands": ["AUTHENTICATE"],
    },
    "message_tags": {
        "name": "Message Tags",
        "spec": "ircv3.2",
        "patterns": [r"message.?tags?", r"msg.?tags?", r"@\w+=", r"parse.*tags?",
                     r"tag.*parser", r"tagmsg", r"TAGMSG"],
        "commands": ["TAGMSG"],
    },
    "server_time": {
        "name": "Server Time",
        "spec": "ircv3.2",
        "patterns": [r"server.?time", r"server_time", r"time=[\dTZ:\-\.\+]+",
                     r"@time="],
    },
    "batch": {
        "name": "Batch",
        "spec": "ircv3.2",
        "patterns": [r"\bBATCH\b", r"batch", r"batch_type", r"batch_ref"],
        "commands": ["BATCH"],
    },
    "account_tag": {
        "name": "Account Tag",
        "spec": "ircv3.2",
        "patterns": [r"account.?tag", r"account_tag", r"@account=",
                     r"account.*notify", r"account_notify"],
    },
    "account_notify": {
        "name": "Account Notify",
        "spec": "ircv3.2",
        "patterns": [r"account.?notify", r"account_notify", r"ACCOUNT\b",
                     r"account.*notif"],
        "commands": ["ACCOUNT"],
    },
    "away_notify": {
        "name": "Away Notify",
        "spec": "ircv3.2",
        "patterns": [r"away.?notify", r"away_notify", r"AWAY\b",
                     r"away.*status"],
        "commands": ["AWAY"],
    },
    "extended_join": {
        "name": "Extended Join",
        "spec": "ircv3.2",
        "patterns": [r"extended.?join", r"extended_join", r"extjoin",
                     r"ext.*join"],
    },
    "chghost": {
        "name": "CHGHOST",
        "spec": "ircv3.2",
        "patterns": [r"\bCHGHOST\b", r"chghost", r"chg.?host"],
        "commands": ["CHGHOST"],
    },
    "echo_message": {
        "name": "Echo Message",
        "spec": "ircv3.2",
        "patterns": [r"echo.?message", r"echo_message", r"echo_msg",
                     r"echo.*messag"],
    },
    "monitor": {
        "name": "Monitor",
        "spec": "ircv3.2",
        "patterns": [r"\bMONITOR\b", r"monitor", r"monitor_list",
                     r"monitor.*online"],
        "commands": ["MONITOR"],
    },
    "multi_prefix": {
        "name": "Multi-prefix",
        "spec": "ircv3.1",
        "patterns": [r"multi.?prefix", r"multi_prefix", r"NAMES.*prefix",
                     r"prefix.*multi"],
    },
    "sts": {
        "name": "STS (Strict Transport Security)",
        "spec": "ircv3.3",
        "patterns": [r"\bSTS\b", r"strict_transport", r"sts_policy",
                     r"sts_persist", r"sts.*security"],
    },
    "invite_notify": {
        "name": "Invite Notify",
        "spec": "ircv3.2",
        "patterns": [r"invite.?notify", r"invite_notify", r"INVITE.*notif"],
    },
    "labeled_response": {
        "name": "Labeled Response",
        "spec": "ircv3.2",
        "patterns": [r"labeled.?response", r"labeled_response",
                     r"@label=", r"label.*tag"],
    },
    "msgid": {
        "name": "msgid",
        "spec": "ircv3.2",
        "patterns": [r"\bmsgid\b", r"msg.?id", r"@msgid=", r"message.?id"],
    },
    "setname": {
        "name": "SETNAME",
        "spec": "ircv3.2",
        "patterns": [r"\bSETNAME\b", r"setname", r"set.?name"],
        "commands": ["SETNAME"],
    },
    "userhost_in_names": {
        "name": "Userhost-in-Names",
        "spec": "ircv3.2",
        "patterns": [r"userhost.?in.?names", r"userhost_in_names",
                     r"userhost.*names"],
    },
    "standard_replies": {
        "name": "Standard Replies",
        "spec": "ircv3.3",
        "patterns": [r"standard.?repl", r"standard_replies", r"FAIL\b",
                     r"WARN\b", r"NOTE\b", r"standard.*reply"],
    },
    "metadata": {
        "name": "METADATA",
        "spec": "ircv3.3",
        "patterns": [r"\bMETADATA\b", r"metadata", r"meta.*data"],
        "commands": ["METADATA"],
    },
    "bot_mode": {
        "name": "Bot Mode",
        "spec": "ircv3.3",
        "patterns": [r"bot.?mode", r"bot_mode", r"BOT\b.*mode"],
    },
    "chathistory": {
        "name": "CHATHISTORY",
        "spec": "ircv3.3",
        "patterns": [r"\bCHATHISTORY\b", r"chat.?history", r"chathistory"],
        "commands": ["CHATHISTORY"],
    },
    "draft_typing": {
        "name": "Typing Indicator (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"typing\b", r"\+typing", r"typing.*indicat",
                     r"typing.*draft", r"@\+typing="],
    },
    "draft_reply": {
        "name": "Reply (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"\+reply", r"@\+reply=", r"\+draft/reply",
                     r"reply.*thread", r"reply.*parent"],
    },
    "draft_read_marker": {
        "name": "Read Marker (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"read.?marker", r"read_marker", r"MARKREAD",
                     r"markread", r"draft/read-marker", r"\+read-marker"],
    },
    "draft_display_name": {
        "name": "Display Name (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"display.?name", r"display_name", r"SETNAME.*display",
                     r"draft/display-name"],
    },
    "draft_channel_rename": {
        "name": "Channel Rename (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"channel.?rename", r"channel_rename", r"RENAME\b",
                     r"rename.*channel"],
    },
    "starttls": {
        "name": "STARTTLS",
        "spec": "ircv3.1",
        "patterns": [r"\bSTARTTLS\b", r"starttls", r"start.?tls",
                     r"tls.*upgrade"],
        "commands": ["STARTTLS"],
    },
    "draft_resume": {
        "name": "Resume (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"\bRESUME\b", r"\bBRB\b", r"draft/resume",
                     r"connection.*resume", r"resume.*token"],
        "commands": ["RESUME", "BRB"],
    },
    "draft_react": {
        "name": "Reaction (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"\+react", r"@\+react=", r"draft/react",
                     r"message.*react", r"emoji.*react"],
    },
    "draft_multiline": {
        "name": "Multiline (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"multiline", r"multi.?line", r"draft/multiline",
                     r"@draft/multiline=", r"batch.*multiline"],
    },
    "draft_relaymsg": {
        "name": "Relaymsg (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"relaymsg", r"relay.?msg", r"draft/relaymsg",
                     r"@\+relaymsg", r"relay.*message"],
    },
    "draft_account_registration": {
        "name": "Account Registration (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"\bREGISTER\b", r"\bUNREGISTER\b",
                     r"account.*regist", r"draft/account-registration",
                     r"registration.*account"],
        "commands": ["REGISTER"],
    },
    "draft_channel_context": {
        "name": "Channel Context (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"channel.?context", r"channel_context",
                     r"draft/channel-context"],
    },
    "draft_pre_away": {
        "name": "Pre-Away (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"pre.?away", r"preaway", r"PREAWAY",
                     r"draft/pre-away"],
        "commands": ["PREAWAY"],
    },
    "draft_event_playback": {
        "name": "Event Playback (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"event.?playback", r"event_playback",
                     r"draft/event-playback", r"replay.*event"],
    },
    "draft_no_implicit_names": {
        "name": "No Implicit Names (draft)",
        "spec": "ircv3-draft",
        "patterns": [r"no.?implicit.?names", r"no_implicit_names",
                     r"draft/no-implicit-names", r"implicit.*names"],
    },
    "utf8only": {
        "name": "UTF8ONLY",
        "spec": "ircv3.2",
        "patterns": [r"\bUTF8ONLY\b", r"utf8only", r"utf.?8.?only",
                     r"utf-8.*enforce", r"utf8.*only"],
    },
    "rpl_isupport": {
        "name": "RPL_ISUPPORT (005)",
        "spec": "ircv3.1",
        "patterns": [r"RPL_ISUPPORT", r"rpl_isupport", r"005\b",
                     r"isupport", r"ISUPPORT", r"RPL_ISUPPORT\b",
                     r"numeric.*005"],
    },

    # -- Common IRCv3-related patterns in code structure --
    "cap_302": {
        "name": "CAP 302 (LS version)",
        "spec": "ircv3.2",
        "patterns": [r"cap.*302", r"CAP.*302", r"302.*cap"],
    },
    "ircv3_version_aware": {
        "name": "IRCv3 version awareness",
        "spec": "meta",
        "patterns": [r"ircv3", r"irc.?v3", r"IRCv3", r"IRCv3\.[123]",
                     r"irc.*version.*3"],
    },
    "webirc": {
        "name": "WEBIRC",
        "spec": "ircv3.1",
        "patterns": [r"\bWEBIRC\b", r"webirc", r"web.*irc"],
    },
    "whox": {
        "name": "WHOX (extended WHO)",
        "spec": "ircv3.2",
        "patterns": [r"\bWHOX\b", r"whox", r"WHO.*extend", r"extended.*who"],
    },
}

# --─ ASCII Art Helpers ----------------------------------------------------

GRADES = {
    (90, 101): ("A+", "█", "EXCELLENT"),
    (80, 90):  ("A",  "█", "VERY STRONG"),
    (70, 80):  ("B",  "▓", "STRONG"),
    (60, 70):  ("C",  "▒", "MODERATE"),
    (50, 60):  ("D",  "▒", "WEAK"),
    (30, 50):  ("E",  "░", "VERY WEAK"),
    (0, 30):   ("F",  " ",  "NEGLIGIBLE"),
}

# Features that are considered "core" (weighted higher)
CORE_FEATURES = {"cap", "sasl", "message_tags", "server_time", "batch",
                 "cap_302", "ircv3_version_aware"}

# Features by spec version
IRCV3_SPECS = {
    "ircv3.1":   [],
    "ircv3.2":   [],
    "ircv3.3":   [],
    "ircv3-draft": [],
    "meta":      [],
}

for key, feat in IRCV3_FEATURES.items():
    spec = feat["spec"]
    if spec in IRCV3_SPECS:
        IRCV3_SPECS[spec].append(key)


def detect_features(source_code: str) -> dict:
    """Scan source for IRCv3 feature patterns."""
    results = {}
    lower_code = source_code.lower()

    for key, feat in IRCV3_FEATURES.items():
        score = 0
        matches = []
        for pattern in feat["patterns"]:
            found = re.findall(pattern, source_code, re.IGNORECASE)
            if found:
                score += min(len(found), 3)  # cap at 3 matches per pattern
                matches.extend(found[:3])

        # Additionally check for command literal strings
        if "commands" in feat:
            for cmd in feat["commands"]:
                if cmd.lower() in lower_code:
                    score += 1
                    matches.append(f"literal:{cmd}")

        results[key] = {
            "name": feat["name"],
            "spec": feat["spec"],
            "score": score,
            "matches": list(set(matches))[:5],
            "supported": score > 0,
        }
    return results


def compute_percentile(features: dict) -> tuple:
    """Compute weighted percentile score."""
    total_possible = 0
    total_score = 0
    spec_scores = {s: {"score": 0, "total": 0} for s in IRCV3_SPECS}

    for key, data in features.items():
        weight = 2 if key in CORE_FEATURES else 1
        max_s = 8 if key in CORE_FEATURES else 4  # rough ceiling
        total_possible += max_s * weight
        total_score += min(data["score"], max_s) * weight

        spec = data["spec"]
        if spec in spec_scores:
            spec_scores[spec]["score"] += min(data["score"], max_s) * weight
            spec_scores[spec]["total"] += max_s * weight

    percentile = round((total_score / total_possible) * 100, 1) if total_possible else 0
    return percentile, spec_scores


def render_bar(value: float, width: int = 30) -> str:
    """Render an ascii-bar for a value 0-100."""
    filled = int((value / 100) * width)
    return "#" * filled + "-" * (width - filled)


def render_report(filepath: str, features: dict, percentile: float,
                  spec_scores: dict) -> str:
    """Produce a readable terminal report."""
    # Find grade
    grade, _, label = "?", "", "UNKNOWN"
    for (lo, hi), (g, ch, lbl) in GRADES.items():
        if lo <= percentile < hi:
            grade, label = g, lbl
            break

    bar = render_bar(percentile)

    lines = []
    lines.append("")
    lines.append("=" * 64)
    lines.append("  IRCv3 SUPPORT ANALYZER")
    lines.append("=" * 64)
    lines.append("")
    lines.append(f"  File        : {filepath}")
    lines.append(f"  Grade       : {grade} ({label})")
    lines.append(f"  Percentile  : {percentile}%")
    lines.append(f"  [{bar}]")
    lines.append("")

    # -- Per-spec breakdown --
    lines.append("  -- Specification-Level Coverage --")
    lines.append(f"  {'Spec':<16} {'Coverage':>10}  {'Bar'}")
    lines.append(f"  {'-' * 16} {'-' * 10}  {'-' * 30}")
    for spec, data in spec_scores.items():
        cov = round((data["score"] / data["total"]) * 100, 1) if data["total"] else 0
        lines.append(f"  {spec:<16} {cov:>9.1f}%  {render_bar(cov, 20)}")
    lines.append("")

    # -- Supported features (sorted by strength) --
    supported = [(k, v) for k, v in features.items() if v["supported"]]
    if supported:
        supported.sort(key=lambda x: x[1]["score"], reverse=True)
        lines.append("  -- DETECTED (sorted by signal strength) --")
        for key, data in supported:
            marker = "*" if key in CORE_FEATURES else "-"
            spec_tag = f"[{data['spec']}]"
            lines.append(f"  {marker} {data['name']:<34} {spec_tag:<14} "
                         f"strength={data['score']}")
    lines.append("")

    # -- Missing features --
    missing = [(k, v) for k, v in features.items() if not v["supported"]]
    if missing:
        lines.append("  -- MISSING --")
        for key, data in missing:
            marker = "*" if key in CORE_FEATURES else "-"
            spec_tag = f"[{data['spec']}]"
            lines.append(f"  {marker} {data['name']:<34} {spec_tag}")
    lines.append("")

    # -- Recommendations --
    lines.append("  -- Top 5 Recommendations (highest-impact missing features) --")
    recs = []
    for key, data in missing:
        boost = 3 if key in CORE_FEATURES else 1
        recs.append((key, data, boost))
    recs.sort(key=lambda x: x[2], reverse=True)
    for i, (key, data, boost) in enumerate(recs[:5], 1):
        lines.append(f"  {i}. Implement {data['name']}  [{data['spec']}]")
    lines.append("")
    lines.append(f"  * = core feature (double-weighted in scoring)")
    lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python ircv3analyzer.py <source_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    source_path = Path(filepath)

    if not source_path.exists():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    if not source_path.is_file():
        print(f"Error: Not a file: {filepath}")
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        source_code = f.read()

    features = detect_features(source_code)
    percentile, spec_scores = compute_percentile(features)

    report = render_report(filepath, features, percentile, spec_scores)
    print(report)


if __name__ == "__main__":
    main()
