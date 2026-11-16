#!/usr/bin/env python3
"""Independently verify a VM attempt's full JSON and terminal summary.

The line algorithms below are the Python reference from
`docs/specs/jail-v1/summary_check.py` at 2d1ffc0f22067cd705a1e8d97c711de863c47d6b,
embedded so packaged-source verification needs no documentation checkout.
They do not import or execute the Rust summarizer. The VM adapter verifies
exact retained bytes before composing guest event lines with host lifecycle
lines, following J18/D5. A named guest receipt requires a complete exported
journal; legacy/unverified attempts without that name use only host evidence.

verify_attempt(attempt, summary_json, summary_text, *, display_mapping=None)
accepts a JSON object and text string. Default comparison is exact, including
the archived receipt path. A caller may explicitly provide literal display
replacements for already redacted or relocated output; they never change the
evidence or its digest/binding checks. Returned PASS verifies rendering, not
containment, vendor compatibility, artifact authenticity or K113 readiness.

CLI: vm_summary_check.py ATTEMPT SUMMARY_JSON SUMMARY_TEXT [--display-map JSON]
Python 3.11+, standard library only. No secret sources, subprocesses or network.
"""
import argparse
import base64
import contextlib
import os
import stat
import struct
import calendar
import hashlib
import ipaddress
import json
import re
import sys
import unicodedata
from pathlib import Path

CLASSES = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"]
AUDIT_CLASSES = ["exec", "fs.write", "fs.deny", "net"]
STATUSES = ["supported", "active", "degraded", "unsupported"]
WRITE_OPERATIONS = ("fs.create", "fs.write", "fs.rename", "fs.unlink")
# Digest reasons that place a path outside the workspace on the jail's own
# evidence (jail-v1 §11.3): the agent's vendor state, and a standard device
# such as /dev/null. The workspace line does not count them as unnamed.
NOT_WORKSPACE_DIGESTS = ("vendor_state", "standard_device")
SCAN_CAP = 16 * 1024 * 1024
RECEIPT_MAX = 4 * 1024 * 1024
# jail-v1 §13.1: an event is at most 64 KiB; a longer line is no frame.
EVENT_MAX = 64 * 1024
TERMINAL_LIST = 5
JSON_LIST = 64
U64_MAX = 2 ** 64 - 1


class VerificationError(ValueError):
    """An evidence binding or independently recomputed summary did not verify."""


def fail(message):
    raise VerificationError(message)


# --------------------------------------------------------------------------
# Escaping: control characters, bidi controls and invisible format
# characters become <U+XXXX> (operating.md, "Every child-chosen string is
# escaped").

BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
INVISIBLE = ({0x2028, 0x2029, 0xFEFF} | set(range(0x200B, 0x200E)) | set(range(0x2060, 0x2065))
             | set(range(0xE0000, 0xE0080)))


def esc(text):
    out = []
    for character in text:
        code = ord(character)
        if unicodedata.category(character) == "Cc" or code in BIDI or code in INVISIBLE:
            out.append("<U+%04X>" % code)
        else:
            out.append(character)
    return "".join(out)


def canonical_value(value):
    """The receipt's integer-only canonical JSON domain, with UTF-16 key order."""
    if value is None or type(value) in (bool, str):
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if type(value) is int and -(2 ** 63) <= value < 2 ** 64:
        return str(value)
    if type(value) is list:
        return '[' + ','.join(canonical_value(item) for item in value) + ']'
    if type(value) is dict and all(type(key) is str for key in value):
        return '{' + ','.join(canonical_value(key) + ':' + canonical_value(value[key])
                              for key in sorted(value, key=lambda item: item.encode('utf-16-be'))) + '}'
    raise VerificationError('unsupported canonical receipt value')


def canonical_digest(receipt):
    return 'sha256:' + hashlib.sha256(canonical_value(receipt).encode()).hexdigest()


def pointer(value, *keys):
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
            value = value[key]
        else:
            return None
    return value


def string(value, *keys):
    found = pointer(value, *keys)
    return found if isinstance(found, str) else None


def unsigned(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= U64_MAX else None


# --------------------------------------------------------------------------
# Reading the journal (jail-v1 §§13.1, 13.3): a frame is one JSON object
# ending in LF; nothing from the first line that is not one is evidence.


class Frame(dict):
    """A JSON object, remembering the keys it held more than once."""


def object_pairs(pairs):
    frame = Frame()
    frame.repeated = set()
    for key, value in pairs:
        if key in frame:
            frame.repeated.add(key)
        frame[key] = value
    return frame


def no_constant(name):
    raise ValueError(f"not JSON: {name}")


TOP = {"attempt_id": str, "source": str, "source_seq": "u64", "operation": str, "decision": str,
       "monotonic_ns": str, "outcome": dict, "fields": dict}
FIELDS = {"kind": str, "transition": str, "phase": str, "receipt_digest": str, "action": str,
          "attempted_operation": str, "destination": str, "reason": str, "credential_id": str,
          "uses_recorded": bool, "credentials": "ids", "credentials_unconfirmed": "ids",
          "syscall": str, "path": "path", "path2": "path"}


def typed(value, kind):
    """Whether a present key holds what the reader expects (null is absent)."""
    if value is None:
        return True
    if kind == "u64":
        return unsigned(value) is not None
    if kind == "ids":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if kind == "path":
        if not isinstance(value, dict) or getattr(value, "repeated", set()) & {"kind", "value"}:
            return False
        if not isinstance(value.get("kind"), str):
            return False
        name = value.get("value")
        return (name is None or isinstance(name, str)
                or (isinstance(name, dict) and name.get("encoding") == "base64" and isinstance(name.get("data"), str)))
    if kind is bool:
        return isinstance(value, bool)
    return isinstance(value, kind) and not (kind is int and isinstance(value, bool))


def well_formed(frame):
    if not isinstance(frame, Frame) or frame.repeated & set(TOP):
        return False
    if not all(typed(frame.get(key), kind) for key, kind in TOP.items()):
        return False
    outcome = frame.get("outcome") or {}
    if "ok" in getattr(outcome, "repeated", set()) or not typed(outcome.get("ok"), bool):
        return False
    fields = frame.get("fields") or {}
    if getattr(fields, "repeated", set()) & set(FIELDS):
        return False
    return all(typed(fields.get(key), kind) for key, kind in FIELDS.items())


def read_journal(data, digest, attempt_id):
    frames, broken, hole, loss, last_seq = [], False, False, False, {}
    lines = data.split(b"\n")
    torn = lines.pop() != b""
    for line in lines:
        frame = None
        if len(line) <= EVENT_MAX and line.lstrip(b" \t\n\x0c\r")[:1] == b"{":
            try:
                frame = json.loads(line.decode("utf-8"), object_pairs_hook=object_pairs,
                                   parse_constant=no_constant)
            except ValueError:
                frame = None
        if frame is None or not well_formed(frame):
            broken = True
            break
        if frame.get("attempt_id") != attempt_id or frame.get("source_seq") is None:
            broken = True
            break
        fields = frame.get("fields") or {}
        if (frame.get("source") == "wrapper" and frame.get("operation") == "note"
                and fields.get("kind") == "coverage_gap" and fields.get("reason") == "trace_transport_loss"):
            loss = True
        source, seq = frame.get("source") or "", frame["source_seq"]
        previous = last_seq.get(source, 0)
        if seq <= previous:
            broken = True
            break
        if seq != previous + 1 and not loss:
            hole = True
        last_seq[source] = seq
        frames.append(frame)
    else:
        broken = torn
    last = frames[-1] if frames else {}
    note = None
    if last.get("source") == "wrapper" and last.get("operation") == "jail.receipt":
        fields = last.get("fields") or {}
        if isinstance(fields.get("phase"), str) and isinstance(fields.get("receipt_digest"), str):
            note = fields["receipt_digest"]
    complete = not broken and not hole and note is not None and note == digest
    another = not complete and not broken and not hole and note is not None
    return frames, complete, another


def class_of(frame):
    source, operation = frame.get("source"), frame.get("operation")
    if source == "audit":
        if operation in ("proc.exec", "proc.exit"):
            return "exec"
        if operation in WRITE_OPERATIONS:
            return "fs.write"
        if operation == "fs.deny":
            return "fs.deny"
        if operation == "net.connect":
            return "net"
    if source == "proxy" and operation == "net.connect":
        return "proxy.net"
    return None


def status_of(receipt, name):
    coverage = pointer(receipt, "coverage", name)
    if not isinstance(coverage, dict) or "status" not in coverage:
        return "unsupported"
    return coverage["status"] if coverage["status"] in STATUSES else "unknown"


def claim_of(receipt, name, frames, state):
    """exact, at_least, not_observed, unavailable (no journal) or disagree."""
    status = status_of(receipt, name)
    if status not in ("active", "degraded"):
        return "not_observed"
    if state not in ("complete", "incomplete") or name == "limits":
        return "unavailable"
    counted = sum(1 for frame in frames if class_of(frame) == name)
    observed = unsigned(pointer(receipt, "coverage", name, "observed_count"))
    if status == "active" and state == "complete":
        return "exact" if observed == counted else "disagree"
    if observed is not None and counted > observed:
        return "disagree"
    return "at_least"


def counts(claim):
    return claim in ("exact", "at_least")


def number(claim, n):
    return f"at least {n}" if claim == "at_least" else str(n)


def noun(n, one, many):
    return one if n == 1 else many


def capped(items, separator):
    shown = separator.join(items[:TERMINAL_LIST])
    more = len(items) - TERMINAL_LIST
    return shown + (f" +{more} more" if more > 0 else "")


def missing(state, size):
    return {"not_scanned": f"journal not scanned ({-(-size // (1024 * 1024))} MiB)",
            "absent": "no local journal", "unreadable": "journal unreadable",
            "guest": "the guest's journal is not exported"}.get(state)


def duration(ms):
    seconds = ms // 1000
    if seconds == 0:
        return f"{ms}ms"
    if seconds < 60:
        return f"{seconds}.{(ms % 1000) // 100}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m{seconds % 60:02d}s"


def wall_duration(created, updated, ms):
    # Mirrors summary.rs: milliseconds only when both stamps carry them;
    # whole-second stamps n apart print `under 1s` (n = 0) or `<n>s ±1s`.
    def millisecond(stamp):
        match = STAMP.match(stamp)
        return bool(match and match.group(7) and len(match.group(7)) >= 3)
    if millisecond(created) and millisecond(updated):
        return duration(ms)
    seconds = max(epoch_ms(updated) // 1000 - epoch_ms(created) // 1000, 0)
    if seconds == 0:
        return "under 1s"
    if seconds < 60:
        return f"{seconds}s ±1s"
    return f"{duration(seconds * 1000)} ±1s"


STAMP = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$")


def epoch_ms(stamp):
    match = STAMP.match(stamp) if isinstance(stamp, str) else None
    if not match:
        return None
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour <= 23 and minute <= 59 and second <= 60):
        return None
    millis = int((match.group(7) or "")[:3].ljust(3, "0"))
    return calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0)) * 1000 + millis


def clock(frame):
    text = frame.get("monotonic_ns")
    return int(text) if isinstance(text, str) and text.isascii() and text.isdigit() else None


# --------------------------------------------------------------------------
# The lines


def status_line(receipt, frames, scanned):
    phase = string(receipt, "phase") or "unknown"
    parts = ["settled" if phase == "settled" else f"NOT settled ({esc(phase)})"]
    kind = string(receipt, "outcome", "kind") or "unknown"
    code, signal = unsigned(pointer(receipt, "outcome", "code")), unsigned(pointer(receipt, "outcome", "signal"))
    cause = string(receipt, "outcome", "cause")
    if kind == "exited" and code is not None:
        outcome = f"exited {code}"
    elif kind == "signaled" and signal is not None:
        outcome = f"signaled {signal}"
    elif kind == "exec_error":
        outcome = "exec failed"
    elif kind == "refused":
        outcome = "" if phase == "refused" else "refused"
    elif kind == "pending":
        outcome = "outcome pending"
    else:
        outcome = "outcome unknown"
    if cause is not None:
        outcome += (" " if outcome else "") + f"({esc(cause)})"
    if outcome:
        parts.append(outcome)
    start = next((clock(frame) for frame in frames
                  if frame.get("source") == "wrapper" and frame.get("operation") == "note"
                  and (frame.get("fields") or {}).get("kind") == "lifecycle"
                  and (frame.get("fields") or {}).get("transition") == "exec_confirmed"
                  and clock(frame) is not None), None)
    end = None
    for frame in frames:
        if (frame.get("source") == "wrapper" and frame.get("operation") == "jail.receipt"
                and (frame.get("fields") or {}).get("phase") == "settled" and clock(frame) is not None):
            end = clock(frame)
    journal_ms = (end - start) // 1_000_000 if start is not None and end is not None and end >= start else None
    wall_ms = None
    if not scanned:
        created, updated = epoch_ms(string(receipt, "created_at")), epoch_ms(string(receipt, "updated_at"))
        if created is not None and updated is not None and updated >= created:
            wall_ms = updated - created
    if journal_ms is not None:
        parts.append(f"{duration(journal_ms)} exec→settled")
    elif wall_ms is not None:
        parts.append(f"{wall_duration(string(receipt, 'created_at'), string(receipt, 'updated_at'), wall_ms)}"
                     " attempt (wall clock)")
    tree_empty = pointer(receipt, "lifetime", "tree_empty")
    scope = string(receipt, "lifetime", "verification_scope")
    boundary = string(receipt, "lifetime", "boundary")
    # J16 (jail-macos.md §4.8): native custody is verified while it lasts,
    # but no kernel ends the tree. Both custodians lost is the residual;
    # a lost guardian alone is a recorded custodian failure.
    # Details may be absent; degrade to the plain form.
    guardian_lost = pointer(receipt, "lifetime", "native", "details", "custodians", "guardian", "result") == "lost"
    if tree_empty is True and boundary == "native_tree" and scope == "attempt_tree" and guardian_lost:
        parts.append("survivors: none (verified · native custody, not kernel-bound · guardian lost)")
        survivors = "none_verified_native_guardian_lost"
    elif tree_empty is True and boundary == "native_tree" and scope == "attempt_tree":
        parts.append("survivors: none (verified · native custody, not kernel-bound)")
        survivors = "none_verified_native"
    elif boundary == "native_tree":
        parts.append("survivors: NOT verified")
        survivors = "not_verified"
    elif tree_empty is True and scope == "registered_boundary":
        parts.append("survivors: none (verified, registered cgroup only)")
        survivors = "none_verified_registered_boundary"
    elif tree_empty is True and scope == "attempt_tree":
        parts.append("survivors: none (verified)")
        survivors = "none_verified"
    else:
        parts.append("survivors: NOT verified")
        survivors = "not_verified"
    codes = []
    for error in pointer(receipt, "errors") or []:
        code_text = string(error, "code")
        if code_text is not None and code_text not in codes:
            codes.append(code_text)
    if codes:
        rendered = ["tree_unknown: run ukai-jail gc" if each == "tree_unknown" else esc(each) for each in codes]
        parts.append("errors: " + capped(rendered, ", "))
    integrity = string(receipt, "lifetime", "integrity")
    if integrity == "lost":
        parts.append("integrity lost: state retained")
    facts = {"phase": phase, "outcome": kind, "code": code, "signal": signal, "cause": cause,
             "exec_to_settled_ms": journal_ms, "attempt_wall_ms": wall_ms, "survivors": survivors,
             "errors": codes, "integrity": integrity}
    return " · ".join(parts), facts


def written(operation, fields):
    """The paths a successful write-class result wrote (§4.2): both sides of
    a rename; of a directory-entry creation only the entry it created, by
    fields.syscall (a hard link's new name, path2; a symlink's link, path:
    its path2 is the target, which the call stores without touching); path
    of every other result. None for a creation with a second path and a call
    that is neither: which path is the new entry is not established. A slot
    is None where the result recorded no such path."""
    path, path2, syscall = fields.get("path"), fields.get("path2"), fields.get("syscall")
    if fields.get("observation") == "es_notify":
        if fields.get("action") in ("cloned", "copied"):
            return [path2]
        if fields.get("action") == "exchanged":
            return [path, path2]
    if operation == "fs.rename":
        return [path, path2]
    if operation == "fs.create" and (syscall in ("link", "linkat") or fields.get("action") == "hard_link_created"):
        return [path2]
    if operation == "fs.create" and syscall in ("symlink", "symlinkat"):
        return [path]
    if operation == "fs.create" and path2 is not None:
        return None
    return [path]


def unnamed_path(path):
    """No name for a written path: none recorded, unavailable, or a digest
    whose reason does not place it outside the workspace."""
    return (path is None or path.get("kind") == "unavailable"
            or (path.get("kind") == "digest" and path.get("reason") not in NOT_WORKSPACE_DIGESTS))


def workspace_line(receipt, frames, claims, state, size):
    opened, renamed, removed, modified, created, metadata = (set() for _ in range(6))
    named, unnamed, refused = {}, 0, 0
    root = {("t", ""), ("b", "")}
    for frame in frames:
        fields, operation = frame.get("fields") or {}, frame.get("operation")
        if frame.get("source") != "audit":
            continue
        if operation == "fs.deny" and fields.get("attempted_operation") in WRITE_OPERATIONS:
            refused += 1
        if operation not in WRITE_OPERATIONS or (frame.get("outcome") or {}).get("ok") is not True:
            continue
        native_mutation = fields.get("observation") == "es_notify" and fields.get("action") in ("copied", "exchanged")
        if operation == "fs.write" and fields.get("action") not in ("opened_for_mutation", "truncated", "modified", "metadata_changed") and not native_mutation:
            continue
        paths = written(operation, fields)
        if paths is None or any(unnamed_path(path) for path in paths):
            unnamed += 1
        for path in paths or []:
            value = path.get("value") if path is not None else None
            if value is None or path.get("kind") != "workspace_relative":
                continue
            key = ("t", value) if isinstance(value, str) else ("b", value["data"])
            named[key] = value if isinstance(value, str) else {"encoding": "base64", "data": value["data"]}
            action = fields.get("action")
            if fields.get("observation") == "es_notify" and action == "cloned":
                other = created
            elif native_mutation or action == "modified" or (action == "truncated" and fields.get("observation") == "es_notify"):
                other = modified
            elif action == "metadata_changed":
                other = metadata
            elif action in ("hard_link_created", "created"):
                other = created
            else:
                other = opened
            {"fs.rename": renamed, "fs.unlink": removed}.get(operation, other).add(key)
    write, deny = claims["fs.write"], claims["fs.deny"]
    observe_off = string(receipt, "policy", "observe") == "off"
    native_notify = string(receipt, "observer", "backend") == "es_notify"
    if write == "not_observed":
        text = "not observed (--observe off)" if observe_off else "not observed"
    elif write == "unavailable":
        text = missing(state, size)
    elif write == "disagree":
        text = "journal and receipt disagree on fs.write"
    else:
        seen = []
        if opened or (write == "exact" and not native_notify):
            seen.append(f"{number(write, len(opened))} {noun(len(opened), 'path', 'paths')} opened for writing")
        for n, what in [(len(modified - root), "modified"), (len(created - root), "created"),
                        (len(metadata - root), "with metadata changes"),
                        (len(renamed), "in renames"), (len(removed), "removed")]:
            if n:
                seen.append(f"{number(write, n)} {what}")
        for paths, what in [(modified, "content modified"), (created, "created"), (metadata, "metadata changed")]:
            if paths & root:
                seen.append(f"workspace root {what}")
        text = ", ".join(seen) if seen else ("no in-set mutations recorded" if native_notify and write == "exact" else "none recorded (a lower bound)")
        if unnamed:
            text += f" · {number(write, unnamed)} " + noun(unnamed, "result with an unnamed path",
                                                          "results with unnamed paths")
    text = "workspace: " + text
    if counts(deny) and refused:
        text += f" · {number(deny, refused)} {noun(refused, 'refused write', 'refused writes')}"
    elif deny == "disagree":
        text += " · refused writes: journal and receipt disagree on fs.deny"
    order = sorted(key for key in named if key[0] == "t") + sorted(key for key in named if key[0] == "b")
    listed = [{"kind": "workspace_relative", "value": named[key]} for key in order] if counts(write) else []
    value = lambda n: n if counts(write) else None
    facts = {"bound": write, "opened_for_writing": value(len(opened)), "renamed": value(len(renamed)),
             "removed": value(len(removed)), "unnamed": value(unnamed),
             "refused": refused if counts(deny) else None, "refused_bound": deny,
             "paths": listed[:JSON_LIST], "omitted": max(0, len(listed) - JSON_LIST)}
    return text, facts


def option_key(destination):
    return (0, "") if destination is None else (1, destination)


def proxy_tally(frames):
    allowed, denied, uses, unconfirmed, refusals = {}, {}, {}, {}, 0
    for frame in frames:
        if class_of(frame) != "proxy.net":
            continue
        fields = frame.get("fields") or {}
        destination, reason = fields.get("destination"), fields.get("reason") or ""
        if frame.get("decision") == "allow":
            results, failed = allowed.get(destination, (0, 0))
            ok = (frame.get("outcome") or {}).get("ok") is True
            allowed[destination] = (results + 1, failed + (0 if ok else 1))
        else:
            denied[(destination, reason)] = denied.get((destination, reason), 0) + 1
        if frame.get("decision") == "deny" and reason.startswith("credential_"):
            refusals += 1
        for key, tally in (("credentials", uses), ("credentials_unconfirmed", unconfirmed)):
            for credential in set(fields.get(key) or []):
                tally[credential] = tally.get(credential, 0) + 1
    return allowed, denied, uses, unconfirmed, refusals


def network_line(receipt, frames, claims, state, size):
    mode = string(receipt, "applied", "network", "mode") or "pending"
    claim = claims["proxy.net"]
    resolver = unsigned(pointer(receipt, "coverage", "proxy.net", "resolver_refused"))
    allowed, denied, _, _, _ = proxy_tally(frames)
    label = lambda destination: "(no destination)" if destination is None else esc(destination)
    allowed_order = sorted(allowed.items(), key=lambda item: (-item[1][0], option_key(item[0])))
    by_destination = {}
    for (destination, _), n in denied.items():
        by_destination[destination] = by_destination.get(destination, 0) + n
    denied_order = sorted(by_destination.items(), key=lambda item: (-item[1], option_key(item[0])))
    if mode == "none":
        text = "none"
    elif mode == "host":
        text = "host, not observed"
    elif mode == "proxy" and claim == "not_observed":
        text = "proxy, not observed"
    elif mode == "proxy" and claim == "unavailable":
        text = "proxy, " + missing(state, size)
    elif mode == "proxy" and claim == "disagree":
        text = "proxy, journal and receipt disagree on proxy.net"
    elif mode == "proxy":
        parts = []
        if allowed_order:
            items = []
            for destination, (results, failed) in allowed_order:
                item = f"{label(destination)} ({number(claim, results)}"
                if failed:
                    item += f", {number(claim, failed)} connect failed"
                items.append(item + ")")
            parts.append("allowed " + capped(items, ", "))
        if denied_order:
            parts.append("denied " + capped([f"{label(d)} ({number(claim, n)})" for d, n in denied_order], ", "))
        if not parts:
            parts.append("proxy, no connections" if claim == "exact" else "proxy, none recorded (a lower bound)")
        if resolver is not None:
            parts.append(f"{resolver} refused for resolver capacity, not policy")
        text = " · ".join(parts)
    else:
        text = "not applied"
    counted = mode == "proxy" and counts(claim)
    pairs = sorted(denied.items(), key=lambda item: (-item[1], option_key(item[0][0]), item[0][1])) if counted else []
    entries = allowed_order if counted else []
    facts = {"mode": mode, "bound": claim if mode == "proxy" else "not_observed",
             "allowed": [{"destination": d, "results": r, "connect_failed": f} for d, (r, f) in entries[:JSON_LIST]],
             "denied": [{"destination": d, "reason": reason, "results": n} for (d, reason), n in pairs[:JSON_LIST]],
             "omitted": max(0, len(entries) - JSON_LIST) + max(0, len(pairs) - JSON_LIST),
             "resolver_refused": resolver}
    return "network: " + text, facts


def credentials_line(receipt, frames, claims, state, size):
    credentials = pointer(receipt, "credentials")
    if not isinstance(credentials, list) or not credentials:
        return None
    claim = claims["proxy.net"]
    _, _, uses, unconfirmed, refusals = proxy_tally(frames)
    marked, transitions = set(), {}
    for frame in frames:
        fields = frame.get("fields") or {}
        if frame.get("source") != "wrapper" or frame.get("operation") != "note" or fields.get("kind") != "credential":
            continue
        identity = fields.get("credential_id")
        if identity is None:
            continue
        if fields.get("uses_recorded") is True:
            marked.add(identity)
        if fields.get("transition") is not None:
            seen = transitions.setdefault(identity, [])
            if fields["transition"] not in seen:
                seen.append(fields["transition"])
    parts, facts, vault = [], [], False
    for credential in credentials:
        identity = string(credential, "id") or ""
        mode = string(credential, "mode") or "unknown"
        never_staged = pointer(credential, "never_staged")
        never_staged = never_staged if isinstance(never_staged, bool) else None
        part = f"{esc(identity)}: {esc(mode)}"
        used, bound = None, "not_observed"
        if mode == "vault":
            vault = True
            if never_staged is True:
                part += ", never staged"
            if claim == "unavailable":
                part += " · uses: " + missing(state, size)
                bound = "unavailable"
            elif claim == "not_observed":
                part += " · uses not observed"
            elif claim == "disagree":
                part += " · uses: journal and receipt disagree on proxy.net"
                bound = "disagree"
            elif identity not in marked:
                part += " · uses not recorded"
                bound = "not_recorded"
            else:
                used, maybe = uses.get(identity, 0), unconfirmed.get(identity, 0)
                bound = "at_least" if maybe else claim
                if bound == "at_least" and used == 0 and maybe == 0:
                    part += " · uses: none recorded (a lower bound)"
                else:
                    part += f" · used on {number(bound, used)} {noun(used, 'proxy result', 'proxy results')}"
                if maybe:
                    part += f" (+{maybe} not confirmed sent)"
        else:
            part += ", staged (readable by the agent)"
        notable = [esc(t) for t in transitions.get(identity, []) if t not in ("loaded", "refresh_started")]
        if notable:
            part += " · " + ", ".join(notable)
        parts.append(part)
        facts.append({"id": identity, "mode": mode, "never_staged": never_staged, "uses": used,
                      "uses_bound": bound,
                      "unconfirmed": None if used is None else unconfirmed.get(identity, 0),
                      "transitions": transitions.get(identity, [])})
    text = ("credential " if len(parts) == 1 else "credentials ") + capped(parts, "; ")
    refused = None
    if vault and counts(claim):
        refused = refusals
        if not (claim == "at_least" and refusals == 0):
            text += f" · {number(claim, refusals)} {noun(refusals, 'credential refusal', 'credential refusals')}"
    return text, {"credentials": facts[:JSON_LIST], "omitted": max(0, len(facts) - JSON_LIST),
                  "refusals": refused, "refusals_bound": claim if vault else "not_observed"}


def evidence_line(receipt, claims, state, size, another):
    observe = string(receipt, "policy", "observe") or "on"
    observe_off = observe == "off"
    attached = pointer(receipt, "observer", "attached")
    parts, gaps = [], []
    statuses = {name: status_of(receipt, name) for name in CLASSES}
    if observe_off:
        parts.append("observation off: exec, file and connect classes not observed")
    else:
        if attached is False:
            parts.append("observer not attached")
        active = sum(1 for name in CLASSES if statuses[name] == "active" and claims[name] != "disagree")
        observer_gaps = pointer(receipt, "observer", "gaps")
        observer_gaps = len(observer_gaps) if isinstance(observer_gaps, list) else 0
        if active == 6 and state == "complete" and observer_gaps == 0 and attached is not False:
            parts.append("6/6 classes active, no gaps")
        else:
            parts.append(f"{active}/6 classes active")
    not_started, not_observed = [], []
    for name in CLASSES:
        if observe_off and name in AUDIT_CLASSES:
            continue
        status = statuses[name]
        if status == "degraded":
            class_gaps = pointer(receipt, "coverage", name, "gaps")
            class_gaps = class_gaps if isinstance(class_gaps, list) else []
            item = f"{name} degraded"
            if class_gaps:
                reason = string(class_gaps[0], "reason") or "?"
                lost = unsigned(pointer(class_gaps[0], "lost_count"))
                item += f" ({esc(reason)}, lost {'unknown' if lost is None else lost}"
                if len(class_gaps) > 1:
                    item += f", +{len(class_gaps) - 1} more gaps"
                item += ")"
            parts.append(item)
            for gap in class_gaps:
                gaps.append({"class": name, "reason": pointer(gap, "reason"), "lost_count": pointer(gap, "lost_count")})
        elif status == "supported":
            not_started.append(name)
        elif status != "active":
            not_observed.append(name)
    for names, said in ((not_started, "not started"), (not_observed, "not observed")):
        if names:
            parts.append(", ".join(names) + " " + said)
    disagree = [name for name in CLASSES if claims[name] == "disagree"]
    parts.extend(f"journal and receipt disagree on {name}" for name in disagree)
    if state == "incomplete":
        parts.append("journal ends on another receipt's note: counts above are lower bounds" if another
                     else "journal incomplete: counts above are lower bounds")
    elif state != "complete":
        parts.append(missing(state, size))
    if not observe_off and any(statuses[name] in ("active", "degraded") for name in AUDIT_CLASSES):
        parts.append("reads and file contents are not observed")
    facts = {"observe": observe, "evidence": string(receipt, "policy", "evidence"),
             "attached": attached if isinstance(attached, bool) else None,
             "classes": statuses, "gaps": gaps, "disagree": disagree}
    return "evidence: " + " · ".join(parts), facts


def limits_line(receipt):
    limits = pointer(receipt, "applied", "limits")
    if not isinstance(limits, list):
        return None
    hit, not_applied = [], []
    for limit in limits:
        pair = (string(limit, "key") or "?", string(limit, "requested") or "?")
        if pointer(limit, "hit") is True:
            hit.append(pair)
        if pointer(limit, "applied") is False:
            not_applied.append(pair)
    if not hit and not not_applied:
        return None
    render = lambda pairs: capped([f"{esc(key)} ({esc(requested)})" for key, requested in pairs], ", ")
    parts = ([f"hit {render(hit)}"] if hit else []) + ([f"not applied: {render(not_applied)}"] if not_applied else [])
    listed = lambda pairs: [{"key": key, "requested": requested} for key, requested in pairs]
    return "limits: " + " · ".join(parts), {"hit": listed(hit), "not_applied": listed(not_applied)}


def state_line(receipt):
    """J14 (jail-interactive-sessions.md §4.7): the persistent vendor state;
    the facts are the receipt's `vendor_state` values."""
    state = pointer(receipt, "vendor_state")
    if not isinstance(state, dict):
        return None
    cleanup = string(receipt, "state_cleanup")
    field = lambda name: esc(state[name]) if isinstance(state.get(name), str) else None
    kind = state.get("kind")
    if kind == "attempt_fallback":
        holder = field("held_by") or "another attempt"
        if state.get("reason") == "unreleased":
            text = (f"state: NOT kept · this session used throwaway state because {holder} had not "
                    "released the persistent state for this workspace (run ukai-jail gc)")
        else:
            text = (f"state: NOT kept · this session used throwaway state because {holder} held the "
                    "persistent state for this workspace")
    elif kind == "persistent":
        generation = state.get("generation_end")
        source = field("inherited_from") or "an earlier attempt"
        matches, reason = state.get("matches_release"), state.get("matches_release_reason")
        if state.get("secret_scan") == "found":
            text = "state: quarantined: a vault credential's value was found in it"
        elif cleanup != "released" or unsigned(generation) is None:
            text = "state: release pending: run ukai-jail gc"
        elif matches is True:
            text = f"state: kept, generation {generation} · started from what {source} released, unchanged"
        elif matches is False:
            text = f"state: kept, generation {generation} · CHANGED outside the jail since {source} released it"
        elif reason == "new_state":
            text = f"state: kept, generation {generation} · new for this workspace"
        elif reason == "state_too_large":
            text = (f"state: kept, generation {generation} · started from what {source} released; "
                    "too large to tell whether it changed")
        else:
            text = (f"state: kept, generation {generation} · started from what {source} released; "
                    "whether it changed is unknown (unreadable)")
        if text.startswith("state: kept") and state.get("secret_scan") == "not_scanned":
            text += " · NOT searched for vault values"
    else:
        return None
    return text, state


def cleanup_line(receipt):
    cleanup, protection = string(receipt, "state_cleanup"), string(receipt, "child_protection")
    persistent = pointer(receipt, "vendor_state", "kind") == "persistent"
    restored = pointer(receipt, "applied", "terminal", "restored")
    failed = [name for field, name in (("foreground", "foreground"), ("termios", "termios"),
                                       ("input_flushed", "input"))
              if isinstance(restored, dict) and restored.get(field) is False]
    parts = (["vendor state cleanup pending: run ukai-jail gc"]
             if cleanup == "pending" and not persistent else []) + \
        ([f"terminal not restored ({', '.join(failed)}): run reset"] if failed else []) + \
        (["uncontained (none): nothing above was enforced"] if protection == "unprotected" else [])
    if not parts:
        return None
    facts = {"state_cleanup": cleanup, "child_protection": protection}
    if isinstance(restored, dict):
        facts["terminal_restored"] = restored
    return " · ".join(parts), facts


# --------------------------------------------------------------------------
# Bounded evidence acquisition and independent VM composition.

VM_SCHEMA = 'ukai.jail.vm-transport/1'
JOURNAL_PART = 512 * 1024
DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate JSON member')
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs, parse_constant=no_constant)


def equal(left, right):
    # Python's bool/int and int/float equality is not JSON equality.
    return json.dumps(left, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(
        right, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


class EvidenceReader:
    """All descendants are read from pinned no-follow directory descriptors."""
    def __init__(self, root):
        self.stack = contextlib.ExitStack()
        self.root = Path(root).absolute()
        self.directories = {}
        self.hashes = {}
        self.cache = {}

    def __enter__(self):
        try:
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
            self.stack.callback(os.close, fd)
            for name in self.root.parts[1:]:
                require(name not in ('', '.', '..'), 'noncanonical evidence path')
                fd = self._directory(name, fd)
            self.directories[''] = fd
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def _directory(self, name, parent):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        self.stack.callback(os.close, fd)
        return fd

    def directory(self, relative):
        if relative not in self.directories:
            parent, _, name = relative.rpartition('/')
            require(name not in ('', '.', '..'), 'invalid evidence component')
            self.directories[relative] = self._directory(name, self.directory(parent))
        return self.directories[relative]

    def listing(self, relative, maximum):
        with os.scandir(self.directory(relative)) as entries:
            result = []
            for entry in entries:
                result.append(entry.name)
                require(len(result) <= maximum, 'too many evidence entries')
        return sorted(result)

    def read(self, relative, cap, optional=False):
        if relative in self.cache:
            return self.cache[relative]
        parent, _, name = relative.rpartition('/')
        require(name not in ('', '.', '..'), 'invalid evidence component')
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=self.directory(parent))
        except FileNotFoundError:
            if optional:
                return None
            raise
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
                    'evidence is oversized or not one regular file')
            data = stream.read(cap + 1)
            after = os.fstat(fd)
        stamp = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(data) == before.st_size and stamp(before) == stamp(after), 'evidence changed during read')
        self.cache[relative] = data
        self.hashes[relative] = hashlib.sha256(data).hexdigest()
        return data


def object_json(data, label):
    value = strict_json(data)
    require(type(value) is dict, label + ' is not an object')
    return value


def receipt(data):
    value = object_json(data, 'receipt')
    require(value.get('schema') == 'ukai.jail.receipt/1' and type(value.get('attempt_id')) is str
            and bool(value['attempt_id']), 'invalid receipt identity')
    canonical_digest(value)  # Reject values outside the canonical receipt domain.
    return value


def compute_summary(value, frames, state, size=0, another=False):
    claims = {name: claim_of(value, name, frames, state) for name in CLASSES}
    lines = [('status', status_line(value, frames, state in ('complete', 'incomplete'))),
             ('workspace', workspace_line(value, frames, claims, state, size)),
             ('network', network_line(value, frames, claims, state, size)),
             ('credentials', credentials_line(value, frames, claims, state, size)),
             ('state', state_line(value)),
             ('evidence', evidence_line(value, claims, state, size, another)),
             ('limits', limits_line(value)), ('cleanup', cleanup_line(value))]
    return {'schema': 'ukai.jail.summary/1', 'attempt_id': value['attempt_id'],
            'receipt_digest': canonical_digest(value), 'journal': 'absent' if state == 'guest' else state,
            'lines': [{'line': name, 'text': line[0], 'facts': line[1]}
                      for name, line in lines if line is not None]}


def complete_guest_journal(reader, guest, receipt_hash):
    root = 'evidence/guest-journal'
    manifest = object_json(reader.read(root + '/manifest.json', 4096), 'guest journal manifest')
    keys = {'schema', 'guest_attempt_id', 'guest_receipt_sha256', 'state', 'bytes', 'parts', 'sha256'}
    require(set(manifest) == keys and manifest['schema'] == 'ukai.vm.guest-journal/1'
            and manifest['guest_attempt_id'] == guest['attempt_id']
            and manifest['guest_receipt_sha256'] == receipt_hash, 'guest journal receipt binding differs')
    size, parts = manifest['bytes'], manifest['parts']
    require(manifest['state'] == 'exported' and type(size) is int and 0 < size <= SCAN_CAP
            and type(parts) is int and parts == (size + JOURNAL_PART - 1) // JOURNAL_PART,
            'a named guest requires a complete bounded journal export')
    expected = ['manifest.json'] + [f'{index:04}.part' for index in range(parts)]
    require(reader.listing(root, SCAN_CAP // JOURNAL_PART + 1) == sorted(expected),
            'guest journal part set differs')
    chunks = []
    for index in range(parts):
        part = reader.read(root + f'/{index:04}.part', JOURNAL_PART)
        require(len(part) == min(JOURNAL_PART, size - index * JOURNAL_PART), 'guest journal part size differs')
        chunks.append(part)
    data = b''.join(chunks)
    require(hashlib.sha256(data).hexdigest() == manifest['sha256'], 'guest journal bytes differ')
    require(reader.listing(root, SCAN_CAP // JOURNAL_PART + 1) == sorted(expected),
            'guest journal entries changed')
    frames, complete, another = read_journal(data, canonical_digest(guest), guest['attempt_id'])
    require(complete and not another and guest.get('phase') == 'settled'
            and pointer(frames[-1], 'fields', 'phase') == 'settled', 'guest journal does not settle this receipt')
    return frames, len(data)


def parse_native_catalog(catalog_bytes):
    """Independent, bounded catalog parser for the retained evidence contract."""
    require(type(catalog_bytes) is bytes and 0 < len(catalog_bytes) <= 65536, "native catalog byte bound")
    catalog = object_json(catalog_bytes, 'native program catalog')
    require(set(catalog) == {'schema', 'entries'} and catalog['schema'] == 'ukai.vm.guest-program-catalog/1'
            and type(catalog['entries']) is list and 1 <= len(catalog['entries']) <= 16, 'native catalog shape')
    fields = {'id', 'alias', 'version', 'format', 'executable', 'install_root', 'program_root', 'argv_prefix',
              'executable_sha256', 'executable_size', 'profile_sha256', 'guest_jail_sha256',
              'supported_states', 'interpreter', 'tree'}
    ids, aliases = set(), set()
    for entry in catalog['entries']:
        require(type(entry) is dict and set(entry) == fields, 'native catalog entry shape')
        for name, pattern in [('id', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'),
                              ('alias', r'[a-z][a-z0-9_-]{0,63}'), ('version', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')]:
            require(type(entry[name]) is str and re.fullmatch(pattern, entry[name]) is not None,
                    'native catalog entry identifier')
        require(entry['id'] not in ids and entry['alias'] not in aliases, 'duplicate native catalog entry')
        ids.add(entry['id']); aliases.add(entry['alias'])
        root = '/opt/ukai/programs/' + entry['alias'] + '/' + entry['version']
        require(entry['install_root'] == root and entry['executable'] == root + '/' + entry['alias']
                and entry['argv_prefix'] == [entry['executable']] and entry['format'] == 'elf64-aarch64'
                and type(entry['program_root']) is int and entry['program_root'] == 1
                and type(entry['executable_size']) is int and 64 <= entry['executable_size'] <= 512 * 1024 * 1024
                and entry['supported_states'] == ['attempt'] and entry['interpreter'] == '/lib/ld-linux-aarch64.so.1',
                'native catalog program shape')
        require(all(type(entry[name]) is str and DIGEST.fullmatch(entry[name]) is not None
                    for name in ('executable_sha256', 'profile_sha256', 'guest_jail_sha256')), 'native catalog hash')
        tree = [{'path': '.', 'kind': 'directory', 'mode': 365, 'uid': 0, 'gid': 0},
                {'path': entry['alias'], 'kind': 'file', 'mode': 365, 'uid': 0, 'gid': 0, 'nlink': 1}]
        require(equal(entry['tree'], tree), 'native catalog inventory differs')
    return catalog


def native_program_binding(reader, guest, transport, binding):
    """Bind native intent to retained catalog and actual Linux receipt.

    This checks the record's consistency, not that the guest installation was
    authentic or that the catalog's binary is safe. No guest path is opened.
    """
    intent, native = transport.get('native_program'), binding.get('native_program')
    catalog_bytes = reader.read('guest-native-catalog.json', 65536, optional=True)
    if intent is None and native is None:
        require(catalog_bytes is None, 'native catalog has no native program intent')
        return
    intent_fields = {'schema', 'catalog_sha256', 'entry_id', 'launch_name', 'profile_sha256', 'state',
                     'selected_credential_id', 'argv_suffix', 'request_argv_digest',
                     'resolved_argv_digest', 'expected_policy_digest'}
    binding_fields = {'catalog_sha256', 'entry_id', 'profile_sha256', 'executable_sha256',
                      'selected_credential_id', 'state', 'request_argv_digest', 'resolved_argv_digest', 'policy_digest'}
    require(type(intent) is dict and set(intent) == intent_fields and type(native) is dict
            and set(native) == binding_fields, 'native program intent/binding fields differ')
    require(intent['schema'] == 'ukai.vm.guest-native-launch/1' and intent['state'] == 'attempt'
            and type(intent['selected_credential_id']) is str
            and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', intent['selected_credential_id']) is not None,
            'native program contract, state or credential differs')
    require(catalog_bytes is not None, 'native program catalog is missing')
    catalog_digest = hashlib.sha256(catalog_bytes).hexdigest()
    require(catalog_digest == intent['catalog_sha256']
            == pointer(transport, 'image', 'guest_program_catalog_sha256'), 'native catalog image binding differs')
    catalog = parse_native_catalog(catalog_bytes)
    matches = [entry for entry in catalog['entries'] if entry['id'] == intent['entry_id']]
    require(len(matches) == 1, 'native catalog entry is missing')
    entry = matches[0]
    require(intent['launch_name'] == entry['alias'] and intent['profile_sha256'] == entry['profile_sha256'],
            'native bundled profile differs')
    encoded = intent['argv_suffix']
    require(type(encoded) is list and len(encoded) <= 4096, 'native argv shape')
    suffix, total = [], 0
    for value in encoded:
        require(type(value) is str, 'native argv type')
        word = base64.b64decode(value, validate=True)
        total += len(word)
        require(base64.b64encode(word).decode() == value and b'\0' not in word and total <= 1024 * 1024,
                'native argv encoding or bound')
        suffix.append(word)
    require(len(suffix) + 1 <= 4096 and total + len(entry['executable'].encode()) <= 1024 * 1024,
            'native resolved argv exceeds transport bound')
    def digest(words):
        raw = b'ukai.jail.argv/1\0' + struct.pack('>Q', len(words))
        raw += b''.join(struct.pack('>Q', len(word)) + word for word in words)
        return 'sha256:' + hashlib.sha256(raw).hexdigest()
    require(intent['request_argv_digest'] == digest([entry['alias'].encode(), *suffix])
            and intent['resolved_argv_digest'] == digest([entry['executable'].encode(), *suffix])
            == guest.get('argv_digest') == binding.get('argv_digest'), 'native requested/resolved argv differs')
    policy = intent['expected_policy_digest']
    require(type(policy) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', policy) is not None
            and policy == pointer(guest, 'policy', 'digest'), 'native actual policy differs from expected policy')
    expected = {key: intent[key] for key in binding_fields - {'executable_sha256', 'policy_digest'}}
    expected.update(executable_sha256=entry['executable_sha256'], policy_digest=policy)
    require(equal(native, expected), 'native program binding differs')
    return entry


MANAGED_SAMPLE_SCHEMA = 'ukai.vm.sampled-exposure/3'
MANAGED_REQUIREMENTS = {'tree_termination', 'closed_set_observation', 'filesystem_containment', 'syscall_filter',
                        'network_proxy', 'protected_coverage:existing_and_root', 'limit:wall', 'limit:pids',
                        'limit:mem', 'limit:swap', 'execution_boundary', 'credential_staging'}


def managed_sampling_gate(report, guest, binding, native, prepared_raw, entry):
    """Authenticate Prepared independently; return whether managed observation finished.

    The final receipt has already passed retained native/transport binding.
    This verifies record consistency, not policy reconstruction: the live host
    checks final network/limits against its plan, and qualification tooling checks
    grants against its pinned profile context. No executable path is read.
    Controller timestamps bracket operations, not exact kernel exec instants.
    """
    gate = report['managed_gate']
    fields = {'schema', 'prepared_receipt_sha256', 'prepared_receipt_digest', 'prepared_process',
              'prepared_observed_ns', 'prepared_validated_ns', 'armed_observed_ns',
              'release_started_ns', 'release_completed_ns', 'failure'}
    uint = lambda value: type(value) is int and 0 <= value <= U64_MAX
    require(type(gate) is dict and set(gate) == fields and gate['schema'] == 'ukai.vm.managed-native-gate/1',
            'managed gate shape differs')
    require(gate['failure'] in (None, 'control_invalid', 'prepared_invalid', 'source_changed',
                               'arming_failed', 'release_failed', 'cancelled', 'early_stop'), 'managed gate failure differs')
    require(type(prepared_raw) is bytes and 0 < len(prepared_raw) <= 512 * 1024 and type(entry) is dict,
            'managed Prepared artifact/context missing')
    prepared = receipt(prepared_raw)
    require(gate['prepared_receipt_sha256'] == hashlib.sha256(prepared_raw).hexdigest()
            and gate['prepared_receipt_digest'] == canonical_digest(prepared), 'managed Prepared digest differs')
    process = report['receipt_process']
    require(equal(gate['prepared_process'], process) and 0 < process['pid'] <= 2 ** 32 - 1,
            'managed Prepared process differs')
    identity = {'pid': process['pid'], 'identity': {'kind': 'linux_boot_start', 'value': {
        'boot_id': binding['guest_boot_id'], 'pid': process['pid'], 'start_time_ticks': process['starttime']}}}
    require(equal(prepared.get('process'), identity) and equal(guest.get('process'), identity)
            and prepared.get('attempt_id') == binding['guest_attempt_id'] == guest.get('attempt_id')
            and re.fullmatch(r'att_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
                             prepared['attempt_id']) is not None, 'managed Prepared identity differs')
    require(pointer(prepared, 'platform', 'os') == 'linux' and pointer(prepared, 'platform', 'arch') == 'aarch64'
            and pointer(prepared, 'jail', 'component') == 'ukai-jail' and pointer(prepared, 'jail', 'backend') == 'bubblewrap'
            and equal(prepared.get('platform'), guest.get('platform')) and equal(prepared.get('jail'), guest.get('jail')),
            'managed Prepared platform differs')
    require(prepared.get('phase') == 'prepared' and prepared.get('exec_observed') is False
            and equal(prepared.get('outcome'), {'kind': 'pending', 'code': None, 'signal': None, 'cause': None, 'error': None})
            and prepared.get('containment') == prepared.get('child_protection') == 'enforced'
            and prepared.get('errors') == [] and 'cleanup_error' in prepared and prepared['cleanup_error'] is None
            and prepared.get('vendor_state') is None, 'managed Prepared authority differs')
    lifetime = prepared.get('lifetime') or {}
    require(type(lifetime) is dict and lifetime.get('boundary') == 'pid_namespace'
            and 'tree_empty' in lifetime and lifetime['tree_empty'] is None
            and lifetime.get('integrity') == 'verified' and lifetime.get('verification_scope') == 'attempt_tree',
            'managed Prepared lifetime differs')
    require(equal(prepared.get('observer'), {'backend': None, 'set': None, 'attached': False,
            'sources': {'wrapper': 'supported', 'audit': 'unsupported', 'proxy': 'unsupported'}, 'gaps': []}),
            'managed Prepared observer differs')
    require(equal(prepared.get('credentials'), [{'id': native['selected_credential_id'], 'mode': 'vault',
            'never_staged': True, 'digest': None, 'digest_unavailable_reason': 'never_staged'}]),
            'managed Prepared selected credential differs')
    policy = prepared.get('policy') or {}
    require(type(policy) is dict and set(policy) == {'name', 'digest', 'observe', 'evidence', 'requirements', 'grants'},
            'managed Prepared policy shape differs')
    requirements = policy.get('requirements')
    require(policy.get('name') == 'agent' and policy.get('observe') == 'on' and policy.get('evidence') == 'strict'
            and policy.get('digest') == native['policy_digest'] == pointer(guest, 'policy', 'digest')
            and prepared.get('argv_digest') == native['resolved_argv_digest'] == guest.get('argv_digest')
            and type(requirements) is list and all(type(value) is str for value in requirements)
            and len(requirements) == len(MANAGED_REQUIREMENTS) and set(requirements) == MANAGED_REQUIREMENTS,
            'managed Prepared policy differs')
    grants = policy.get('grants')
    require(type(grants) is list and all(type(row) is dict and set(row) == {'kind', 'value', 'by'} for row in grants),
            'managed Prepared grants shape differs')
    normalized = lambda rows: sorted(canonical_value(row) for row in rows)
    require(normalized(grants) == normalized(pointer(guest, 'policy', 'grants')),
            'managed Prepared grants differ from bound final policy')
    roots = [row for row in grants if row['kind'] == 'read_only']
    hosts = [row for row in grants if row['kind'] == 'allow_host']
    require(roots == [{'kind': 'read_only', 'value': entry['install_root'], 'by': 'program_resolution'}]
            and len(roots) + len(hosts) == len(grants)
            and all(row['by'] == 'operator' and type(row['value']) is str for row in hosts), 'managed Prepared program grant differs')
    applied, final_applied = prepared.get('applied') or {}, guest.get('applied') or {}
    filesystem = applied.get('filesystem') or {}
    mounts = filesystem.get('mounts')
    require(filesystem.get('mechanism') == 'bubblewrap-binds' and filesystem.get('protected_coverage') == 'existing_and_root'
            and type(mounts) is list and mounts and all(type(row) is dict and set(row) == {'path', 'mode'}
            and type(row['path']) is str and row['mode'] in ('ro', 'rw', 'hidden') for row in mounts)
            and {'path': entry['install_root'], 'mode': 'ro'} in mounts
            and {'path': '/mnt/workspace', 'mode': 'rw'} in mounts, 'managed Prepared filesystem differs')
    network = applied.get('network') or {}
    require(network.get('mode') == 'proxy'
            and network.get('mechanism') == 'network-namespace+outside-http-proxy+loopback-bridge+unix-peer-mediation'
            and equal(network, final_applied.get('network')), 'managed Prepared network differs')
    allowed, tls_only = network.get('allowed_hosts'), network.get('tls_only', [])
    require(all(type(values) is list and all(type(value) is str for value in values)
                for values in (allowed, tls_only)), 'managed Prepared network list differs')
    require(sorted(allowed) == sorted(row['value'] for row in hosts)
            and set(tls_only) <= set(allowed), 'managed Prepared network grants differ')
    syscalls = applied.get('syscalls') or {}
    require(syscalls.get('mechanism') == 'seccomp-bpf+seccomp-user-notification'
            and type(syscalls.get('digest')) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', syscalls['digest']) is not None,
            'managed Prepared syscall filter differs')
    for key in ('environment_names', 'removed_environment_names'):
        require(type(applied.get(key)) is list and all(type(value) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value)
                for value in applied[key]), 'managed Prepared environment names differ')
    require(applied.get('terminal') is None, 'managed Prepared terminal differs')
    limits, final_limits = applied.get('limits'), final_applied.get('limits')
    require(type(limits) is list and type(final_limits) is list and len(limits) == len(final_limits) == 4,
            'managed Prepared limit count differs')
    mechanisms = {'wall': 'boottime-deadline', 'pids': 'pids.max', 'mem': 'memory.max', 'swap': 'memory.swap.max'}
    seen = set()
    for row in limits:
        require(type(row) is dict and set(row) == {'key', 'requested', 'required', 'applied', 'mechanism', 'scope', 'hit'}
                and type(row['key']) is str and row['key'] in mechanisms and row['key'] not in seen,
                'managed Prepared limit shape differs')
        seen.add(row['key'])
        requested = row['requested']
        require(type(requested) is str and re.fullmatch(r'0|[1-9][0-9]*', requested) is not None
                and int(requested) <= U64_MAX and row['required'] is True and row['applied'] is True
                and row['scope'] == 'tree' and row['mechanism'] == mechanisms[row['key']]
                and (row['hit'] is False or row['hit'] is None), 'managed Prepared limit authority differs')
        require((row['key'] == 'wall' and int(requested) > 0) or requested == {'pids': '64', 'mem': '536870912', 'swap': '0'}.get(row['key']),
                'managed Prepared ceiling differs')
        matching = [item for item in final_limits if item.get('key') == row['key']]
        require(len(matching) == 1 and all(equal(matching[0].get(key), row[key]) for key in ('requested', 'required', 'applied', 'scope')),
                'managed Prepared/final requested ceiling differs')
    observed, validated, armed, release, completed = (gate[key] for key in
        ('prepared_observed_ns', 'prepared_validated_ns', 'armed_observed_ns', 'release_started_ns', 'release_completed_ns'))
    started, exited, stopped = (report['lifecycle'][key] for key in ('started_ns', 'supervisor_exit_observed_ns', 'stopped_ns'))
    require(uint(observed) and uint(validated) and uint(started) and observed <= validated <= started,
            'managed Prepared time order differs')
    require(all(value is None or uint(value) for value in (armed, release, completed))
            and (armed is None or (report['first_ns'] is not None and report['first_ns'] <= armed))
            and (release is None or (armed is not None and armed <= release))
            and (completed is None or (release is not None and release <= completed)), 'managed release causal order differs')
    return (gate['failure'] is None and completed is not None and exited is not None and stopped is not None
            and completed <= exited <= stopped and report['last_ns'] is not None and report['last_ns'] <= exited
            and report['lifecycle']['stop_reason'] == 'supervisor_exit' and guest.get('exec_observed') is True
            and guest.get('phase') == 'settled' and pointer(guest, 'lifetime', 'tree_empty') is True
            and pointer(guest, 'lifetime', 'integrity') == 'verified' and guest.get('cleanup_error') is None)


def sampled_exposure_report(report, guest, receipt_hash, binding, native, sampler_hash, supervisor_pid, *, prepared_raw=None, native_entry=None):
    """Independently validate bounded sampled observations, never memory absence."""
    keys = {'schema', 'host_attempt_id', 'service_boot_id', 'guest_attempt_id', 'guest_boot_id',
            'catalog_sha256', 'executable_sha256', 'sampler_sha256', 'guest_receipt_sha256',
            'finished', 'actual_values_retained', 'scope', 'continuous_coverage_claimed', 'arbitrary_memory_examined',
            'period_ns', 'first_ns', 'last_ns', 'observed_interval_ns', 'maximum_gap_ns', 'maximum_tick_duration_ns',
            'tick_count', 'late_poll_count', 'missed_tick_count', 'reads', 'verified_program_reads',
            'receipt_program_reads', 'receipt_program_observed', 'receipt_process',
            'verified_program_observed', 'observation_incomplete', 'scan_errors', 'hits', 'processes',
            'supervisor', 'catalog_executable_identity', 'workload_uid', 'limits', 'lifecycle'}
    managed = type(report) is dict and report.get('schema') == MANAGED_SAMPLE_SCHEMA
    require(type(report) is dict and set(report) == keys | ({'managed_gate'} if managed else set())
            and report['schema'] in ('ukai.vm.sampled-exposure/2', MANAGED_SAMPLE_SCHEMA), 'sampled exposure schema differs')
    expected = {'host_attempt_id': binding['attempt_id'], 'service_boot_id': binding['boot_id'],
                'guest_attempt_id': guest['attempt_id'], 'guest_boot_id': binding['guest_boot_id'],
                'guest_receipt_sha256': receipt_hash, 'catalog_sha256': native['catalog_sha256'],
                'executable_sha256': native['executable_sha256'], 'sampler_sha256': sampler_hash}
    require(all(report[key] == value for key, value in expected.items()), 'sampled exposure identity differs')
    require(report['finished'] is True and report['actual_values_retained'] is False
            and report['continuous_coverage_claimed'] is False and report['arbitrary_memory_examined'] is False
            and report['scope'] == ('managed-native-periodic-readable-environment-and-argv-only' if managed
                                    else 'periodic-readable-environment-and-argv-only'), 'sampled exposure scope differs')
    def uint(value, minimum=0):
        return type(value) is int and minimum <= value < 2 ** 64
    for key in ('period_ns', 'observed_interval_ns', 'maximum_gap_ns', 'maximum_tick_duration_ns',
                'tick_count', 'late_poll_count', 'missed_tick_count', 'workload_uid'):
        require(uint(report[key]), 'invalid sampled exposure counter')
    require(report['period_ns'] == 100_000_000, 'sampled exposure period differs')
    require(1 <= report['workload_uid'] <= 2 ** 32 - 1, 'sampled workload UID differs')
    ticks = report['tick_count']
    if ticks:
        require(uint(report['first_ns']) and uint(report['last_ns']) and report['first_ns'] <= report['last_ns']
                and report['observed_interval_ns'] == report['last_ns'] - report['first_ns']
                and report['late_poll_count'] <= ticks - 1, 'sampled exposure timing differs')
        require((ticks == 1 and report['maximum_gap_ns'] == report['observed_interval_ns'] == 0)
                or (ticks > 1 and 0 < report['maximum_gap_ns'] <= report['observed_interval_ns']
                    <= report['maximum_gap_ns'] * (ticks - 1)), 'sampled exposure gap differs')
        require((report['maximum_gap_ns'] > report['period_ns']) == (report['late_poll_count'] > 0)
                and (report['maximum_gap_ns'] >= 2 * report['period_ns']) == (report['missed_tick_count'] > 0)
                and report['missed_tick_count'] <= report['observed_interval_ns'] // report['period_ns'],
                'sampled exposure late counters differ')
    else:
        require(report['first_ns'] is None and report['last_ns'] is None
                and all(report[key] == 0 for key in ('observed_interval_ns', 'maximum_gap_ns',
                                                     'late_poll_count', 'missed_tick_count')), 'empty sampling timing differs')
    channels = {'environment', 'argv'}
    states = {'readable', 'unreadable', 'oversize', 'vanished', 'unstable', 'capped'}
    for key in ('reads', 'verified_program_reads', 'receipt_program_reads'):
        rows = report[key]
        require(type(rows) is dict and set(rows) == channels and all(type(row) is dict and set(row) == states
                and all(uint(value) for value in row.values()) for row in rows.values()), 'sampled exposure read counters differ')
        require(sum(rows['environment'].values()) == sum(rows['argv'].values())
                <= ticks * (1 if key == 'receipt_program_reads' else 4096), 'sampled exposure population counters differ')
    require(all(report['verified_program_reads'][channel][state] <= report['reads'][channel][state]
                for channel in channels for state in states), 'sampled program counts exceed population')
    require(all(report['receipt_program_reads'][channel][state] <= report['verified_program_reads'][channel][state]
                for channel in channels for state in states), 'sampled receipt program counts exceed aggregate')
    errors = report['scan_errors']
    error_codes = {'malformed_stat', 'malformed_status', 'tick_time_cap', 'tick_byte_cap', 'nonregular_proc_file',
                   'oversize', 'boot_identity_changed', 'nonregular_executable', 'identity_cap', 'hit_cap',
                   'identity_changed', 'proc_root_changed', 'invalid_pid_entry', 'process_cap', 'supervisor_unobserved',
                   'inventory_vanished', 'inventory_unreadable', 'selected_process_vanished',
                   'selected_process_unreadable', 'proc_root_vanished', 'proc_root_unreadable',
                   'monitor_initialization_failed', 'monitor_worker_failed', 'monitor_join_timeout'}
    require(type(errors) is dict and set(errors) <= error_codes and all(uint(value, 1) for value in errors.values()),
            'sampled exposure errors differ')
    require(report['maximum_tick_duration_ns'] <= 50_000_000 or errors.get('tick_time_cap', 0) > 0,
            'sampled tick overrun lacks error')
    positive = all(report['verified_program_reads'][channel]['readable'] > 0 for channel in channels)
    receipt_positive = all(report['receipt_program_reads'][channel]['readable'] > 0 for channel in channels)
    incomplete = bool(errors) or not positive or not receipt_positive or ticks == 0 or any(
        row[state] for row in report['reads'].values() for state in states - {'readable'})
    require(report['verified_program_observed'] is positive and report['receipt_program_observed'] is receipt_positive,
            'sampled exposure positive observation claim differs')
    limits = {'read_bytes': 2 * 1024 * 1024, 'process_count': 4096, 'tick_bytes': 16 * 1024 * 1024,
              'tick_ns': 50_000_000, 'hit_count': 4096}
    require(equal(report['limits'], limits), 'sampled exposure bounds differ')
    processes = report['processes']; identities = set()
    require(type(processes) is list and len(processes) <= 4096, 'sampled exposure population bound')
    for process in processes:
        require(type(process) is dict and set(process) == {'pid', 'starttime', 'roles'}
                and uint(process['pid'], 1) and uint(process['starttime'], 1), 'sampled process identity differs')
        identity = process['pid'], process['starttime']
        require(identity not in identities, 'duplicate sampled process')
        identities.add(identity)
        roles = process['roles']
        require(type(roles) is list and bool(roles) and all(type(role) is str for role in roles)
                and roles == sorted(set(roles)) and set(roles) <= {'supervisor', 'descendant', 'workload_uid', 'catalog_program'},
                'sampled process role differs')
    require(not positive or any('catalog_program' in process['roles'] for process in processes), 'no sampled program identity')
    supervisor = report['supervisor']; executable = report['catalog_executable_identity']
    receipt_process = report['receipt_process']
    require(type(receipt_process) is dict and set(receipt_process) == {'pid', 'starttime'}
            and all(uint(value, 1) for value in receipt_process.values())
            and uint(pointer(guest, 'process', 'identity', 'value', 'pid'), 1)
            and uint(pointer(guest, 'process', 'identity', 'value', 'start_time_ticks'), 1)
            and receipt_process['pid'] == pointer(guest, 'process', 'identity', 'value', 'pid')
            and receipt_process['starttime'] == pointer(guest, 'process', 'identity', 'value', 'start_time_ticks')
            and pointer(guest, 'process', 'identity', 'kind') == 'linux_boot_start', 'sampled receipt workload differs')
    require(not receipt_positive or any(process['pid'] == receipt_process['pid']
                and process['starttime'] == receipt_process['starttime'] and 'catalog_program' in process['roles']
                for process in processes), 'sampled receipt program identity absent')
    require(type(supervisor) is dict and set(supervisor) == {'pid', 'starttime'}
            and uint(supervisor_pid, 1) and supervisor_pid <= 2 ** 32 - 1
            and supervisor['pid'] == supervisor_pid and uint(supervisor['pid'], 1)
            and (uint(supervisor['starttime'], 1) or (supervisor['starttime'] is None and ticks == 0
                and not positive and not receipt_positive and processes == [] and report['hits'] == []
                and all(sum(row.values()) == 0 for row in report['reads'].values())
                and errors.get('monitor_initialization_failed', 0) > 0)), 'sampled released supervisor differs')
    require(type(executable) is dict and set(executable) == {'dev', 'ino'} and uint(executable['dev'])
            and uint(executable['ino']) and (executable['ino'] > 0 or (executable['dev'] == 0 and ticks == 0 and not positive
                and errors.get('monitor_initialization_failed', 0) > 0)), 'sampled executable identity differs')
    supervisor_observed = any(process['pid'] == supervisor['pid'] and process['starttime'] == supervisor['starttime']
                              and 'supervisor' in process['roles'] for process in processes)
    incomplete = incomplete or not supervisor_observed
    lifecycle = report['lifecycle']
    require(type(lifecycle) is dict and set(lifecycle) == {'started_ns', 'supervisor_exit_observed_ns', 'stopped_ns', 'stop_reason'}
            and lifecycle['stop_reason'] in {'manual', 'requested', 'supervisor_exit', 'worker_failed', 'join_timeout'}
            and all(value is None or uint(value) for key, value in lifecycle.items() if key != 'stop_reason'),
            'sampled lifecycle differs')
    started, exited, stopped = (lifecycle[key] for key in ('started_ns', 'supervisor_exit_observed_ns', 'stopped_ns'))
    if managed:
        incomplete = not managed_sampling_gate(report, guest, binding, native, prepared_raw, native_entry) or incomplete
    require(report['observation_incomplete'] is incomplete, 'sampled exposure availability claim differs')
    if lifecycle['stop_reason'] == 'manual':
        require(started is exited is stopped is None, 'manual sampling lifecycle differs')
    else:
        require(started is not None and (exited is None or exited >= started)
                and (stopped is None or stopped >= started)
                and (incomplete or exited is None or stopped is None or exited <= stopped)
                and (not ticks or (started <= report['first_ns'] and (stopped is None or stopped >= report['last_ns']))),
                'sampled lifecycle time order differs')
    hits = report['hits']
    require(type(hits) is list and len(hits) <= 4096, 'sampled hit bound')
    for hit in hits:
        require(type(hit) is dict and set(hit) == {'pid', 'starttime', 'channel', 'representation', 'identity_stable'}
                and uint(hit['pid'], 1) and uint(hit['starttime'], 1) and hit['channel'] in channels
                and hit['representation'] in {'raw', 'base64', 'base64url', 'hex', 'url', 'json'}
                and type(hit['identity_stable']) is bool, 'sampled hit shape differs')
        require(incomplete or (hit['identity_stable'] and (hit['pid'], hit['starttime']) in identities),
                'complete sampling has unbound hit')
    result = {'state': 'incomplete' if incomplete else 'complete', 'no_hits': hits == [],
            'verified_program_observed': positive, 'period_ns': report['period_ns'], 'tick_count': ticks,
            'receipt_program_observed': receipt_positive, 'receipt_program_reads': report['receipt_program_reads'],
            'receipt_process': receipt_process, 'supervisor': supervisor,
            'first_ns': report['first_ns'], 'last_ns': report['last_ns'], 'observed_interval_ns': report['observed_interval_ns'],
            'maximum_gap_ns': report['maximum_gap_ns'], 'late_poll_count': report['late_poll_count'],
            'missed_tick_count': report['missed_tick_count'], 'reads': report['reads'],
            'verified_program_reads': report['verified_program_reads'], 'scan_errors': errors,
            'scope': report['scope'], 'sampler_sha256': sampler_hash, 'lifecycle': lifecycle}
    if managed:
        result.update(schema=MANAGED_SAMPLE_SCHEMA, managed_gate=report['managed_gate'])
    return result


def sampled_exposure(reader, guest, transport, binding, receipt_hash):
    """Sampling failure is separate from an actual receipt and its rendering."""
    native = binding.get('native_program')
    if native is None:
        return {'state': 'invalid', 'reason': 'unexpected_sampling_evidence'} if (
            binding.get('sampled_exposure_sha256') is not None or transport.get('sampled_exposure') is not None
            or transport.get('sampled_exposure_contract') is not None
        ) else {'state': 'not_requested'}
    try:
        status = transport.get('sampled_exposure')
        require(type(status) is dict and {'status'} <= set(status) <= {'status', 'path', 'sha256', 'reason'}
                and status['status'] in {'complete', 'incomplete', 'invalid', 'unavailable'}, 'sampling status')
        require('reason' not in status or (type(status['reason']) is str
                and re.fullmatch(r'[a-z0-9_-]{1,64}', status['reason']) is not None), 'sampling reason')
        require('path' not in status or status['path'] == 'evidence/sampled-exposure.json', 'sampling path')
        raw = reader.read('evidence/sampled-exposure.json', 512 * 1024, optional=True)
        pin = pointer(transport, 'image', 'sampler_sha256')
        if 'sampler_sha256' in transport['image']:
            require(type(pin) is str and DIGEST.fullmatch(pin) is not None, 'sampling source pin')
        if raw is None or pin is None:
            require(status['status'] == 'unavailable', 'sampling availability contradicts transport')
            return {'state': 'unavailable', 'reason': 'missing_report_or_source_pin'}
        digest = hashlib.sha256(raw).hexdigest()
        require(binding.get('sampled_exposure_sha256') == digest, 'sampling report hash')
        require(status.get('path') == 'evidence/sampled-exposure.json' and status.get('sha256') == digest,
                'sampling transport report hash')
        if 'supervisor_pid' not in transport:
            require(status['status'] == 'unavailable', 'missing released supervisor contradicts transport')
            return {'state': 'unavailable', 'reason': 'released_supervisor_missing'}
        with EvidenceReader(Path(__file__).absolute().parent) as source:
            local_source = hashlib.sha256(source.read('guest_exposure.py', 512 * 1024)).hexdigest()
        require(pin == local_source, 'sampling archived source hash')
        report = object_json(raw, 'sampled exposure')
        contract = transport.get('sampled_exposure_contract')
        require(contract is None or contract == MANAGED_SAMPLE_SCHEMA == report.get('schema'), 'sampling Session contract differs')
        managed = report.get('schema') == MANAGED_SAMPLE_SCHEMA
        if managed:
            require(contract == MANAGED_SAMPLE_SCHEMA, 'managed sampling Session contract missing')
        entry = native_program_binding(reader, guest, transport, binding) if managed else None
        prepared = reader.read('evidence/managed-prepared.json', 512 * 1024) if managed else None
        result = sampled_exposure_report(report, guest, receipt_hash, binding, native, pin,
                                         transport.get('supervisor_pid'), prepared_raw=prepared, native_entry=entry)
        require(status['status'] == result['state'], 'sampling state contradicts transport')
        result.update(report_sha256=digest)
        return result
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        return {'state': 'invalid', 'reason': 'sampling_evidence_mismatch'}


def bound_guest(reader, host):
    details = pointer(host, 'lifetime', 'native', 'details')
    require(type(details) is dict, 'VM receipt has no details')
    transport = object_json(reader.read('vm-transport.json', RECEIPT_MAX), 'transport')
    guest_bytes = reader.read('evidence/jail.json', RECEIPT_MAX)
    guest = receipt(guest_bytes)
    binding = object_json(reader.read('evidence/vm-binding.json', RECEIPT_MAX), 'guest binding')
    literal_keys = {'attempt_id', 'boot_id', 'guest_attempt_id', 'guest_boot_id', 'profile', 'argv_digest'}
    require(literal_keys <= set(binding) <= literal_keys | {'native_program', 'sampled_exposure_sha256'},
            'unexpected guest binding fields')
    native_program_binding(reader, guest, transport, binding)
    digest = hashlib.sha256(guest_bytes).hexdigest()
    require(transport.get('schema') == VM_SCHEMA and details.get('guest_receipt') == 'evidence/jail.json'
            and details.get('guest_receipt_sha256') == 'sha256:' + digest
            and transport.get('guest_receipt_sha256') == digest, 'guest receipt hash binding differs')
    require(transport.get('attempt_id') == binding.get('attempt_id') == host['attempt_id'],
            'host attempt binding differs')
    require(type(transport.get('boot_id')) is str and bool(transport['boot_id'])
            and transport['boot_id'] == binding.get('boot_id') == details.get('vm_boot_id'),
            'service boot binding differs')
    require(binding.get('guest_attempt_id') == guest['attempt_id']
            and type(binding.get('guest_boot_id')) is str and bool(binding['guest_boot_id'])
            and binding['guest_boot_id'] == pointer(guest, 'process', 'identity', 'value', 'boot_id'),
            'guest attempt or kernel boot binding differs')
    require(binding.get('profile') == pointer(host, 'policy', 'name') == pointer(guest, 'policy', 'name')
            and type(binding.get('profile')) is str and bool(binding['profile']), 'profile binding differs')
    argv_digest = binding.get('argv_digest')
    require(type(argv_digest) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', argv_digest) is not None
            and argv_digest == host.get('argv_digest') == guest.get('argv_digest'), 'argv binding differs')
    image = transport.get('image')
    image_keys = {'disk_sha256', 'seed_sha256', 'helper_sha256', 'custodian_sha256'}
    require(type(image) is dict and image_keys <= set(image) <= image_keys | {'guest_program_catalog_sha256', 'sampler_sha256'}
            and all(type(value) is str and DIGEST.fullmatch(value) is not None for key, value in image.items() if key != 'sampler_sha256')
            and image['disk_sha256'] == details.get('disk_sha256'), 'image binding differs')
    port = transport.get('vsock_port')
    require(type(port) is int and 0 < port <= 2 ** 32 - 1 and port == details.get('vsock_port'),
            'vsock binding differs')
    # Ready uses uname.release; the Linux receipt uses uname.sysname + release.
    require(type(transport.get('guest_kernel')) is str and bool(transport['guest_kernel'])
            and pointer(guest, 'platform', 'os') == 'linux'
            and 'Linux ' + transport['guest_kernel'] == pointer(guest, 'platform', 'kernel'),
            'guest kernel binding differs')
    # D5 mirrors the guest's observed fields, retaining the host terminal and
    # any wall hit it observed itself. Do not conflate host cleanup with guest cleanup.
    for path in [('platform', 'kernel'), ('platform', 'arch'), ('exec_observed',), ('observer',), ('coverage',)]:
        require(equal(pointer(host, *path), pointer(guest, *path)), 'mirrored guest fact differs')
    host_applied, guest_applied = host.get('applied'), guest.get('applied')
    require(type(host_applied) is dict and type(guest_applied) is dict
            and set(host_applied) - {'terminal'} == set(guest_applied) - {'terminal'},
            'mirrored enforcement fields differ')
    for name in set(guest_applied) - {'terminal', 'limits'}:
        require(equal(host_applied[name], guest_applied[name]), 'mirrored enforcement differs')
    host_limits, guest_limits = host_applied.get('limits', []), guest_applied.get('limits', [])
    require(type(host_limits) is list and type(guest_limits) is list and len(host_limits) == len(guest_limits),
            'mirrored limit rows differ')
    for host_limit, guest_limit in zip(host_limits, guest_limits):
        require(type(host_limit) is dict and type(guest_limit) is dict, 'invalid limit row')
        compared = dict(host_limit)
        if host_limit.get('hit') is True and guest_limit.get('hit') is not True:
            # The host may preserve a hit it independently observed; only that
            # field can differ. The summary renders it as a host fact.
            if 'hit' in guest_limit:
                compared['hit'] = guest_limit['hit']
            else:
                compared.pop('hit')
        require(equal(compared, guest_limit), 'mirrored limit differs beyond a host hit')
    require(pointer(host, 'outcome', 'cause') is not None or pointer(guest, 'outcome', 'cause') is None,
            'guest cause disappeared')
    for name in ('kind', 'code', 'signal'):
        require(equal(pointer(host, 'outcome', name), pointer(guest, 'outcome', name)), 'relayed guest outcome differs')
    return guest, transport, digest, sampled_exposure(reader, guest, transport, binding, digest)


def transport_text(transport):
    return ('vm: guest-reported facts in evidence/jail.json · boot ' + esc(transport['boot_id'])
            + ' · image ' + transport['image']['disk_sha256'][:16]
            + ' · vsock ' + str(transport['vsock_port'])
            + ' · receipt sha256:' + transport['guest_receipt_sha256'][:16])


def expected_summary(reader):
    host = receipt(reader.read('jail.json', RECEIPT_MAX))
    details = pointer(host, 'lifetime', 'native', 'details')
    if details is None:
        details = {}
    require(type(details) is dict, 'invalid native receipt details')
    if 'guest_receipt_sha256' not in details:
        trace = reader.read('trace.ndjson', SCAN_CAP, optional=True)
        frames, complete, another = read_journal(trace, canonical_digest(host), host['attempt_id']) if trace is not None else ([], False, False)
        state = 'absent' if trace is None else ('complete' if complete else 'incomplete')
        return compute_summary(host, frames, state, len(trace or b''), another), None, 'host_only', len(frames), {'state': 'not_requested'}
    named = details['guest_receipt_sha256']
    require(type(named) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', named) is not None,
            'invalid named guest receipt')
    require(details.get('transport') == VM_SCHEMA, 'named guest requires its exact transport schema')
    host_trace = reader.read('trace.ndjson', SCAN_CAP)
    _, host_complete, host_another = read_journal(host_trace, canonical_digest(host), host['attempt_id'])
    require(host_complete and not host_another, 'host journal does not bind this receipt')
    guest, transport, digest, sampling = bound_guest(reader, host)
    frames, size = complete_guest_journal(reader, guest, digest)
    guest_summary = compute_summary(guest, frames, 'complete', size)
    result = compute_summary(host, [], 'guest')
    result['journal'] = guest_summary['journal']
    for name in ('workspace', 'network', 'credentials', 'evidence'):
        replacement = next((line for line in guest_summary['lines'] if line['line'] == name), None)
        index = next((index for index, line in enumerate(result['lines']) if line['line'] == name), None)
        if index is not None:
            if replacement is None:
                result['lines'].pop(index)
            else:
                result['lines'][index] = replacement
        elif replacement is not None:
            network = next((i for i, line in enumerate(result['lines']) if line['line'] == 'network'), None)
            result['lines'].insert(len(result['lines']) if network is None else network + 1, replacement)
    return result, transport_text(transport), 'bound_guest', len(frames), sampling


def valid_display_key(key):
    if type(key) is not str or not 0 < len(key) <= 4096:
        return False
    if key.startswith('/'):
        return key != '/' and all(part not in ('.', '..') for part in key.split('/')[1:])
    try:
        ipaddress.ip_address(key)
        return True
    except ValueError:
        return False


def display_transform(value, mapping):
    if type(value) is str:
        # Simultaneous replacements prevent one replacement from becoming a
        # second search key. Only display values are transformed, never keys.
        if not mapping:
            return value
        pattern = '|'.join(re.escape(key) for key in sorted(mapping, key=len, reverse=True))
        return re.sub(pattern, lambda match: mapping[match.group()], value)
    if type(value) is list:
        return [display_transform(item, mapping) for item in value]
    if type(value) is dict:
        return {key: display_transform(item, mapping) for key, item in value.items()}
    return value


def verify_attempt(attempt, summary_json, summary_text, *, display_mapping=None):
    """Recompute, bind and compare; PASS means the summary describes these bytes."""
    try:
        mapping = {} if display_mapping is None else display_mapping
        require(type(mapping) is dict and len(mapping) <= 32
                and all(valid_display_key(key) and type(value) is str and 0 < len(value) <= 4096
                        and esc(value) == value for key, value in mapping.items()), 'invalid explicit display mapping')
        require(type(summary_json) is dict and type(summary_text) is str, 'summary inputs have the wrong type')
        require(len(json.dumps(summary_json, ensure_ascii=False)) <= RECEIPT_MAX
                and len(summary_text.encode()) <= RECEIPT_MAX, 'summary input exceeds its bound')
        with EvidenceReader(attempt) as reader:
            expected, transport, scope, frames, sampling = expected_summary(reader)
            expected_text = ''.join('ukai-jail: ' + line['text'] + '\n' for line in expected['lines'])
            if transport is not None:
                expected_text += 'ukai-jail: ' + transport + '\n'
            expected_text += 'ukai-jail: receipt ' + esc(str(reader.root / 'jail.json')) + '\n'
            displayed_json = dict(expected)
            displayed_json['lines'] = display_transform(expected['lines'], mapping)
            displayed_text = display_transform(expected_text, mapping)
            require(equal(displayed_json, summary_json), 'summary JSON differs from independent recomputation')
            require(displayed_text == summary_text, 'summary text differs from independent recomputation')
            return {'schema': 'ukai.vm.summary-verification/1', 'outcome': 'PASS', 'qualified': False,
                    'scope': scope, 'journal': expected['journal'], 'journal_frames': frames, 'sampling': sampling,
                    'lines': len(expected['lines']), 'display_mapping_applied': bool(mapping),
                    'display_mapping_sha256': hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest(),
                    'evidence_sha256': dict(reader.hashes),
                    'summary_json_sha256': hashlib.sha256(json.dumps(summary_json, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest(),
                    'summary_text_sha256': hashlib.sha256(summary_text.encode()).hexdigest()}
    except VerificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError, UnicodeError) as error:
        # Do not echo evidence strings, malformed values or arbitrary exception text.
        raise VerificationError('evidence cannot be verified (' + type(error).__name__ + ')') from None


def read_input(path):
    path = Path(path).absolute()
    with EvidenceReader(path.parent) as reader:
        return reader.read(path.name, RECEIPT_MAX)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('attempt', type=Path)
    parser.add_argument('summary_json', type=Path)
    parser.add_argument('summary_text', type=Path)
    parser.add_argument('--display-map', type=Path, help='explicit JSON object of literal expected→display replacements')
    args = parser.parse_args(argv)
    try:
        result = verify_attempt(args.attempt, strict_json(read_input(args.summary_json)),
                                read_input(args.summary_text).decode(),
                                display_mapping=strict_json(read_input(args.display_map)) if args.display_map else None)
    except (VerificationError, OSError, ValueError, UnicodeError) as error:
        print('vm_summary_check: verification failed (' + type(error).__name__ + ')', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
