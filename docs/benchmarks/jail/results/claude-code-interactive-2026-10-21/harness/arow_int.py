"""Driver for the interactive Claude Code A-row (docs/specs/jail-interactive-sessions.md §6.3).

Runs §6.3's runs 1-8 through a scripted terminal (ttyharness.Session: a local
pty running `ssh -tt` to the reference host, rendered by pyte), then, per
attempt, the host-side collector (host/arow_int_collect.py: receipt, policy,
journal, `tail --summary`, `state list/show`, the state's files, the
independent recomputation, the pass conditions, the token search), and
fetches the host's run directory back only when the token search found
nothing.

usage (from this directory):
  uv run --with pexpect --with pyte python3 arow_int.py --out runs-DATE [--reps 2]
         [--root '$HOME/arow-int-pilot'] [--only r01,r02,...] [--first-launch both|as-written|workaround]

The host must be prepared first (host_setup.sh; see driver.sh). Nothing here
reads the token: on the host, only `credential set` and `grep -lF -f` touch it.
"""
import argparse
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

from ttyharness import HOST, KEY, Session

FIXTURE = "Create a file named greeting.txt containing the single word hello."
LONG_PROMPT = ("Without using any tools, write about 1500 words on the history of version control "
               "systems, from SCCS to git.")
ASK_RESUME = "In one short sentence: which file did you create earlier in this conversation?"
ASK_CONTINUE = "In one short sentence: what was the question I asked just before this one?"
ASK_FALLBACK = "What is 17 times 3? Answer with the number only."
FAKE_CODE = "fake-code-for-ukai-record"
WORKAROUND = "--allow-host platform.claude.com"   # operator flag; see the report
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1bP[^\x1b]*\x1b\\|\x1b[()][0-9A-Za-z]|\x1b[=>78]|\x0f|\x0e")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------------------
# The host, non-interactively (setup, attempt lists, collection)
# ---------------------------------------------------------------------------
class Host:
    def __init__(self, root):
        self.root = root  # as the far shell spells it, e.g. $HOME/arow-int-pilot
        self.env = (f"export UKAI_CONFIG_DIR={root}/config UKAI_DATA_DIR={root}/data "
                    f"PATH={root}/bin:$HOME/.local/bin:$PATH H={root}/harness; ")

    def sh(self, cmd, check=False, timeout=600):
        p = subprocess.run(["ssh", "-F", "/dev/null", "-i", KEY, "-o", "BatchMode=yes", "-o",
                            "IdentitiesOnly=yes", "-o", "ConnectTimeout=20", HOST, self.env + cmd],
                           capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise RuntimeError(f"host command failed ({p.returncode}): {cmd}\n{p.stderr}")
        return p

    def attempts(self):
        return set(self.sh(f"ls {self.root}/data/attempts 2>/dev/null").stdout.split())

    def new_attempt(self, before, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            new = sorted(self.attempts() - before)
            if new:
                return new[0] if len(new) == 1 else new
            time.sleep(1)
        return None

    def phase(self, attempt):
        p = self.sh(f"python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[\"phase\"])' "
                    f"{self.root}/data/attempts/{attempt}/jail.json")
        return p.stdout.strip()

    def put(self, local_paths, remote_dir):
        self.sh(f"mkdir -p {remote_dir}", check=True)
        subprocess.run(["scp", "-q", "-i", KEY, "-o", "BatchMode=yes", *map(str, local_paths),
                        f"{HOST}:{remote_dir.replace('$HOME/', '')}/"], check=True)

    def get(self, remote_dir, local_dir):
        local_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["scp", "-q", "-r", "-i", KEY, "-o", "BatchMode=yes",
                        f"{HOST}:{remote_dir.replace('$HOME/', '')}/.", str(local_dir)], check=True)


# ---------------------------------------------------------------------------
# Claude Code 2.1.302's screens, as the pilot saw them
# ---------------------------------------------------------------------------
def lines_of(text):
    return text.split("\n")


def input_box(text):
    """Index of the input line (`❯ …` between two rules), or None."""
    ls = lines_of(text)
    for i in range(len(ls) - 2, 0, -1):
        if ls[i].startswith("❯") and ls[i - 1].startswith("────") and ls[i + 1].startswith("────"):
            return i
    return None


def footer(text):
    i = input_box(text)
    return "\n".join(lines_of(text)[i + 2:]) if i is not None else ""


def rule_width(text):
    i = input_box(text)
    return len(lines_of(text)[i - 1].rstrip()) if i is not None else None


def classify(text):
    if "Unable to connect to Anthropic services" in text:
        return "preflight_fail"
    if "Choose the text style that looks best with your terminal" in text:
        return "theme"
    if "Security notes:" in text and "Press Enter to continue" in text:
        return "security"
    if "Use Claude Code's terminal setup?" in text:
        return "terminal_setup"
    if "Yes, I trust this folder" in text:
        return "trust"
    if "Select login method:" in text:
        return "login_method"
    if "Paste code here if prompted" in text:
        return "login_code"
    if re.search(r"Do you want to .*\?", text) and re.search(r"❯ 1\. Yes", text):
        return "permission"
    if "Resume session" in text and "Esc to cancel" in text:
        return "picker"
    i = input_box(text)
    if i is not None:
        return "generating" if "esc to interrupt" in footer(text) else "idle"
    return "unknown"


ONBOARDING = {"theme", "security", "terminal_setup", "trust", "login_method", "preflight_fail"}


def picker_entries(text):
    """[(title, meta, selected)] of the /resume picker."""
    out = []
    ls = lines_of(text)
    for i, l in enumerate(ls):
        if i and re.search(r"(ago|just now)\b.*·", l):
            title = ls[i - 1]
            out.append((title.replace("❯", " ").strip(), l.strip(), "❯" in title))
    return out


def plain(raw):
    return ANSI.sub("", raw.decode("utf-8", "replace")).replace("\r\n", "\n").replace("\r", "\n")


# ---------------------------------------------------------------------------
# One terminal
# ---------------------------------------------------------------------------
class Term:
    def __init__(self, run, name, root, ws, cols=120, rows=40):
        self.run = run
        self.s = Session(run.dir, cols=cols, rows=rows, name=name)
        self.name = name
        if not self.s.wait(lambda t, r: b"$ " in bytes(r[-200:]) or b"# " in bytes(r[-200:]), 30,
                           "login prompt", settle=1.0):
            raise RuntimeError("no login prompt")
        mark = self.s.mark()
        self.s.type(f"unset HISTFILE PROMPT_COMMAND; PS1='[arow \\W]\\$ '; export UKAI_CONFIG_DIR={root}/config "
                    f"UKAI_DATA_DIR={root}/data PATH={root}/bin:$HOME/.local/bin:$PATH H={root}/harness; "
                    f"cd {root}/ws-{ws}; echo \"ARROW-SETUP-$((6*7)) TTY=$(tty) SIZE=$(stty size) "
                    "TERM=$TERM LANG=$LANG TZ=${TZ-unset} COLORTERM=${COLORTERM-unset} SHELLOPTS=$- PWD=$PWD\"",
                    delay=0.003, enter=True, enter_pause=0.1)
        m = self.s.wait_raw(rb"ARROW-SETUP-42 ([^\r\n]*)\r\n", 20, "shell setup", start=mark)
        if not m:
            raise RuntimeError("shell setup failed")
        self.shell = dict(kv.split("=", 1) for kv in m.group(1).decode().split(" ") if "=" in kv)
        self.shell["SIZE"] = m.group(1).decode().split("SIZE=")[1].split(" TERM=")[0]
        self.s.note("shell", **self.shell)

    def text(self):
        return self.s.text()

    def snap(self, label):
        return self.s.snapshot(label)

    def wait_label(self, labels, timeout, desc, settle=0.8):
        found = {}

        def pred(text, _raw):
            lab = classify(text)
            if lab in labels:
                found["l"] = lab
                return True
            return False
        ok = self.s.wait(pred, timeout, desc, settle=settle)
        lab = found.get("l") if ok else classify(self.text())
        return lab if ok else None

    def launch(self, cmd):
        """Type one command line: the jail, then the K62 probe, then the marker."""
        self.s.type("clear", delay=0.003, enter=True, enter_pause=0.05)
        time.sleep(0.5)
        mark = self.s.mark()
        line = f'{cmd}; rc=$?; python3 -I $H/k62.py; echo "ARROW-DONE rc=$rc"'
        self.s.note("launch", line=line)
        self.s.type(line, delay=0.004, enter=True, enter_pause=0.1)
        return mark

    def done(self, mark, timeout):
        m = self.s.wait_raw(rb"ARROW-DONE rc=(\d+)", timeout, "shell marker", start=mark)
        return int(m.group(1)) if m else None

    def results(self, mark):
        raw = self.s.raw_since(mark)
        text = plain(raw)
        res = {}
        k = re.search(r"K62-RESULT (\{.*\})\n", text)
        res["k62"] = json.loads(k.group(1)) if k else None
        m = re.search(r"ARROW-DONE rc=(\d+)", text)
        res["rc"] = int(m.group(1)) if m else None
        sid = re.findall(r"claude --resume ([0-9a-f-]{36})", text)
        res["session_id"] = sid[-1] if sid else None
        pre = []
        for l in text.split("\n"):
            for part in re.findall(r"ukai-jail: [^\n]*", l):
                if re.match(r"ukai-jail: (claude = |terminal: |state: claude)", part):
                    pre.append(part)
        res["pre_exec"] = pre
        res["live_summary"] = live_summary(text)
        return res

    def type_prompt(self, text):
        self.s.type(text, delay=0.02, enter=True, enter_pause=0.5)

    def exit_claude(self):
        self.s.type("/exit", delay=0.03)
        time.sleep(0.6)
        self.s.send(b"\r", note="enter")

    def onboarding(self, allow, timeout=120):
        """Answer whatever onboarding appears until one of `allow` shows.
        Returns (final label, [labels seen])."""
        seen = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            lab = self.wait_label(ONBOARDING | set(allow), max(1, deadline - time.time()), "onboarding step")
            if lab is None:
                return None, seen
            if lab in allow:
                return lab, seen
            seen.append(lab)
            self.snap("onboarding-" + lab)
            if lab == "preflight_fail":
                return lab, seen
            if lab == "theme":
                self.s.key("enter")
            elif lab == "security":
                self.s.key("enter")
            elif lab == "terminal_setup":
                self.s.key("down")
                time.sleep(0.2)
                self.s.key("enter")
            elif lab == "trust":
                self.s.key("down")
                time.sleep(0.3)
                if "❯ Yes, I trust this folder" not in self.text():
                    self.snap("trust-not-selected")
                self.s.key("enter")
            elif lab == "login_method":
                return lab, seen
            # wait for the screen to change before classifying again
            before = self.text()
            self.s.wait(lambda t, r: t != before, 15, "screen changes")
        return None, seen

    def turn(self, prompt, permission=None, timeout=300):
        """Submit a prompt and wait for the turn to end; answer a permission
        prompt with `permission` ("1" = Yes) if one appears."""
        self.type_prompt(prompt)
        seen = []
        started = self.wait_label({"generating", "permission"}, 30, "turn started", settle=0)
        seen.append(started)
        deadline = time.time() + timeout
        while time.time() < deadline:
            lab = self.wait_label({"idle", "permission"}, deadline - time.time(), "turn ends or asks", settle=1.5)
            if lab == "permission":
                seen.append("permission")
                self.snap("permission")
                if permission is None:
                    return seen
                self.s.send(permission.encode(), note="permission answer")
                self.s.wait(lambda t, r: classify(t) != "permission", 15, "permission dialog closes")
                continue
            seen.append(lab)
            return seen
        return seen

    def set_mode(self, want="manual mode on"):
        start = footer(self.text())
        for _ in range(5):
            if want in footer(self.text()):
                return start
            self.s.send(b"\x1b[Z", note="shift+tab")
            time.sleep(0.8)
        return start

    def close(self):
        if getattr(self, "closed", False):
            return
        if not self.s.eof:
            self.s.type("exit", delay=0.01, enter=True, enter_pause=0.05)
            self.s.wait(lambda t, r: False, 3, "logout")
        (self.run.dir / f"final-screen-{self.name}.txt").write_text(self.s.text() + "\n")
        self.s.close()
        self.closed = True


def live_summary(text):
    """The summary block as the terminal received it: from the last
    `ukai-jail: settled` to the `ukai-jail: receipt` line."""
    ls = text.split("\n")
    idx = [i for i, l in enumerate(ls) if "ukai-jail: receipt " in l]
    if not idx:
        return None
    end = idx[-1]
    starts = [i for i in range(end + 1) if "ukai-jail: settled" in ls[i]]
    if not starts:
        return None
    block = ls[starts[-1]:end + 1]
    block[0] = block[0][block[0].index("ukai-jail: settled"):]
    return [l.rstrip() for l in block]


# ---------------------------------------------------------------------------
# A run: its directory, its record, its attempts
# ---------------------------------------------------------------------------
class Run:
    def __init__(self, driver, name, spec):
        self.d = driver
        self.name = name
        self.dir = driver.out / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.rec = {"run": name, "spec": spec, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "steps": [], "attempts": [], "observations": {}}
        self.terms = []

    def term(self, name, ws, **kw):
        t = Term(self, name, self.d.root, ws + self.d.args.ws_suffix, **kw)
        self.terms.append(t)
        self.rec.setdefault("shells", {})[name] = t.shell
        return t

    def obs(self, key, value):
        self.rec["observations"][key] = value
        log(f"  {self.name}: {key} = {json.dumps(value, default=str)[:200]}")

    def step(self, what, **detail):
        self.rec["steps"].append({"t": time.strftime("%H:%M:%S"), "what": what, **detail})

    def finish(self):
        for t in self.terms:
            try:
                if not getattr(t, "closed", False):
                    t.snap("final")
                t.close()
            except Exception as e:  # noqa: BLE001
                self.step("close failed", term=t.name, error=repr(e))
        self.rec["ended_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (self.dir / "run.json").write_text(json.dumps(self.rec, indent=1, default=str) + "\n")


class Driver:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.out).resolve()
        self.out.mkdir(parents=True, exist_ok=True)
        self.root = args.root
        self.host = Host(self.root)
        self.chain_path = self.out / "chain.json"
        self.chain = json.loads(self.chain_path.read_text()) if self.chain_path.exists() else {}
        self.results = []
        self.facts = json.loads((self.out / "facts.json").read_text()) if (self.out / "facts.json").exists() else {}

    def save(self):
        self.chain_path.write_text(json.dumps(self.chain, indent=1) + "\n")
        (self.out / "facts.json").write_text(json.dumps(self.facts, indent=1) + "\n")

    def ws_path(self, ws):
        return f"{self.root}/ws-{ws}{self.args.ws_suffix}"

    # -- collection --------------------------------------------------------
    def collect(self, run, attempt, ws, label, *, kind="persistent", attached=True, expect_exit="0",
                new_state=False, chain=True, holder=None, extra_hosts=(), expect=(), absent=(),
                res=None, hangup=False):
        """Collect one attempt on the host, check it, and advance the chain.
        `res` is the terminal's view of the run (Term.results), or None after a hangup."""
        live = res["live_summary"] if res and not hangup else None
        remote = f"{self.root}/runs/{self.out.name}/{run.name}/{label}"   # one namespace per output dir
        # The transcripts and raw streams go to the host first, for the token search.
        files = sorted(run.dir.glob("transcript-*.ndjson")) + sorted(run.dir.glob("stream-*.bin"))
        self.host.put(files, f"{remote}/transcripts")
        argv = [f"{self.root}/harness/arow_int_collect.py", f"{remote}", attempt,
                "--workspace", self.ws_path(ws),
                "--kind", kind, "--attached", "yes" if attached else "no", "--expect-exit", expect_exit,
                "--token-file", "$HOME/.config/ukai/credentials/claude-oauth",
                "--jail", f"{self.root}/bin/ukai-jail", "--hosts", self.args.profile_hosts]
        if hangup:
            argv.append("--hangup")
        prev = self.chain.get(ws)
        expected_pre = []   # the pre-exec lines §3.7, §4.6 and §4.7 require
        if attached:
            expected_pre.append(r"ukai-jail: terminal: attached \(/dev/pts/\d+\) · wall 8h · \^C and \^Z go to "
                                r"claude, not the jail; to end the attempt, exit claude or run `kill -INT \d+`")
        else:
            expected_pre.append(r"ukai-jail: terminal: detached \(stdin is not a terminal\)")
        if kind == "persistent":
            expected_pre.append(r"ukai-jail: state: claude, new for this workspace" if new_state or not prev else
                                re.escape(f"ukai-jail: state: claude, this workspace, generation "
                                          f"{prev['generation']} (from {prev['attempt']})"))
        else:
            expected_pre.append(re.escape(f"ukai-jail: state: claude for this workspace is held by {holder} · "
                                          "this session uses throwaway state and will not be kept"))
        if kind == "persistent":
            if new_state:
                argv.append("--new-state")
            elif prev:
                argv += ["--prev-attempt", prev["attempt"], "--prev-generation", str(prev["generation"])]
        if holder:
            argv += ["--holder", holder]
        for h in extra_hosts:
            argv += ["--extra-host", h]
        for e in expect:
            argv += ["--expect", e]
        for a in absent:
            argv += ["--absent-in-state", a]
        # Every argument is a safe word or a path under $HOME, which the far shell expands.
        assert all(re.fullmatch(r"[A-Za-z0-9_$/.:=@+,-]+", a) for a in argv), argv
        p = self.host.sh("python3 -I " + " ".join(argv))
        try:
            line = json.loads(p.stdout.strip().split("\n")[-1])
        except (ValueError, IndexError):
            line = {"attempt": attempt, "pass": False, "failed": ["collector_failed"],
                    "stderr": p.stderr[-2000:], "stdout": p.stdout[-2000:]}
        # Fetch the host's run directory back only when the token search found nothing.
        ts = self.host.sh(f"cat {remote}/token-search.json").stdout
        try:
            token = json.loads(ts)
        except ValueError:
            token = {"exit": None}
        local = run.dir / label
        if token.get("exit") == 1:
            self.host.get(remote, local)
            # The live summary equals `tail --summary` (K52), when the terminal showed one.
            tail = (local / "tail-summary.txt").read_text().rstrip("\n").split("\n")
            if live is not None:
                line["live_equals_tail"] = live == tail
                if not line["live_equals_tail"]:
                    line.setdefault("failed", []).append("live_equals_tail")
                    line["pass"] = False
        else:
            line["pass"] = False
            line.setdefault("failed", []).append("token_search_not_clean_or_failed")
            (local).mkdir(parents=True, exist_ok=True)
            (local / "token-search-NOT-FETCHED.json").write_text(ts or "{}")
        line["label"] = label
        if res:
            line["pre_exec"] = res.get("pre_exec")
            missing = [rx for rx in expected_pre if not any(re.fullmatch(rx, l) for l in res.get("pre_exec") or [])]
            line["pre_exec_as_required"] = not missing
            if missing:
                line["pass"] = False
                line.setdefault("failed", []).append("pre_exec_lines")
                line["pre_exec_missing"] = missing
        if res and not hangup:
            line["k62_pending"] = (res.get("k62") or {}).get("pending")
            line["shell_rc"] = res.get("rc")
            if live is None:
                line["live_equals_tail"] = "no live summary"
                line["pass"] = False
                line.setdefault("failed", []).append("no_live_summary")
            if line["k62_pending"] != 0:
                line["pass"] = False
                line.setdefault("failed", []).append("k62")
        run.rec["attempts"].append(line)
        (run.dir / "run.json").write_text(json.dumps(run.rec, indent=1, default=str) + "\n")
        log(f"  {run.name}/{label}: pass={line.get('pass')} failed={line.get('failed')} "
            f"gen={line.get('generation')} {line.get('outcome')}/{line.get('code')}")
        if chain and kind == "persistent" and line.get("state_cleanup") == "released":
            gen = line.get("generation") or [None, None]
            self.chain[ws] = {"attempt": attempt, "generation": gen[1], "run": f"{run.name}/{label}"}
        self.save()
        self.results.append({"run": run.name, "label": label, **line})
        return line

    def cmd(self, args="", workaround=False):
        if workaround:
            return f"ukai-jail run --launch claude --from-path {WORKAROUND} -- {args}".rstrip()
        return f"ukai-jail claude {args}".rstrip()

    # -- the runs ------------------------------------------------------------
    def r01(self):
        """(1) First launch in A, empty state: onboarding, the A01 task with the
        permission prompt answered at the keyboard, /exit."""
        modes = {"both": [False, True], "as-written": [False], "workaround": [True]}[self.args.first_launch]
        for workaround in modes:
            name = "r01-first-launch" + ("-workaround" if workaround else "")
            run = Run(self, name, "6.3 (1)")
            before = self.host.attempts()
            t = run.term("t1", "A")
            mark = t.launch(self.cmd(workaround=workaround))
            att = self.host.new_attempt(before)
            run.obs("attempt", att)
            lab, seen = t.onboarding({"idle"})
            run.obs("onboarding_seen", seen)
            run.obs("onboarding_end", lab)
            if lab == "idle":
                run.obs("login_prompt_appeared", "login_method" in seen)
                run.obs("initial_mode", t.set_mode("manual mode on").strip())
                run.obs("mode_after_switch", footer(t.text()).strip())
                t.snap("idle-manual")
                turn = t.turn(FIXTURE, permission="1")
                run.obs("turn", turn)
                run.obs("permission_prompt_answered", "permission" in turn)
                t.snap("after-task")
                t.exit_claude()
            rc = t.done(mark, 120)
            res = t.results(mark)
            run.obs("results", res)
            first_ok = lab == "idle"
            self.facts["first_launch_" + ("workaround" if workaround else "as_written")] = {
                "onboarding": seen, "end": lab, "rc": rc, "session_id": res["session_id"]}
            if res["session_id"]:
                self.facts["r01_session"] = res["session_id"]
            run.finish()
            if att and not isinstance(att, list):
                self.collect(run, att, "A", "A", new_state=True, expect_exit="0",
                             extra_hosts=[WORKAROUND.split()[-1] + ":443"] if workaround else [],
                             expect=[f"greeting.txt=hello"] if first_ok else [], res=res,
                             chain=first_ok)
            if not first_ok and len(modes) > 1:
                # The as-written launch could not pass onboarding: remove the state it
                # left so the next launch starts empty, as §6.3 (1) requires.
                p = self.host.sh(f"cd {self.ws_path('A')} && ukai-jail state rm claude")
                run.step("state rm", rc=p.returncode, out=(p.stdout + p.stderr)[-500:])
                (run.dir / "run.json").write_text(json.dumps(run.rec, indent=1, default=str) + "\n")
                self.chain.pop("A", None)
                self.save()
            if first_ok:
                break

    def resume_once(self, run, label, mode):
        """(2) one launch with --resume (pick run 1's session) or --continue."""
        before = self.host.attempts()
        t = run.term(f"t-{label}", "A")
        mark = t.launch(self.cmd("--resume" if mode == "resume" else "--continue"))
        att = self.host.new_attempt(before)
        ok = True
        if mode == "resume":
            lab, seen = t.onboarding({"picker", "idle"})
            run.obs(f"{label}:onboarding_seen", seen)
            run.obs(f"{label}:first_screen", lab)
            ok = lab == "picker" and not seen
            if lab == "picker":
                t.snap("picker")
                entries = picker_entries(t.text())
                run.obs(f"{label}:picker_entries", entries)
                target = self.facts.get("r01_title")
                if target is None and len(entries) == 1:
                    target = entries[0][0]
                    self.facts["r01_title"] = target
                titles = [e[0] for e in entries]
                run.obs(f"{label}:r01_listed", target in titles)
                idx = titles.index(target) if target in titles else 0
                cur = next((i for i, e in enumerate(entries) if e[2]), 0)
                for _ in range(idx - cur):
                    t.s.key("down")
                    time.sleep(0.2)
                t.s.key("enter")
                lab = t.wait_label({"idle"}, 60, "resumed")
        else:
            lab, seen = t.onboarding({"idle", "picker"})
            run.obs(f"{label}:onboarding_seen", seen)
            ok = lab == "idle" and not seen
        if lab == "idle":
            t.snap("resumed")
            if mode == "resume":
                run.obs(f"{label}:history_shows_run1_prompt", FIXTURE in t.text().replace("\n", " "))
            else:
                run.obs(f"{label}:history_shows_previous_question", ASK_RESUME in t.text().replace("\n", " "))
            turn = t.turn(ASK_RESUME if mode == "resume" else ASK_CONTINUE)
            run.obs(f"{label}:turn", turn)
            t.snap("answered")
            ans = t.text()
            if mode == "resume":
                run.obs(f"{label}:answer_mentions_greeting", "greeting" in ans.split(ASK_RESUME)[-1])
            else:
                run.obs(f"{label}:answer_mentions_file_question", "file" in ans.split(ASK_CONTINUE)[-1])
            t.exit_claude()
        rc = t.done(mark, 120)
        res = t.results(mark)
        run.obs(f"{label}:results", res)
        run.obs(f"{label}:same_session_as_r01", res["session_id"] == self.facts.get("r01_session"))
        t.close()
        if att and not isinstance(att, list):
            self.collect(run, att, "A", label, res=res)
        return ok

    def r02(self):
        run = Run(self, "r02-resume-continue", "6.3 (2)")
        self.resume_once(run, "resume", "resume")
        self.resume_once(run, "continue", "continue")
        run.finish()

    def r07(self):
        for n in range(1, self.args.reps + 1):
            run = Run(self, f"r07-rep{n:02d}", "6.3 (7)")
            try:
                self.resume_once(run, "resume", "resume")
                self.resume_once(run, "continue", "continue")
            except Exception as e:  # noqa: BLE001 - each failure kept
                run.step("exception", error=repr(e))
            run.finish()

    def r03(self):
        """(3) A launch in B: run (1)'s session is not listed. The picker is opened
        with /resume inside the session: cancelling the picker of `--resume` makes
        Claude Code 2.1.302 exit 1 (seen in the pilot), which §6.3's exit-0
        condition would count against the jail."""
        run = Run(self, "r03-workspace-b", "6.3 (3)")
        before = self.host.attempts()
        t = run.term("t1", "B")
        wk = self.args.first_launch != "as-written" and "B" not in self.chain
        mark = t.launch(self.cmd(workaround=wk))
        att = self.host.new_attempt(before)
        lab, seen = t.onboarding({"idle"})
        run.obs("onboarding_seen", seen)
        if lab == "idle":
            t.type_prompt("/resume")
            lab = t.wait_label({"picker"}, 30, "picker")
            if lab == "picker":
                t.snap("picker")
                run.obs("picker_text", [l.strip() for l in t.text().split("\n") if l.strip()][-4:])
                run.obs("picker_entries", picker_entries(t.text()))
                t.s.send(b"\x01", note="ctrl+a: all projects")
                time.sleep(1.5)
                t.snap("picker-all-projects")
                run.obs("picker_all_projects_entries", picker_entries(t.text()))
                run.obs("no_conversations_shown", "No conversations found" in t.text())
                run.obs("r01_title_absent", self.facts.get("r01_title", "\0") not in t.text())
                t.s.key("esc")
                lab = t.wait_label({"idle"}, 20, "after picker")
                run.obs("after_picker", lab)
        if lab == "idle":
            t.exit_claude()
        t.done(mark, 120)
        res = t.results(mark)
        run.obs("results", res)
        run.finish()
        if att and not isinstance(att, list):
            self.collect(run, att, "B", "B", new_state="B" not in self.chain,
                         extra_hosts=["platform.claude.com:443"] if wk else [], res=res)

    def r04(self):
        """(4) Resize during generation, ^C during generation, ^Z then fg, hangup."""
        run = Run(self, "r04-signals-hangup", "6.3 (4)")
        before = self.host.attempts()
        t = run.term("t1", "A")
        mark = t.launch(self.cmd())
        att = self.host.new_attempt(before)
        lab, seen = t.onboarding({"idle"})
        run.obs("onboarding_seen", seen)
        if lab != "idle":
            run.finish()
            return
        t.type_prompt(LONG_PROMPT)
        run.obs("generating", t.wait_label({"generating"}, 30, "generation starts", settle=0))
        time.sleep(4)
        t.snap("before-resize")
        w0 = rule_width(t.text())
        t.s.resize(100, 32)
        time.sleep(2.0)
        t.snap("after-resize")
        txt = t.text()
        run.obs("resize", {"rule_before": w0, "rule_after": rule_width(txt),
                           "still_generating": classify(txt) == "generating"})
        gen_before_c = classify(t.text())
        t.s.key("ctrl-c")
        lab = t.wait_label({"idle"}, 20, "turn interrupted", settle=1.0)
        t.snap("after-ctrl-c")
        run.obs("ctrl_c", {"generating_before": gen_before_c, "after": lab,
                           "shell_marker_seen": re.search(rb"ARROW-DONE rc=\d", t.s.raw_since(mark)) is not None,
                           "interrupted_text": "Interrupted" in t.text()})
        # The external editor (§6.3: does it give the terminal to another process
        # group?): ctrl+g opens the prompt in $EDITOR (nano when none is set);
        # the host's process table shows its group and the terminal's.
        t.s.send(b"\x15", note="ctrl+u: clear the input")
        time.sleep(0.5)
        t.s.type("draft for the editor", delay=0.02)
        time.sleep(0.5)
        t.s.send(b"\x07", note="ctrl+g: external editor")
        ed = t.s.wait(lambda tx, r: "GNU nano" in tx or "VIM" in tx or "~" * 3 in tx, 15, "editor shows",
                      settle=1.0)
        t.snap("editor")
        pts = t.shell.get("TTY", "").replace("/dev/", "")
        ps = self.host.sh(f"ps -t {pts} -o pid=,ppid=,pgid=,tpgid=,stat=,comm=").stdout if pts else ""
        (run.dir / "editor-ps.txt").write_text(ps)
        procs = [l.split() for l in ps.splitlines() if l.strip()]
        editor = [p for p in procs if p[5] in ("nano", "vi", "vim", "vim.basic", "vim.tiny", "editor")]
        agent = [p for p in procs if p[5] == "2.1.302"]
        run.obs("editor", {"shown": ed, "editor": editor, "agent": agent,
                           "editor_in_agent_group": bool(editor and agent and editor[0][2] == agent[0][2]),
                           "terminal_group_is_agent_group": bool(agent and agent[0][3] == agent[0][2])})
        if "GNU nano" in t.text():
            t.s.send(b"\x18", note="ctrl+x: leave nano")
        else:
            t.s.type(":q!", delay=0.05, enter=True, enter_pause=0.1)
        back = t.wait_label({"idle"}, 15, "back from editor")
        t.snap("after-editor")
        run.obs("editor_returned", {"label": back, "draft_back_in_input": "draft for the editor" in t.text(),
                                    "nano_gone": "GNU nano" not in t.text()})
        t.s.send(b"\x15", note="ctrl+u: clear the input")
        time.sleep(0.5)
        m2 = t.s.mark()
        t.s.key("ctrl-z")
        stopped = t.s.wait_raw(rb"Stopped", 20, "job stopped", start=m2)
        rc_at_stop = t.done(m2, 20)
        t.snap("after-ctrl-z")
        stop_raw = t.s.raw_since(m2)
        stop_text = plain(stop_raw)
        sus = stop_raw.find(b"suspended")
        stp = stop_raw.find(b"Stopped")
        run.obs("reset_written_at_stop", sus >= 0 and stp > sus and b"\x1b[0m\x1b[?25h" in stop_raw[sus:stp])
        k = re.search(r"K62-RESULT (\{.*\})\n", stop_text)
        run.obs("ctrl_z", {"stopped_line": bool(stopped), "list_continued_rc": rc_at_stop,
                           "claude_message": "Claude Code has been suspended" in stop_text,
                           "k62_at_stop": json.loads(k.group(1)) if k else None})
        if att and not isinstance(att, list):
            run.obs("phase_while_stopped", self.host.phase(att))
            p = self.host.sh(f"grep -c terminal_stopped {self.root}/data/attempts/{att}/trace.ndjson")
            run.obs("journal_terminal_stopped_while_stopped", p.stdout.strip())
        m3 = t.s.mark()
        t.s.type("fg", delay=0.05, enter=True, enter_pause=0.2)
        lab = t.wait_label({"idle", "generating"}, 30, "back after fg", settle=1.5)
        t.snap("after-fg")
        run.obs("fg", {"label": lab, "redrawn": input_box(t.text()) is not None,
                       "rule_width": rule_width(t.text())})
        # The hangup: the terminal is closed as a window close does.
        t.s.hangup()
        run.step("hangup")
        settled = None
        if att and not isinstance(att, list):
            deadline = time.time() + 120
            while time.time() < deadline:
                ph = self.host.phase(att)
                if ph == "settled":
                    settled = round(120 - (deadline - time.time()), 1)
                    break
                time.sleep(2)
        run.obs("settled_after_hangup_s", settled)
        run.obs("rx_after_fg", plain(t.s.raw_since(m3))[-400:])
        res = t.results(mark)
        run.finish()
        if att and not isinstance(att, list):
            self.collect(run, att, "A", "A", expect_exit="any", res=res, hangup=True)

    def login_code(self, run, t, code, label):
        """At the code prompt, paste `code`, wait for Claude Code's answer, record it."""
        before_text = t.text()
        t.s.type(code, delay=0.02, enter=True, enter_pause=0.5)
        t.s.wait(lambda tx, r: tx != before_text and code not in tx, 60, "login result", settle=3.0)
        t.snap(f"login-result-{label}")
        lines = [l.strip() for l in t.text().split("\n") if l.strip()]
        i = max([k for k, l in enumerate(lines) if l == "Login"] or [0])
        run.obs(f"login_result_{label}", lines[i:][-10:])

    def r05(self):
        """(5) /login inside a session. The pilot found that a code without `#`
        is refused by Claude Code itself ("OAuth error: Invalid code"), before
        any request; so the run pastes the plain fake code first, then retries
        with `fake-code-for-ukai-record#<the state shown in the URL>`, the shape
        that makes Claude Code attempt the token exchange, which the jail must deny."""
        run = Run(self, "r05-login", "6.3 (5)")
        before = self.host.attempts()
        t = run.term("t1", "A")
        mark = t.launch(self.cmd())
        att = self.host.new_attempt(before)
        lab, seen = t.onboarding({"idle"})
        run.obs("onboarding_seen", seen)
        if lab == "idle":
            t.type_prompt("/login")
            lab = t.wait_label({"login_method"}, 30, "login method")
            t.snap("login-method")
            run.obs("login_method_screen", lab)
            run.obs("login_warning", " ".join(l.strip() for l in t.text().split("\n")
                                               if "CLAUDE_CODE_OAUTH_TOKEN" in l or "sessions will keep" in l
                                               or "after logging in" in l))
            if lab == "login_method":
                t.s.key("enter")
                lab = t.wait_label({"login_code"}, 60, "code prompt")
                t.snap("login-code-prompt")
                run.obs("code_prompt", lab)
                if lab == "login_code":
                    self.login_code(run, t, FAKE_CODE, "plain")
                    # Retry: Enter, back to a code prompt with a new URL.
                    t.s.key("enter")
                    lab = t.wait_label({"login_code", "login_method"}, 30, "retry")
                    if lab == "login_method":
                        t.s.key("enter")
                        lab = t.wait_label({"login_code"}, 60, "code prompt again")
                    if lab == "login_code":
                        t.snap("login-code-prompt-2")
                        flat = "".join(l.strip() for l in t.text().split("\n"))
                        m = re.search(r"[?&]state=([A-Za-z0-9_-]+)", flat)
                        run.obs("url_state_found", bool(m))
                        if m:
                            self.login_code(run, t, f"{FAKE_CODE}#{m.group(1)}", "with_state")
            for _ in range(4):
                if classify(t.text()) == "idle":
                    break
                t.s.key("esc")
                time.sleep(1.5)
            t.snap("after-login")
            run.obs("after_login", classify(t.text()))
            if classify(t.text()) == "idle":
                t.exit_claude()
        t.done(mark, 120)
        res = t.results(mark)
        run.obs("results", res)
        run.finish()
        if att and not isinstance(att, list):
            line = self.collect(run, att, "A", "A", absent=[".credentials.json"], res=res)
            run.obs("platform_claude_com_results", [p for p in line.get("proxy", [])
                                                    if p[0] == "platform.claude.com:443"])
            chk = run.dir / "A" / "check.json"
            if chk.exists():
                facts = json.loads(chk.read_text())["facts"]
                run.obs("discarded", (facts.get("vendor_state") or {}).get("discarded"))
            (run.dir / "run.json").write_text(json.dumps(run.rec, indent=1, default=str) + "\n")

    def r06(self):
        """(6) A headless -p run from the interactive shell: attached, then stdin a pipe (detached)."""
        run = Run(self, "r06-headless", "6.3 (6)")
        flags = "--dangerously-skip-permissions --output-format json"
        for label, prefix, attached in (("attached", "", True), ("detached", "true | ", False)):
            before = self.host.attempts()
            t = run.term(f"t-{label}", "A")
            mark = t.launch(f"rm -f greeting.txt; {prefix}ukai-jail claude -p {shlex.quote(FIXTURE)} {flags}")
            rc = t.done(mark, 300)
            att = self.host.new_attempt(before, timeout=5)
            res = t.results(mark)
            res["claude_result"] = None
            for l in plain(t.s.raw_since(mark)).split("\n"):
                if l.startswith("{") and '"is_error"' in l:
                    try:
                        j = json.loads(l)
                        res["claude_result"] = {k: j.get(k) for k in ("type", "subtype", "is_error", "num_turns",
                                                                      "result", "session_id", "permission_denials")}
                    except ValueError:
                        res["claude_result"] = "unparsed"
            run.obs(f"{label}:results", res)
            t.close()
            if att and not isinstance(att, list):
                self.collect(run, att, "A", label, attached=attached, expect=["greeting.txt=hello"],
                             res=res)
        run.finish()

    def r08(self):
        """(8) A second ukai-jail claude in A while a session holds the state."""
        run = Run(self, "r08-concurrent", "6.3 (8)")
        before = self.host.attempts()
        t1 = run.term("t1", "A")
        m1 = t1.launch(self.cmd())
        a1 = self.host.new_attempt(before)
        lab, seen = t1.onboarding({"idle"})
        run.obs("t1:onboarding_seen", seen)
        run.obs("t1:attempt", a1)
        # The second terminal: another ssh connection.
        before2 = self.host.attempts()
        t2 = run.term("t2", "A")
        wk = self.args.first_launch != "as-written"
        m2 = t2.launch(self.cmd(workaround=wk))
        a2 = self.host.new_attempt(before2)
        run.obs("t2:attempt", a2)
        time.sleep(3)
        pre2 = t2.results(m2)["pre_exec"]
        run.obs("t2:pre_exec", pre2)
        run.obs("t2:fallback_line_names_holder", any("held by " + str(a1) in l and "throwaway" in l for l in pre2))
        lab2, seen2 = t2.onboarding({"idle"})
        run.obs("t2:onboarding_seen", seen2)
        if lab2 == "idle":
            turn = t2.turn(ASK_FALLBACK)
            run.obs("t2:turn", turn)
            t2.snap("t2-answered")
            t2.exit_claude()
        t2.done(m2, 120)
        r2 = t2.results(m2)
        run.obs("t2:results", r2)
        self.facts["r08_fallback_session"] = r2["session_id"]
        t2.close()
        if a2 and not isinstance(a2, list):
            self.collect(run, a2, "A", "t2-fallback", kind="attempt_fallback", holder=a1, chain=False,
                         extra_hosts=["platform.claude.com:443"] if wk else [], res=r2)
        # Back in the first session: its own /resume picker must not list the fallback's session.
        if lab == "idle":
            t1.type_prompt("/resume")
            pl = t1.wait_label({"picker"}, 30, "picker in session")
            t1.snap("t1-picker-in-session")
            run.obs("t1:picker_in_session", picker_entries(t1.text()) if pl else None)
            t1.s.key("esc")
            t1.wait_label({"idle"}, 20, "back to idle")
            t1.exit_claude()
        t1.done(m1, 120)
        r1 = t1.results(m1)
        run.obs("t1:results", r1)
        if a1 and not isinstance(a1, list):
            self.collect(run, a1, "A", "t1-holder", res=r1)
        # After both: a new --resume in A lists nothing of the fallback session.
        before3 = self.host.attempts()
        m3 = t1.launch(self.cmd("--resume"))
        a3 = self.host.new_attempt(before3)
        lab3, seen3 = t1.onboarding({"picker", "idle"})
        if lab3 == "picker":
            t1.snap("t1-picker-after")
            entries = picker_entries(t1.text())
            run.obs("t3:picker_entries", entries)
            titles = [e[0] for e in entries]
            target = self.facts.get("r01_title")
            idx = titles.index(target) if target in titles else 0
            cur = next((i for i, e in enumerate(entries) if e[2]), 0)
            for _ in range(idx - cur):
                t1.s.key("down")
                time.sleep(0.2)
            t1.s.key("enter")   # continue run 1's session: cancelling would exit 1
            lab3 = t1.wait_label({"idle"}, 60, "resumed")
            run.obs("t3:resumed", lab3)
        if lab3 == "idle":
            t1.exit_claude()
        t1.done(m3, 120)
        r3 = t1.results(m3)
        run.obs("t3:results", r3)
        run.finish()
        if a3 and not isinstance(a3, list):
            line = self.collect(run, a3, "A", "t3-resume-after", res=r3)
            sid = self.facts.get("r08_fallback_session")
            files = (run.dir / "t3-resume-after" / "state-files.txt")
            if sid and files.exists():
                run.obs("fallback_session_absent_from_state", sid not in files.read_text())
                (run.dir / "run.json").write_text(json.dumps(run.rec, indent=1, default=str) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--root", default="$HOME/arow-int-pilot")
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--ws-suffix", default="", help="workspaces are ws-A<suffix> and ws-B<suffix> under the root")
    ap.add_argument("--profile-hosts", default="api.anthropic.com:443,platform.claude.com:443",
                    help="the allow_host grants the bundled claude profile declares (since spec §8 item 30)")
    ap.add_argument("--only", default="r01,r02,r07,r03,r04,r05,r06,r08",
                    help="runs in order (run 7 repeats run 2, so it follows it by default)")
    ap.add_argument("--first-launch", default="as-written", choices=["both", "as-written", "workaround"],
                    help="as-written = the bundled profile; workaround = plus --allow-host platform.claude.com "
                         "for launches that start from an empty state (r01, r03, r08's fallback)")
    args = ap.parse_args()
    d = Driver(args)
    for name in args.only.split(","):
        log(f"== {name}")
        try:
            getattr(d, name)()
        except Exception as e:  # noqa: BLE001 - keep going, keep the failure
            log(f"  {name} raised {e!r}")
            d.results.append({"run": name, "pass": False, "failed": ["exception: " + repr(e)]})
        with open(d.out / "results.ndjson", "a") as f:
            for r in d.results:
                f.write(json.dumps(r, default=str) + "\n")
        d.results = []
    log("done")


if __name__ == "__main__":
    main()
