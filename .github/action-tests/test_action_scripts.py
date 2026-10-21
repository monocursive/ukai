"""The action's step scripts against stand-ins (docs/specs/jail-ci-action.md).

Run from the repository root:
  python3 -m unittest discover -s .github/action-tests -p test_action_scripts.py

`ukai-jail`, `gh`, `id` and `sudo` are replaced by stubs that log what they
were given, so these cases check the scripts' own behaviour (argv, the
environment, masking, the exposure check, fail-on, the comment) and nothing
about the real binary or GitHub; the self-test workflow runs the real ones.
They simulate what a hosted runner cannot produce on demand: a root step,
pull_request_target, a fork's pull request, a reading of 0, a tampered
tarball, an unsettled receipt with survivors.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action"
SCRIPTS = ACTION / "scripts"
STUB = Path(__file__).with_name("stub_ukai_jail.py")
# The scripts need bash 4.3 or later; macOS's /bin/bash is 3.2.
BASH = "/opt/homebrew/bin/bash" if sys.platform == "darwin" else "bash"
LINUX = sys.platform.startswith("linux")
TOKEN = "ukai-selftest-fixture-" + "5f" * 20
SUMMARY = {"lines": [{"line": "status", "facts": {"phase": "settled", "survivors": "none_verified"},
                      "text": "settled · exited 0"},
                     {"line": "evidence", "facts": {"classes": {c: "active" for c in
                      ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"]}, "gaps": [], "disagree": []}}]}


def executable(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class Scripts(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ukai-action-test."))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()
        self.runner_temp = self.tmp / "rt"
        self.runner_temp.mkdir()
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()
        subprocess.run(["git", "init", "-q", str(self.workspace)], check=True)
        self.log = self.tmp / "stub.log"
        self.output = self.tmp / "output"
        self.summary = self.tmp / "summary.md"
        self.env = {
            "PATH": f"{self.stubs}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "RUNNER_TEMP": str(self.runner_temp),
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_ACTION_PATH": str(ACTION),
            "GITHUB_OUTPUT": str(self.output), "GITHUB_STEP_SUMMARY": str(self.summary),
            "GITHUB_WORKSPACE": str(self.workspace), "GITHUB_EVENT_NAME": "push",
            "GITHUB_REPOSITORY": "owner/repo", "GITHUB_RUN_ID": "7", "GITHUB_WORKFLOW": "wf",
            "GITHUB_JOB": "job", "GITHUB_SERVER_URL": "https://github.com",
            "STUB_LOG": str(self.log),
            "UKAI_ACTION_VERSION": "0.1.0-rc.4", "UKAI_ACTION_FAIL_ON": "unsettled,survivors",
            "UKAI_ACTION_PR_COMMENT": "false", "UKAI_ACTION_ARTIFACT_NAME": "ukai-jail-receipt",
            "UKAI_ACTION_ALLOW_CHECKOUT_TOKEN": "false",
        }
        bin_dir = self.runner_temp / "ukai" / "bin"
        bin_dir.mkdir(parents=True)
        executable(bin_dir / "ukai-jail", STUB.read_text())
        for name in ("config", "data"):
            (self.runner_temp / "ukai" / name).mkdir(mode=0o700)

    # --- helpers ---------------------------------------------------------------
    def script(self, name, **extra):
        env = {**self.env, **{k: str(v) for k, v in extra.items()}}
        return subprocess.run([BASH, str(SCRIPTS / name)], env=env, capture_output=True, text=True)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def outputs(self):
        if not self.output.exists():
            return {}
        return dict(line.split("=", 1) for line in self.output.read_text().splitlines() if "=" in line)

    def report_dir(self, mode="profile", **facts):
        directory = self.runner_temp / "ukai" / "report.test"
        directory.mkdir(parents=True, exist_ok=True)
        facts = {"mode": mode, "workspace": str(self.workspace), "environment": "github-hosted",
                 "bwrap_built": "true", "bwrap_path": "/usr/local/bin/bwrap", "bwrap_version": "0.11.1",
                 "profile_loaded": "true", "sysctl_before": "1", **facts}
        (directory / "facts.env").write_text("".join(f"{k}={v}\n" for k, v in facts.items()))
        (directory / "setup.txt").write_text("facts\n")
        self.env["UKAI_ACTION_DIR"] = str(directory)
        return directory

    def store(self, directory, credential_id, value):
        credentials = self.runner_temp / "ukai" / "config" / "credentials"
        credentials.mkdir(parents=True, exist_ok=True)
        (credentials / credential_id).write_text(value)
        with open(directory / "credential-ids", "a") as ids:
            ids.write(credential_id + "\n")

    # --- check.sh (§3.2) ---------------------------------------------------------
    def assert_refused_unchanged(self, result, words):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("::error", result.stdout)
        self.assertIn(words, result.stdout)
        self.assertFalse(any(p.name.startswith("report.") for p in (self.runner_temp / "ukai").iterdir()),
                         "a refused check created its report directory")

    def test_check_refuses_root_before_any_change(self):
        executable(self.stubs / "id", '#!/bin/sh\n[ "$1" = -u ] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n')
        self.assert_refused_unchanged(
            self.script("check.sh", UKAI_ACTION_PROFILE="tool", UKAI_ACTION_RUN="true"), "EUID 0")

    def test_check_refuses_other_runners(self):
        self.assert_refused_unchanged(
            self.script("check.sh", UKAI_ACTION_PROFILE="tool", UKAI_ACTION_RUN="true", RUNNER_OS="macOS"),
            "RUNNER_OS Linux")

    @unittest.skipUnless(LINUX, "reads /etc/os-release and ldd")
    def test_check_refuses_pull_request_target(self):
        self.assert_refused_unchanged(
            self.script("check.sh", UKAI_ACTION_PROFILE="tool", UKAI_ACTION_RUN="true",
                        GITHUB_EVENT_NAME="pull_request_target"), "pull_request_target")

    @unittest.skipUnless(LINUX, "reads /etc/os-release and ldd")
    def test_check_refuses_the_checkout_token_without_reading_it(self):
        subprocess.run(["git", "-C", str(self.workspace), "config", "http.https://github.com/.extraheader",
                        f"AUTHORIZATION: basic {TOKEN}"], check=True)
        refused = self.script("check.sh", UKAI_ACTION_PROFILE="tool", UKAI_ACTION_RUN="true")
        self.assert_refused_unchanged(refused, "persist-credentials: false")
        self.assertNotIn(TOKEN, refused.stdout + refused.stderr)
        allowed = self.script("check.sh", UKAI_ACTION_PROFILE="tool", UKAI_ACTION_RUN="true",
                              UKAI_ACTION_ALLOW_CHECKOUT_TOKEN="true")
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
        setup = Path(self.outputs()["dir"], "setup.txt").read_text()
        self.assertIn("checkout token PRESENT and allowed", setup)
        self.assertNotIn(TOKEN, allowed.stdout + allowed.stderr + setup)

    def test_check_refuses_inputs_before_evaluating_them(self):
        marker = self.tmp / "evaluated"
        cases = [
            ({"UKAI_ACTION_LAUNCH": "claude", "UKAI_ACTION_PROFILE": "tool"}, "not both"),
            ({"UKAI_ACTION_PROFILE": "none", "UKAI_ACTION_RUN": "true"}, "uncontained"),
            ({"UKAI_ACTION_PROFILE": "agent"}, "needs a `run` script"),
            ({"UKAI_ACTION_LAUNCH": f"claude;touch {marker}"}, "not a launch profile name"),
            ({"UKAI_ACTION_PROFILE": "tool", "UKAI_ACTION_RUN": "true",
              "UKAI_ACTION_CREDENTIALS": f"x=A[$(touch {marker})]"}, "environment variable name"),
            ({"UKAI_ACTION_PROFILE": "tool", "UKAI_ACTION_RUN": "true",
              "UKAI_ACTION_CREDENTIALS": "x=PATH"}, "cannot hold a credential"),
            ({"UKAI_ACTION_PROFILE": "tool", "UKAI_ACTION_RUN": "true", "UKAI_ACTION_FAIL_ON": "bogus"},
             "fail-on"),
            ({"UKAI_ACTION_PROFILE": "tool", "UKAI_ACTION_RUN": "true",
              "UKAI_ACTION_ARTIFACT_NAME": f"$(touch {marker})/x"}, "artifact-name"),
        ]
        for extra, words in cases:
            with self.subTest(words=words):
                self.assert_refused_unchanged(self.script("check.sh", **extra), words)
        self.assertFalse(marker.exists(), "an input was evaluated")

    # --- credentials.sh (§3.3 item 5, K78) ------------------------------------
    def test_credentials_mask_first_then_stdin_never_argv_or_environment(self):
        self.report_dir()
        result = self.script("credentials.sh", UKAI_ACTION_CREDENTIALS="api=SELFTEST_VALUE",
                             SELFTEST_VALUE=TOKEN + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = [line for line in result.stdout.splitlines() if TOKEN in line]
        self.assertEqual(lines, [f"::add-mask::{TOKEN}"], "the value printed other than in its mask")
        self.assertNotIn(TOKEN, result.stderr)
        [call] = self.calls()
        self.assertEqual(call["argv"], ["credential", "set", "--force", "api"])
        self.assertEqual(call["stdin_sha256"], hashlib.sha256(TOKEN.encode()).hexdigest())
        self.assertNotIn("SELFTEST_VALUE", call["env_names"])

    def test_credentials_empty_fails_naming_the_line(self):
        self.report_dir()
        result = self.script("credentials.sh", UKAI_ACTION_CREDENTIALS="api=SELFTEST_VALUE", SELFTEST_VALUE="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("api=SELFTEST_VALUE", result.stdout)
        self.assertIn("fork", result.stdout)
        self.assertEqual(self.calls(), [])

    def test_credentials_line_break_refused_without_printing_or_masking(self):
        self.report_dir()
        result = self.script("credentials.sh", UKAI_ACTION_CREDENTIALS="api=SELFTEST_VALUE",
                             SELFTEST_VALUE=f"{TOKEN[:30]}\n{TOKEN[30:]}")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(TOKEN[:30], result.stdout + result.stderr)
        self.assertNotIn(TOKEN[30:], result.stdout + result.stderr)
        self.assertEqual(self.calls(), [])

    # --- doctor.sh, run.sh (§3.3 item 4, §3.4, K83, K85) -------------------------
    def test_doctor_not_ready_fails_with_reasons(self):
        self.report_dir()
        result = self.script("doctor.sh", UKAI_ACTION_PROFILE="tool", STUB_DOCTOR_READY="false")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requirement tree_termination: unavailable (bwrap_too_old)", result.stdout)

    def test_run_launch_mode_passes_args_as_argv(self):
        directory = self.report_dir(mode="launch")
        args = ["-p", "$(touch /x)", "`id`", "it's \"q\"", "a;b", "${{ github.token }}", "", "--allow-host=x"]
        result = self.script("run.sh", UKAI_ACTION_LAUNCH="claude", UKAI_ACTION_ARGS="\n".join(args) + "\n",
                             UKAI_ACTION_ALLOW_HOSTS="a.example b.example\nc.example",
                             UKAI_ACTION_LIMITS="wall=30s", UKAI_ACTION_CREDENTIALS="anthropic=SELFTEST_VALUE",
                             SELFTEST_VALUE=TOKEN, STUB_RUN_EXIT=3)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        [call] = self.calls()
        self.assertEqual(call["argv"], ["run", "--launch", "claude", "--from-path", "--workspace",
                                        str(self.workspace),
                                        "--allow-host=a.example", "--allow-host=b.example",
                                        "--allow-host=c.example", "--limit=wall=30s", "--", *args])
        self.assertTrue(call["stdin_devnull"])
        self.assertNotIn("SELFTEST_VALUE", call["env_names"])
        self.assertEqual(self.outputs()["exit-code"], "3")
        self.assertEqual((directory / "attempt-id").read_text(), "att_stub")

    def test_run_profile_mode_passes_run_as_one_element(self):
        self.report_dir()
        script = 'echo "$(id)"\nprintf %s ${{ github.token }}; exit 4'
        result = self.script("run.sh", UKAI_ACTION_PROFILE="agent", UKAI_ACTION_RUN=script)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        [call] = self.calls()
        self.assertEqual(call["argv"], ["run", "--profile", "agent", "--workspace", str(self.workspace),
                                        "--", "/bin/bash", "-e", "-c", script])

    def test_run_turns_workflow_commands_off_around_the_agent(self):
        self.report_dir()
        result = self.script("run.sh", UKAI_ACTION_PROFILE="tool", UKAI_ACTION_RUN="true",
                             STUB_RUN_STDOUT="::set-output name=exit-code::0")
        lines = result.stdout.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith("::stop-commands::"))
        token = lines[start].split("::")[2]
        agent = lines.index("::set-output name=exit-code::0")
        self.assertGreater(len(token), 16)
        self.assertLess(start, agent)
        self.assertLess(agent, lines.index(f"::{token}::"))

    # --- report.sh (§3.5, K78, K79) ----------------------------------------------
    def report(self, trace='{"note": "stub"}', text="ukai-jail: settled · exited 0", **extra):
        directory = self.report_dir()
        self.store(directory, "api", TOKEN)
        summary_json = self.tmp / "summary.json"
        summary_json.write_text(json.dumps(SUMMARY))
        ran = self.script("run.sh", UKAI_ACTION_PROFILE="tool", UKAI_ACTION_RUN="true", STUB_TRACE=trace)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        return directory, self.script("report.sh", UKAI_ACTION_PROFILE="tool", STUB_SUMMARY_JSON=summary_json,
                                      STUB_SUMMARY_TEXT=text, **extra)

    def test_report_writes_the_summary_and_artifact(self):
        directory, result = self.report()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = self.outputs()
        self.assertEqual(outputs["upload"], "true")
        self.assertEqual(outputs["settled"], "true")
        self.assertEqual(sorted(p.name for p in Path(outputs["artifact-dir"]).iterdir()),
                         ["jail.json", "policy.json", "setup.txt", "summary.json", "summary.txt", "trace.ndjson"])
        page = self.summary.read_text()
        self.assertIn("```text\nukai-jail: settled · exited 0\n```", page)
        self.assertIn("host setup (this runner only): bubblewrap 0.11.1 built from its release tarball "
                      "(sha256:c1b7455a…) at /usr/local/bin/bwrap · AppArmor profile ukai-jail-action-bwrap "
                      "allows user namespaces for that binary only", page)

    def test_report_exposure_check_positive_control(self):
        directory, result = self.report(trace=json.dumps({"path": f"/ws/{TOKEN}.txt"}))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact/trace.ndjson (credential api)", result.stdout)
        self.assertNotIn(TOKEN, result.stdout + result.stderr + self.summary.read_text())
        self.assertIn("exposure check FAILED, nothing uploaded", self.summary.read_text())
        self.assertEqual(self.outputs().get("upload"), "false")
        self.assertFalse((directory / "artifact").exists())

    def test_report_fence_outgrows_backticks_in_a_summary(self):
        _, result = self.report(text="ukai-jail: workspace: 1 path opened for writing (```` x)")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("`````text\n", self.summary.read_text())

    # --- verdict.sh and facts.py (§3.6, K81) -------------------------------------
    def verdict(self, status, summary, fail_on):
        directory = self.report_dir()
        (directory / "artifact").mkdir(exist_ok=True)
        (directory / "artifact" / "summary.json").write_text(json.dumps(summary))
        (directory / "exit-code").write_text(str(status))
        return self.script("verdict.sh", UKAI_ACTION_FAIL_ON=fail_on)

    def test_verdict_status_and_each_fail_on_condition(self):
        unsettled = json.loads(json.dumps(SUMMARY))
        unsettled["lines"][0]["facts"].update(phase="enforced", survivors="unknown")
        gaps = json.loads(json.dumps(SUMMARY))
        gaps["lines"][1]["facts"]["classes"]["proxy.net"] = "unsupported"
        cases = [
            (0, SUMMARY, "unsettled,survivors,gaps", 0, None),
            (3, SUMMARY, "unsettled,survivors", 3, "ukai-jail exited 3"),
            (125, unsettled, "", 125, "ukai-jail exited 125"),
            (0, unsettled, "unsettled", 1, "fail-on)::unsettled"),
            (0, unsettled, "survivors", 1, "fail-on)::survivors: survivors are unknown"),
            (0, gaps, "gaps", 1, "fail-on)::gaps: proxy.net unsupported"),
            (0, gaps, "unsettled,survivors", 0, None),
        ]
        for status, summary, fail_on, expected, words in cases:
            with self.subTest(status=status, fail_on=fail_on):
                result = self.verdict(status, summary, fail_on)
                self.assertEqual(result.returncode, expected, result.stdout)
                if words:
                    self.assertIn(words, result.stdout)

    # --- post.sh (§3.5 item 5, K82) ----------------------------------------------
    def post(self, event, payload=None, comments=(), flag="true"):
        directory = self.report_dir()
        (directory / "comment.md").write_text("<!-- m -->\nbody\n")
        (directory / "comment-marker").write_text("ukai-jail-action:wf:job:ukai-jail-receipt")
        event_file = self.tmp / "event.json"
        event_file.write_text(json.dumps(payload or {}))
        comments_file = self.tmp / "comments.json"
        comments_file.write_text(json.dumps([list(comments)]))
        executable(self.stubs / "gh", f"""#!/usr/bin/env python3
import json, sys
with open({str(self.log)!r}, "a") as log:
    log.write(json.dumps({{"gh": sys.argv[1:]}}) + "\\n")
if "--paginate" in sys.argv:
    print(open({str(comments_file)!r}).read())
""")
        result = self.script("post.sh", GITHUB_EVENT_NAME=event, GITHUB_EVENT_PATH=event_file,
                             UKAI_ACTION_PR_COMMENT=flag, UKAI_ACTION_ARTIFACT_URL="https://example.test/a")
        return result, [c["gh"] for c in self.calls() if "gh" in c]

    def pull(self, head="owner/repo"):
        return {"pull_request": {"number": 12, "head": {"repo": {"full_name": head}}},
                "repository": {"full_name": "owner/repo"}}

    def test_post_comment_cases(self):
        mine = {"id": 99, "user": {"login": "github-actions[bot]"},
                "body": "<!-- ukai-jail-action:wf:job:ukai-jail-receipt -->"}
        theirs = {"id": 98, "user": {"login": "someone"}, "body": mine["body"]}
        result, calls = self.post("pull_request", self.pull())
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual([c[:3] for c in calls if "--method" in c], [["api", "--method", "POST"]])
        self.log.unlink()
        result, calls = self.post("pull_request", self.pull(), comments=[theirs, mine])
        self.assertEqual([c[:4] for c in calls if "--method" in c],
                         [["api", "--method", "PATCH", "repos/owner/repo/issues/comments/99"]])
        for event, payload, flag in (("pull_request", self.pull("fork/repo"), "true"),
                                     ("push", {}, "true"), ("pull_request", self.pull(), "false")):
            with self.subTest(event=event, flag=flag):
                if self.log.exists():
                    self.log.unlink()
                result, calls = self.post(event, payload, flag=flag)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(calls, [])

    # --- setup.sh, sourced (§3.3 items 2 and 3, K77) ------------------------------
    def setup_function(self, body, **extra):
        executable(self.stubs / "sudo", f'#!/bin/sh\necho "sudo $*" >> {self.tmp}/sudo.log\nexit 1\n')
        source = f'source {SCRIPTS / "setup.sh"}\n{body}\n'
        env = {**self.env, **{k: str(v) for k, v in extra.items()}}
        return subprocess.run([BASH, "-c", source], env=env, capture_output=True, text=True)

    def test_setup_refuses_a_tarball_whose_digest_differs_before_building(self):
        self.report_dir()
        src = self.runner_temp / "ukai" / "src"
        src.mkdir()
        (src / "bubblewrap-0.11.1.tar.xz").write_bytes(b"not the release tarball")
        result = self.setup_function('first_bwrap() { return 1; }\nensure_bwrap')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not the pinned c1b7455a", result.stdout)
        self.assertFalse((self.tmp / "sudo.log").exists(), "sudo ran before the digest was checked")
        self.assertFalse((src / "bubblewrap-0.11.1").exists())

    def test_setup_loads_no_profile_unless_the_restriction_reads_1(self):
        directory = self.report_dir()
        for reading, words in (("0", "the restriction is not on (reads 0)"), ("absent", "reads absent")):
            with self.subTest(reading=reading):
                result = self.setup_function(f'read_sysctl() {{ printf {reading}; }}\nensure_apparmor')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(words, (directory / "setup.txt").read_text())
                self.assertIn("profile_loaded=false", (directory / "facts.env").read_text())
        self.assertFalse((self.tmp / "sudo.log").exists())


if __name__ == "__main__":
    unittest.main()
