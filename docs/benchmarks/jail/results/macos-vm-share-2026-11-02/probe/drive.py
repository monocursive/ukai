#!/usr/bin/env python3
"""K109 share containment probe, host side.

Prepares the exported workspace with escape sentinels (a symlink and a
hardlink that both point outside the share, a protected .git, an NFD
unicode name), boots the cloud image with the share attached, runs the
guest battery via cloud-init, then verifies the host side: what changed
inside and outside the share. Emits a verdict JSON.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
SHARE = ROOT / "share"
OUTSIDE = ROOT / "outside"
DISK = ROOT / "probe.raw"
SEED = ROOT / "seed.iso"
NVRAM = ROOT / "probe.nvram"
CONSOLE = ROOT / "console.log"
VERDICT = ROOT / "verdict.json"
IMAGE_SHA256 = "4e86a7819b4cc7b4a9c2e719dec3e0a723c4a2788dc3f23f17641cba7f5ca216"


def setup_sentinels():
    for path in (SHARE, OUTSIDE):
        if path.exists():
            subprocess.run(["rm", "-rf", str(path)], check=True)
    SHARE.mkdir()
    OUTSIDE.mkdir()
    (SHARE / "keep.txt").write_text("inside\n")
    git = SHARE / ".git"
    git.mkdir()
    (git / "config").write_text("[core]\n")
    # NFD cafe-acute (macOS default decomposition).
    (SHARE / "café.txt").write_text("nfd-original\n")
    (OUTSIDE / "sentinel.txt").write_text("untouched\n")
    # Planted symlink pointing outside the export (relative climb).
    os.symlink("../outside/sentinel.txt", SHARE / "out-link")
    # Pre-existing hardlink inside the share to a file outside it.
    os.link(OUTSIDE / "sentinel.txt", SHARE / "hard-out")
    assert (SHARE / "hard-out").stat().st_ino == (OUTSIDE / "sentinel.txt").stat().st_ino


def seed_iso():
    directory = ROOT / "seed"
    if directory.exists():
        subprocess.run(["rm", "-rf", str(directory)], check=True)
    if SEED.exists():
        SEED.unlink()
    directory.mkdir()
    battery = (ROOT / "battery.sh").read_bytes()
    config = {
        "users": [],
        "ssh_deletekeys": True,
        "ssh_genkeytypes": [],
        "write_files": [
            {"path": "/usr/local/lib/ukai-vm/battery.sh", "encoding": "b64",
             "content": base64.b64encode(battery).decode(), "permissions": "0755"},
        ],
        "runcmd": [["/bin/sh", "/usr/local/lib/ukai-vm/battery.sh"]],
    }
    (directory / "user-data").write_text("#cloud-config\n" + json.dumps(config))
    (directory / "meta-data").write_text(
        "instance-id: ukai-share-probe\nlocal-hostname: ukai-share-probe\n")
    subprocess.run(
        ["hdiutil", "makehybrid", "-o", str(SEED), str(directory), "-iso", "-joliet",
         "-default-volume-name", "cidata"], check=True, capture_output=True)


def prepare_disk():
    if DISK.exists():
        DISK.unlink()
    subprocess.run(
        ["/Users/monocursive/Library/Android/sdk/emulator/qemu-img", "convert",
         "-f", "qcow2", "-O", "raw", str(ROOT / "cache/ubuntu.img"), str(DISK)], check=True)
    with DISK.open("r+b") as disk:
        disk.truncate(6 * 1024 ** 3)


def run_vm():
    if CONSOLE.exists():
        CONSOLE.unlink()
    for stale in (NVRAM,):
        if stale.exists():
            stale.unlink()
    started = time.monotonic()
    process = subprocess.Popen(
        [str(ROOT / "vzshare"), str(DISK), str(SEED), str(NVRAM), str(CONSOLE), str(SHARE)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        code = process.wait(timeout=420)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        code = "timeout"
    return code, time.monotonic() - started


def read(path):
    return path.read_text(errors="replace") if path.exists() else None


def verify():
    outside = read(OUTSIDE / "sentinel.txt")
    git_config = read(SHARE / ".git" / "config")
    guest_link_target = None
    if os.path.islink(SHARE / "guest-planted-link"):
        guest_link_target = os.readlink(SHARE / "guest-planted-link")
    created = SHARE / "created.txt"
    return {
        "outside_sentinel": outside,
        "outside_touched": outside != "untouched\n",
        "git_config": git_config,
        "git_touched": git_config != "[core]\n",
        "git_dir_case_variant_created": (SHARE / "GIT").exists(),
        "hardlink_write_escaped": outside == "pwned-hard\n",
        "nfc_variant_files": sorted(p.name for p in SHARE.glob("caf*")),
        "nfd_original_content": read(SHARE / "café.txt"),
        "created_mode": oct(created.stat().st_mode & 0o777) if created.exists() else None,
        "devnode_exists": (SHARE / "devnode").exists(),
        "fifo_exists": (SHARE / "fifo").exists(),
        "guest_planted_link": guest_link_target,
        "keep_moved_out": not (SHARE / "keep.txt").exists(),
        "share_listing": sorted(p.name for p in SHARE.iterdir()),
    }


def main():
    image = ROOT / "cache/ubuntu.img"
    if not image.exists():
        sys.exit("image missing")
    import hashlib
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    assert digest == IMAGE_SHA256, f"image sha mismatch: {digest}"
    setup_sentinels()
    seed_iso()
    prepare_disk()
    code, elapsed = run_vm()
    console = read(CONSOLE) or ""
    verdict = {
        "vm_exit": code,
        "elapsed_s": round(elapsed, 1),
        "console": console,
        "host_side": verify(),
    }
    VERDICT.write_text(json.dumps(verdict, indent=2) + "\n")
    print(json.dumps({k: verdict[k] for k in ("vm_exit", "elapsed_s")}))
    print(json.dumps(verdict["host_side"], indent=2))


if __name__ == "__main__":
    main()
