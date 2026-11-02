#!/bin/sh
# K109 share containment battery, guest side. Runs as root via cloud-init.
# Every line reaches the host through the captured console (hvc0).
exec > /dev/hvc0 2>&1
echo "PROBE battery-start $(date -u +%FT%TZ) kernel=$(uname -release)"
modprobe virtiofs 2>/dev/null
mkdir -p /mnt/ws
if ! mount -t virtiofs share /mnt/ws; then
    echo "PROBE mount FAILED"
    sleep 2
    poweroff -f
fi
echo "PROBE mount ok fstype=$(mount | grep /mnt/ws | head -1)"
echo "PROBE inventory-begin"
ls -la /mnt/ws
echo "PROBE inventory-end"

# A. symlink resolution: the planted host-side link points outside.
if cat /mnt/ws/out-link > /tmp/a.read 2>/dev/null; then
    echo "PROBE read_through_planted_link BYTES=$(wc -c < /tmp/a.read) DATA=$(head -c 40 /tmp/a.read | tr -d '\n')"
else
    echo "PROBE read_through_planted_link refused"
fi
if echo pwned-host-link > /mnt/ws/out-link 2>/dev/null; then
    echo "PROBE write_through_planted_link WROTE"
else
    echo "PROBE write_through_planted_link refused"
fi
ln -s ../../../outside/sentinel.txt /mnt/ws/guest-planted-link
if echo pwned-guest-link > /mnt/ws/guest-planted-link 2>/dev/null; then
    echo "PROBE write_planted_relative_link WROTE"
else
    echo "PROBE write_planted_relative_link refused"
fi

# B. hardlinks: the host pre-made one inside the share to a file outside.
if echo pwned-hard > /mnt/ws/hard-out 2>/dev/null; then
    echo "PROBE write_preexisting_hardlink WROTE"
else
    echo "PROBE write_preexisting_hardlink refused"
fi
if ln /mnt/ws/keep.txt /mnt/ws/hard-inside 2>/dev/null; then
    echo "PROBE guest_hardlink_inside ok"
else
    echo "PROBE guest_hardlink_inside refused"
fi

# C. case folding against the guest's case-sensitive view.
if mkdir /mnt/ws/GIT 2>/dev/null; then echo "PROBE mkdir_GIT created"; else echo "PROBE mkdir_GIT refused"; fi
if echo pwned-case > /mnt/ws/GIT/config 2>/dev/null; then echo "PROBE write_GIT_config WROTE"; else echo "PROBE write_GIT_config refused"; fi
if echo pwned-case-dot > /mnt/ws/.GIT/config 2>/dev/null; then echo "PROBE write_dotGIT_config WROTE"; else echo "PROBE write_dotGIT_config refused"; fi

# D. Unicode normalization folding (host file is NFD cafe-acute).
if printf pwned-nfc > "/mnt/ws/café.txt" 2>/dev/null; then echo "PROBE write_nfc_variant WROTE"; else echo "PROBE write_nfc_variant refused"; fi
if printf pwned-ascii > /mnt/ws/cafe.txt 2>/dev/null; then echo "PROBE write_ascii_cafe WROTE"; else echo "PROBE write_ascii_cafe refused"; fi

# E. special nodes.
if mknod /mnt/ws/devnode c 1 3 2>/dev/null; then echo "PROBE mknod created"; else echo "PROBE mknod refused"; fi
if mkfifo /mnt/ws/fifo 2>/dev/null; then echo "PROBE mkfifo created"; else echo "PROBE mkfifo refused"; fi

# F. creation, mode and xattr.
if echo hi > /mnt/ws/created.txt && chmod 0755 /mnt/ws/created.txt; then
    echo "PROBE create_chmod ok stat=$(stat -c %a /mnt/ws/created.txt)"
fi
python3 - <<'PY'
import os
try:
    os.setxattr("/mnt/ws/created.txt", "user.probe", b"x")
    print("PROBE setxattr ok")
except OSError as error:
    print(f"PROBE setxattr refused errno={error.errno}")
try:
    os.setxattr("/mnt/ws/created.txt", "com.apple.provenance", b"x")
    print("PROBE setxattr_apple ok")
except OSError as error:
    print(f"PROBE setxattr_apple refused errno={error.errno}")
PY

# G. guest-side .. traversal (expected to stay inside the guest VFS).
echo "PROBE guest_dotdot $(ls /mnt/ws/.. 2>&1 | head -c 100 | tr '\n' ' ')"

# H. rename that would climb (guest-side; expected refused by the mount).
if mv /mnt/ws/keep.txt /mnt/ws/../escaped.txt 2>/dev/null; then
    echo "PROBE rename_climb MOVED"
else
    echo "PROBE rename_climb refused"
fi

echo "PROBE battery-done"
sync
sleep 1
poweroff -f
