#!/bin/sh
exec > /dev/hvc0 2>&1
echo "PROBE3 start"
modprobe virtiofs 2>/dev/null
mkdir -v /mnt/ws /mnt/mapped 2>&1
ls -ld /mnt /mnt/ws /mnt/mapped 2>&1
ls /sys/fs/virtiofs 2>&1 || echo "no /sys/fs/virtiofs"
useradd -m -u 1500 probe3 2>&1 || echo "useradd rc=$?"
if mount -t virtiofs -o uid=1500,gid=1500 share /mnt/mapped 2>/tmp/m3; then
    echo "PROBE3 mount_uid_gid ok"; ls -lan /mnt/mapped | head -5
else
    echo "PROBE3 mount_uid_gid refused: $(cat /tmp/m3)"
fi
if mount -t virtiofs share /mnt/ws 2>/tmp/m4; then
    echo "PROBE3 plain mount ok"; ls -lan /mnt/ws | head -5
else
    echo "PROBE3 plain mount refused: $(cat /tmp/m4)"
fi
su -s /bin/sh probe3 -c 'echo as-user > /mnt/ws/user-write.txt' 2>/tmp/e3 && echo "PROBE3 uid1500_plain_write WROTE" || echo "PROBE3 uid1500_plain_write refused: $(head -1 /tmp/e3)"
su -s /bin/sh probe3 -c 'echo as-user > /mnt/mapped/user-write.txt' 2>/tmp/e4 && echo "PROBE3 uid1500_mapped_write WROTE" || echo "PROBE3 uid1500_mapped_write refused: $(head -1 /tmp/e4)"
dmesg 2>/dev/null | grep -i virtio | tail -3
echo "PROBE3 done"; sync; sleep 1; poweroff -f
