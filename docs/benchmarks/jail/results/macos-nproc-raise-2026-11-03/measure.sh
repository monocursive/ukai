#!/bin/sh
# Can a non-root process raise RLIMIT_NPROC, and how far? No limit is
# raised above what the shell inherited; every change dies with its subshell.
echo "== host"
sw_vers
uname -srm
echo "uid=$(id -u)"
sysctl kern.maxproc kern.maxprocperuid
echo "== 1. inherited, then raise the soft limit (hard untouched)"
/bin/sh -c 'echo "inherited: soft=$(ulimit -Su) hard=$(ulimit -Hu)"
  ulimit -Su 12000; echo "raise soft to 12000: rc=$? soft=$(ulimit -Su) hard=$(ulimit -Hu)"
  ulimit -Su 16000 2>&1; echo "raise soft to 16000: rc=$? soft=$(ulimit -Su) hard=$(ulimit -Hu)"'
echo "== 2. soft lowered to 5000 (the only change), then a child raises it"
/bin/sh -c 'ulimit -Su 5000; echo "lowered: soft=$(ulimit -Su) hard=$(ulimit -Hu)"
  /bin/sh -c "ulimit -Su 10666; echo \"child raise to 10666: rc=\$? soft=\$(ulimit -Su) hard=\$(ulimit -Hu)\"
    ulimit -Su 12000 2>&1; echo \"child raise to 12000: rc=\$? soft=\$(ulimit -Su)\""'
echo "== 3. soft 5000 and hard 8000 (both lowered), then a child raises"
/bin/sh -c 'ulimit -Su 5000; ulimit -Hu 8000; echo "lowered: soft=$(ulimit -Su) hard=$(ulimit -Hu)"
  /bin/sh -c "ulimit -Su 8000; echo \"child raise to hard 8000: rc=\$? soft=\$(ulimit -Su)\"
    ulimit -Su 9000 2>&1; echo \"child raise to 9000: rc=\$? soft=\$(ulimit -Su)\""'
echo "== 4. setrlimit directly (python3 resource): soft 5000, hard as inherited"
python3 -c '
import resource as r
s, h = r.getrlimit(r.RLIMIT_NPROC)
print("inherited", (s, h))
r.setrlimit(r.RLIMIT_NPROC, (5000, h))
print("after setrlimit(5000, %d):" % h, r.getrlimit(r.RLIMIT_NPROC))
'
