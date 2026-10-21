import sys, os
# usage: binwin.py FILE NEEDLE BEFORE AFTER [MAXHITS]
path, needle, before, after = sys.argv[1], sys.argv[2].encode(), int(sys.argv[3]), int(sys.argv[4])
maxhits = int(sys.argv[5]) if len(sys.argv) > 5 else 3
data = open(path, "rb").read()
i = 0; n = 0
while n < maxhits:
    i = data.find(needle, i)
    if i < 0: break
    print("@%d:" % i, data[max(0, i - before):i + len(needle) + after].decode("utf-8", "replace"))
    print("-----")
    i += 1; n += 1
