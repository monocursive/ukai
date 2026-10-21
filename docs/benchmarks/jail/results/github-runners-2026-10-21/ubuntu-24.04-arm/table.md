| runner | variant | bwrap | bwrap probe | doctor tool ready | doctor agent ready | tool run | agent run |
|---|---|---|---|---|---|---|---|
| ubuntu-24.04-arm | 1-stock | bubblewrap 0.9.0 | rc=1 | False | False | rc=125 | rc=125  |
| ubuntu-24.04-arm | 2-bwrap-0.11.1 | bubblewrap 0.11.1 | rc=1 | False | False | rc=125 | rc=125  |
| ubuntu-24.04-arm | 3-bwrap-0.11.1+apparmor-profile | bubblewrap 0.11.1 | rc=0 | True | True | rc=0 | http 200 rc=0  |
| ubuntu-24.04-arm | 4-bwrap-0.11.1+sysctl0 | bubblewrap 0.11.1 | rc=0 | True | True | rc=0 | http 200 rc=0  |
