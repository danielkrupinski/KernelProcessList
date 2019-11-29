# KernelProcessList
Example Windows Kernel-mode Driver which enumerates running processes.

## Output
Driver writes process list to the `KernelProcessList.txt` file located in Windows directory (%SystemRoot%).

Example output:
```
System : 4
Registry : 104
smss.exe : 348
csrss.exe : 548
wininit.exe : 636
csrss.exe : 644
winlogon.exe : 736
services.exe : 772
lsass.exe : 800
svchost.exe : 940
svchost.exe : 964
fontdrvhost.exe : 992
fontdrvhost.exe : 988
svchost.exe : 496
svchost.exe : 884
dwm.exe : 1044
```