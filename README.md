# mapwatcher - watch memory maps in Linux

This is a tool which watches the memory maps (via /proc/<pid>/smaps
of a running process on Linux.

Usage:

```
mapwatcher PID DELAY
```

where PID is the process ID of a process and DELAY is a time in seconds
between checks. The tool first shows all maps of the process and then
regularly checks and prints the difference to the previous time it checked.

It shows a line for each new map, a line for each deleted map and a
line whenever a map changes its end, its size or its resident set size.

Only maps with a non-empty name are considered.
