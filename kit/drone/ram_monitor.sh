#!/bin/sh
# RAM and CPU of the ArduCopter process, once per second (busybox compatible:
# runs on the PC against SITL).
#
#   sh ram_monitor.sh <out.csv> <seconds> [process-name-pattern] [pid]
#
# An explicit pid skips the name search; it is needed when several processes
# share a name (the two dtls_tunnel endpoints, one per network namespace).
#
# CSV: t_s,pid,vmrss_kb,vmhwm_kb,utime_ticks,stime_ticks
#   VmRSS = resident memory now, VmHWM = peak resident memory,
#   utime/stime = CPU ticks (USER_HZ, normally 100/s) used so far;
#   summarize.py turns the tick deltas into CPU %.

OUT=${1:?usage: ram_monitor.sh out.csv seconds [pattern] [pid]}
DUR=${2:?usage: ram_monitor.sh out.csv seconds [pattern] [pid]}
PAT=${3:-arducopter}

find_pid() {
    for d in /proc/[0-9]*; do
        [ -r "$d/cmdline" ] || continue
        # match the executable name (argv[0]) only, not the arguments, so that
        # scripts with "arducopter" in their arguments are not picked up
        exe=$(tr '\000' '\n' < "$d/cmdline" 2>/dev/null | head -n 1)
        case "${exe##*/}" in
            *"$PAT"*) echo "${d#/proc/}"; return 0 ;;
        esac
    done
    return 1
}

PID=${4:-$(find_pid)}
if [ -z "$PID" ]; then
    echo "ram_monitor: no process matching '$PAT'" >&2
    exit 1
fi
echo "ram_monitor: pid $PID ($PAT), ${DUR} s -> $OUT" >&2
echo "t_s,pid,vmrss_kb,vmhwm_kb,utime_ticks,stime_ticks" > "$OUT"
i=0
while [ "$i" -lt "$DUR" ]; do
    [ -r "/proc/$PID/status" ] || { echo "ram_monitor: process $PID ended" >&2; break; }
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$PID/status")
    hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$PID/status")
    # fields 14 and 15 of /proc/pid/stat, counted after the ")" of the command name
    ticks=$(sed 's/^.*) //' "/proc/$PID/stat" | awk '{print $12 "," $13}')
    echo "$i,$PID,$rss,$hwm,$ticks" >> "$OUT"
    i=$((i + 1))
    sleep 1
done
