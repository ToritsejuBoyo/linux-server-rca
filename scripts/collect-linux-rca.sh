#!/usr/bin/env bash
#
# collect-linux-rca.sh - Read-only Linux diagnostic telemetry collector
# Gathers systemd, memory, disk, inode, and kernel error state into sanitized JSON.
# Zero third-party dependencies. Pure native Linux utilities and /proc filesystem.
#

set -o pipefail

SANITIZE=false
for arg in "$@"; do
  if [ "$arg" == "--sanitize" ] || [ "$arg" == "-s" ]; then
    SANITIZE=true
  fi
done

# Hostname
RAW_HOSTNAME=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo "unknown-host")
if [ "$SANITIZE" = true ]; then
  HASHED_HOST=$(echo -n "$RAW_HOSTNAME" | sha256sum 2>/dev/null | awk '{print substr($1,1,12)}')
  HOST="mock-server-${HASHED_HOST}.synthetic-lab.local"
else
  HOST="$RAW_HOSTNAME"
fi

# Kernel & Uptime
KERNEL=$(uname -r 2>/dev/null || echo "unknown-kernel")
UPTIME=$(uptime -p 2>/dev/null || cat /proc/uptime 2>/dev/null | awk '{print "up " int($1/86400) " days, " int(($1%86400)/3600) " hours"}' || echo "up unknown")

echo "{"
echo '  "timestamp_utc": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "1970-01-01T00:00:00Z")'",'
echo '  "hostname": "'"$HOST"'",'
echo '  "kernel": "'"$KERNEL"'",'
echo '  "uptime": "'"$UPTIME"'",'

# 1. IP Addresses
echo '  "ip_addresses": ['
FIRST_IP=true
while read -r ip; do
  if [ -n "$ip" ]; then
    if [ "$FIRST_IP" = true ]; then FIRST_IP=false; else echo ","; fi
    if [ "$SANITIZE" = true ]; then
      echo -n '    "192.0.2.'$((RANDOM % 200 + 10))'"'
    else
      echo -n '    "'$ip'"'
    fi
  fi
done < <(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.')
echo ""
echo '  ],'

# 2. Failed systemd units
echo '  "failed_services": ['
FIRST_SVC=true
while read -r svc; do
  if [ -n "$svc" ]; then
    if [ "$FIRST_SVC" = true ]; then FIRST_SVC=false; else echo ","; fi
    echo -n '    "'"$svc"'"'
  fi
done < <(systemctl --failed --no-legend 2>/dev/null | awk '{print $2}')
echo ""
echo '  ],'

# 3. Disk Storage Usage (df -hP)
echo '  "disk_usage": ['
FIRST_DISK=true
while read -r line; do
  if [ -n "$line" ]; then
    if [ "$FIRST_DISK" = true ]; then FIRST_DISK=false; else echo ","; fi
    clean_line=$(echo "$line" | sed 's/"/\\"/g')
    echo -n '    "'"$clean_line"'"'
  fi
done < <(df -hP 2>/dev/null | grep -vE '^Filesystem|tmpfs|cdrom|overlay|shm')
echo ""
echo '  ],'

# 4. Inode Usage (df -iP)
echo '  "inode_usage": ['
FIRST_INODE=true
while read -r line; do
  if [ -n "$line" ]; then
    if [ "$FIRST_INODE" = true ]; then FIRST_INODE=false; else echo ","; fi
    clean_line=$(echo "$line" | sed 's/"/\\"/g')
    echo -n '    "'"$clean_line"'"'
  fi
done < <(df -iP 2>/dev/null | grep -vE '^Filesystem|tmpfs|cdrom|overlay|shm')
echo ""
echo '  ],'

# 5. Memory & OOM killer
FREE_STR="total:unknown, used:unknown, free:unknown, available:unknown"
if command -v free >/dev/null 2>&1; then
  FREE_STR=$(free -h 2>/dev/null | grep -E '^Mem:' | awk '{print "total:"$2", used:"$3", free:"$4", available:"$7}')
elif [ -r /proc/meminfo ]; then
  MEM_TOTAL=$(awk '/MemTotal:/ {print int($2/1024) "Mi"}' /proc/meminfo)
  MEM_AVAIL=$(awk '/MemAvailable:/ {print int($2/1024) "Mi"}' /proc/meminfo)
  FREE_STR="total:$MEM_TOTAL, available:$MEM_AVAIL"
fi

OOM_COUNT=0
if command -v dmesg >/dev/null 2>&1; then
  OOM_COUNT=$(dmesg -T 2>/dev/null | grep -ic "Out of memory" || echo "0")
fi
if [ "$OOM_COUNT" -eq 0 ] 2>/dev/null && command -v journalctl >/dev/null 2>&1; then
  OOM_COUNT=$(journalctl -k -b 2>/dev/null | grep -ic "Out of memory" || echo "0")
fi

echo '  "memory": {'
echo '    "free_h": "'"$FREE_STR"'",'
echo '    "oom_killer_events": '"$OOM_COUNT"
echo '  },'

# 6. Uninterruptible sleep processes (D-state)
echo '  "processes_uninterruptible_sleep": ['
FIRST_D=true
while read -r line; do
  if [ -n "$line" ]; then
    if [ "$FIRST_D" = true ]; then FIRST_D=false; else echo ","; fi
    clean_d=$(echo "$line" | sed 's/"/\\"/g')
    echo -n '    "'"$clean_d"'"'
  fi
done < <(ps -eo pid,stat,comm 2>/dev/null | awk '$2 ~ /D/ {print $3 " (PID: " $1 ", State: " $2 ")"}')
echo ""
echo '  ],'

# 7. Recent priority errors (journalctl / dmesg)
echo '  "recent_kernel_errors": ['
FIRST_ERR=true
ERR_CMD="journalctl -p 3 -xb -n 15 --no-pager 2>/dev/null"
if ! command -v journalctl >/dev/null 2>&1 || ! journalctl -n 1 >/dev/null 2>&1; then
  ERR_CMD="dmesg -T 2>/dev/null | grep -iE 'error|failed|fault|oom|corrupt|kill' | tail -n 15"
fi

while IFS= read -r line; do
  if [ -n "$line" ]; then
    if [ "$FIRST_ERR" = true ]; then FIRST_ERR=false; else echo ","; fi
    clean_err=$(echo "$line" | sed 's/"/\\"/g' | sed 's/\t/ /g')
    if [ "$SANITIZE" = true ]; then
      clean_err=$(echo "$clean_err" | sed -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/198.51.100.25/g')
    fi
    echo -n '    "'"$clean_err"'"'
  fi
done < <(eval "$ERR_CMD")
echo ""
echo '  ]'

echo "}"
