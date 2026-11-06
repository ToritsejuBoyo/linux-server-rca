# Linux Diagnostic Thresholds & Systemd Error Reference

## 1. Systemd Unit Failure Codes

| Status / Exit Code | Name | Cause | Resolution |
| --- | --- | --- | --- |
| `status=203/EXEC` | Exec failed | Service binary not found or missing execute (`+x`) permissions | Verify binary path in `.service` file and permissions |
| `status=217/USER` | User failed | Service user/group specified in `.service` does not exist | Add system account or update `User=` parameter |
| `status=1/FAILURE` | Application Error | Binary crashed on startup (missing config file, syntax error) | Run binary manually with `--test` or inspect service stdout |
| `status=137` | SIGKILL (9) | Process killed by OOM killer or external SIGKILL | Check `dmesg | grep oom` and review memory limits |
| `status=143` | SIGTERM (15) | Process gracefully requested to stop | Verify if automated scaler or admin initiated stop |

---

## 2. Resource Saturation Thresholds

- **Load Average vs CPU Cores:** If 1-minute load average is > (2 × number of cores), investigate thread contention.
- **I/O Wait (`%wa` in top):** If `%wa` > 15%, storage subsystem is unable to keep up with write queues.
- **Swap In/Out (`si`/`so` in vmstat):** Continuous non-zero `si`/`so` indicates active memory thrashing.
- **Inode Exhaustion:** When `IUse%` reaches 100%, applications will throw `No space left on device` even with gigabytes of free disk space.
