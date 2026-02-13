---
name: aurora-instance-ops
description: Install, run, tune, and maintain Aurora for Linux instances, including systemd service deployment, signature updates, noisy-process reduction, and pprof-based memory/CPU troubleshooting.
---

# Aurora Instance Ops

Use this skill when the user asks to install Aurora, run it as a service, tune noisy detections, or investigate performance/memory issues.

## Preconditions

- Target OS is Linux with `systemd`.
- Root access is available (`sudo`).
- Repo is available or Aurora package already exists under `/opt/aurora-linux`.
- For source builds on Linux, `go`, `make`, `bpftool`, and `clang` are required.

## Standard Workflow

1. Build binaries (source checkout path):
```bash
make build
```

2. Install service and default runtime layout.
From source checkout:
```bash
sudo ./scripts/install-service.sh \
  --aurora-binary ./aurora \
  --aurora-util-binary ./aurora-util
```
From extracted package under `/opt/aurora-linux`:
```bash
sudo /opt/aurora-linux/scripts/install-service.sh
```

3. Validate service health:
```bash
sudo systemctl status aurora --no-pager
sudo journalctl -u aurora -n 100 --no-pager
```

4. Validate logfile output:
```bash
sudo tail -n 50 /var/log/aurora-linux/aurora.log
```
If JSON output is enabled:
```bash
sudo tail -f /var/log/aurora-linux/aurora.log | jq .
```

5. Verify rules directory and updater:
```bash
sudo /opt/aurora-linux/aurora-util update-signatures
```

## Runtime Config Pattern

Primary config file: `/opt/aurora-linux/config/aurora.env`.

Do not edit `/etc/systemd/system/aurora.service` unless the user explicitly asks. Prefer setting flags via `AURORA_EXTRA_ARGS`, then restart:
```bash
sudo systemctl restart aurora
sudo systemctl status aurora --no-pager
```

Common `AURORA_EXTRA_ARGS` examples:
- `--stats-interval 30`
- `--min-level medium`
- `--throttle-rate 0.5 --throttle-burst 3`
- `--process-exclude /usr/bin/some-noisy-binary`
- `--pprof-listen 127.0.0.1:6060` (only during troubleshooting)

## Noisy Detection Tuning Playbook

Apply these in order, from safest to most aggressive:

1. Reduce volume without dropping categories:
- Increase threshold: `--min-level medium`
- Tighten duplicate suppression: lower `--throttle-rate`, tune `--throttle-burst`

2. Identify top noisy process candidates from logs:
```bash
sudo tail -n 5000 /var/log/aurora-linux/aurora.log \
  | jq -r '.Image,.ParentImage // empty' \
  | sort | uniq -c | sort -nr | head -30
```

3. Use `--process-exclude` only if still needed.
- It is a substring match across `Image`, `CommandLine`, `ParentImage`, and `ParentCommandLine`.
- Keep the filter narrow (prefer full path or specific command fragment).
- Re-check detections after each change to avoid blind spots.

4. Restart and verify:
```bash
sudo systemctl restart aurora
sudo journalctl -u aurora -n 80 --no-pager
```

## Memory/Leak Triage (pprof)

When Aurora shows sustained memory growth:

1. Enable temporary pprof endpoint (loopback only):
- Add to `AURORA_EXTRA_ARGS`: `--pprof-listen 127.0.0.1:6060`
- Restart service.

2. Capture profiles:
```bash
sudo /opt/aurora-linux/aurora-util collect-profile \
  --pprof-url http://127.0.0.1:6060 \
  --output-dir /tmp/aurora-profiles \
  --cpu-seconds 30 \
  --heap \
  --allocs
```

3. Wait under representative load, then capture again to compare growth.

4. Analyze with Go pprof tools:
```bash
go tool pprof -top /tmp/aurora-profiles/<heap-profile>.pprof
go tool pprof -top -base /tmp/aurora-profiles/<earlier-heap>.pprof /tmp/aurora-profiles/<later-heap>.pprof
go tool pprof -http=:0 /tmp/aurora-profiles/<later-heap>.pprof
```

5. If one allocation path dominates growth, report function/package hotspots and recommend the smallest safe mitigation first (rule level tuning, throttle changes, temporary process exclude).

6. Disable pprof after triage by removing `--pprof-listen` and restarting.

## Scheduled Maintenance

Install recurring maintenance (signature refresh + service restart):
```bash
sudo ./scripts/install-maintenance-cron.sh --schedule "17 3 * * *"
```

Enable weekly binary upgrade in the same job when requested:
```bash
sudo ./scripts/install-maintenance-cron.sh \
  --schedule "17 3 * * *" \
  --enable-binary-upgrade
```

Expected artifacts:
- `/etc/cron.d/aurora-maintenance`
- `/opt/aurora-linux/bin/aurora-maintenance.sh`
- `/var/log/aurora-linux/maintenance.log`

## Quick Troubleshooting Checks

- Service flaps on startup:
  - Check `journalctl -u aurora -n 120 --no-pager`.
  - Confirm `AURORA_RULES_DIR` exists and contains loadable Linux rules.
- No output with `--no-stdout`:
  - Ensure at least one sink is set (`--logfile`, `--tcp-target`, or `--udp-target`).
- Logfile startup failure:
  - Verify parent directory exists and permissions allow Aurora to open a regular file.
- pprof bind error:
  - `--pprof-listen` must be loopback (`localhost`, `127.0.0.1`, or `::1`) and free port.

## Agent Behavior Rules

- Prefer install/maintenance scripts over ad-hoc manual steps.
- Make one tuning change at a time and verify impact before stacking more changes.
- Preserve existing user config unless explicitly asked to reset.
- For high-volume environments, suggest log forwarding via `/opt/aurora-linux/deploy/templates/rsyslog-aurora.conf.example`.
