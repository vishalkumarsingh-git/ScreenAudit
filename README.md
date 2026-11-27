# ScreenAudit

**ScreenAudit** is a native Windows screen-activity viewer written in C++17. It uses Win32 foreground-window events, a periodic idle check, local CSV files, and a GDI+ dashboard.

> **Development status: early foundation / not feature-complete.** This version provides foreground-process usage collection, idle exclusion, daily CSV logging, a basic dashboard, a notification-area icon, pause/resume, startup registration, and CSV export. It does not implement the complete Apple Screen Time feature set.

## Design

- Native Win32 desktop window and notification-area integration.
- Segoe UI typography and Windows accent blue (`#0078D4`).
- Light and dark palette foundations.
- GDI+ double-buffered dashboard painting.
- No Electron, WebView2, .NET, Qt, Python, or external database runtime.
- Local daily CSV storage under `%APPDATA%\\ScreenAudit\\`.

## Implemented

- Foreground-window notifications using `SetWinEventHook(EVENT_SYSTEM_FOREGROUND, ...)`.
- Executable-name attribution, with best-effort child-process lookup for `ApplicationFrameHost.exe`.
- Idle exclusion using `GetLastInputInfo()` on a 15-second timer; default cutoff is five minutes.
- Daily UTF-8 CSV append logs named `YYYY-MM-DD.csv`, with binary-safe multi-day export.
- Dashboard with today's accumulated usage and a ranked application list.
- Notification-area context menu: open, pause/resume, export, startup toggle, dark-mode toggle, idle-cutoff selection (3/5/10 minutes), and exit.
- Session-unlock notification registration (counts are in memory only in this version).
- Startup registration quotes the executable path so installations under directories containing spaces work correctly.
- Dashboard reports the tracked-app count rather than displaying today's total as a misleading daily average.

## Current scope and limitations

This is **not yet a complete digital-wellbeing manager** and must not be represented as having full macOS Screen Time parity.

Not implemented yet: scheduled downtime enforcement, per-app/category quotas, whitelist management UI, reliable app-restriction enforcement, lock overlay flows, secure PIN enrollment/verification, eye-break reminders, persistent pickup analytics, hourly/category charts, app icon extraction, and full settings pages.

A topmost overlay is not a security boundary. This version does not terminate, suspend, or prevent other processes from launching. Reliable enforcement requires a separately designed Windows service/policy architecture, permission analysis, recovery paths, and explicit user consent. The current app is an activity viewer, not a process-control security product.

The 5 MB memory goal is a profiling target, not a verified guarantee. Actual memory use depends on Windows, the graphics stack, loaded DLLs, and process architecture. Measure release builds on minimum supported hardware before publishing a footprint claim.

Windows does not expose every macOS Screen Time capability through ordinary Win32 APIs. Family sharing, cross-device aggregation, web-content restrictions, and equivalent ecosystem features require additional platform services.

## Data and privacy

- Logs: `%APPDATA%\\ScreenAudit\\YYYY-MM-DD.csv`.
- Preferences: `%APPDATA%\\ScreenAudit\\settings.ini`.
- No telemetry upload or cloud synchronization is implemented.
- CSV logs contain executable names and usage durations. Treat them as personal activity data.
- Delete the `ScreenAudit` folder under `%APPDATA%` to remove local logs and settings.

## Build

GitHub Actions builds on `windows-latest` with MinGW-w64 and uploads `ScreenAudit.exe` as the `ScreenAudit-windows-x64` artifact.

Local MinGW-w64 build:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -municode src/main.cpp -o ScreenAudit.exe -static -static-libgcc -static-libstdc++ -lgdiplus -luser32 -lgdi32 -lshell32 -lpsapi -lwtsapi32 -ldwmapi -lcomdlg32 -lcomctl32 -ladvapi32 -mwindows
```

The target is 64-bit Windows. A successful commit does not itself mean the executable has compiled; check the Actions run.

## Repository layout

```text
ScreenAudit/
├── .github/workflows/build.yml
├── src/main.cpp
└── README.md
```

## License

No license has been selected yet. Until a license is added, normal copyright restrictions apply; a public repository is not automatically open-source licensed.
