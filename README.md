# Adaptive Memory Optimization Engine (AMOE)

AMOE is a modular C++17 system utility that observes live processes, converts activity into a process reference stream, simulates four page replacement policies, chooses the safest fitting policy for the current machine state, and produces explainable process recommendations with confirmation and audit logging.

## Architecture

- `system/process_manager.*`
  Cross-platform process abstraction. Linux uses `/proc`, Windows uses WinAPI, and other POSIX systems fall back to real `ps`-backed process inspection.
- `monitor/tracker.*`
  Collects repeated live snapshots, tracks recent activity, and generates the PID-based reference stream plus system-state signals.
- `algorithms/*.cpp`
  FCFS, LRU, Optimal, and Hybrid page replacement simulations with step-by-step output and page fault totals.
- `decision/engine.*`
  Chooses the preferred algorithm for the detected system state and ranks low-value process actions.
- `security/*.cpp`
  Applies classification, permission awareness, and action restrictions.
- `audit/*.cpp`
  Appends JSON-line audit records, reads them back, filters them, and supports undo lookup.
- `ui/cli.*`
  Beginner-friendly CLI, confirmation prompts, detailed explainability output, and log viewing.

## Build

### Linux with `g++`

```bash
g++ -std=c++17 -Wall -Wextra -pedantic -O2 \
  main.cpp common/utils.cpp config/config.cpp system/process_manager.cpp \
  algorithms/fcfs.cpp algorithms/lru.cpp algorithms/optimal.cpp algorithms/hybrid.cpp \
  monitor/tracker.cpp decision/engine.cpp security/safety.cpp security/permissions.cpp \
  audit/logger.cpp audit/audit_reader.cpp ui/cli.cpp \
  -o amoe
```

### Cross-platform with CMake

```bash
cmake -S . -B build
cmake --build build
```

### Windows (MSVC)

```powershell
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

### Windows (MinGW)

```bash
g++ -std=c++17 -Wall -Wextra -O2 ^
  main.cpp common/utils.cpp config/config.cpp system/process_manager.cpp ^
  algorithms/fcfs.cpp algorithms/lru.cpp algorithms/optimal.cpp algorithms/hybrid.cpp ^
  monitor/tracker.cpp decision/engine.cpp security/safety.cpp security/permissions.cpp ^
  audit/logger.cpp audit/audit_reader.cpp ui/cli.cpp ^
  -lpsapi -ladvapi32 -o amoe.exe
```

## Run

```bash
./amoe --mode dry-run
./amoe --mode advanced
./amoe --view-logs
./amoe --undo-last
```

## Sample Execution Output

```text
====================================
Adaptive Memory Optimization Engine
====================================
Processes: 380
Frames: 5
Mode: DRY_RUN
Platform: macOS libproc
Memory Pressure: 80.1%
Privileges: standard user

Algorithm Comparison
--------------------
FCFS    : 40 faults
LRU     : 40 faults
OPTIMAL : 25 faults
HYBRID  : 40 faults  <== selected
System State: High memory pressure detected above configured threshold. Background overload detected from low-CPU, high-RSS processes. Reference stream contains repeating access windows.
  - Background overload favors the Hybrid policy.
  - Selected HYBRID with 40 page faults inside the preferred policy set.

Process: Code Helper (Renderer)
PID: 1242
Memory: 632.3 MB
Last Active: 0 sec ago
Confidence: HIGH
Recommended: SUSPEND
--------------------

Options:
[1] Apply
[2] Skip
[3] Always ignore
[4] View details

Choice:
[OK] Recommendation skipped.
```

## Security Model

- Critical processes are never touched. PID `0`, PID `1`, and configured critical names are hard-blocked.
- Protected processes can be whitelisted in `amoe.conf` or through the CLI using `Always ignore`.
- Non-elevated sessions are restricted to user-owned processes where ownership is available.
- Live actions require explicit `YES` confirmation unless the user skips or whitelists the recommendation.
- Every decision is written to `amoe_audit.log` in structured JSON-line format.

## Modes

- `beginner`: concise recommendations with confirmation and detail-on-demand.
- `advanced`: same safety flow, intended for deeper inspection with the details view.
- `auto`: preselects the recommended action but still requires confirmation.
- `dry-run`: executes the full analysis path while preventing any live process action.

## Limitations

- Optimal uses the observed reference window as an approximation of future access.
- CPU usage is approximate and platform-dependent.
- Suspend and priority controls are best-effort and depend on OS permissions.
- Kill actions are intentionally conservative and may still be blocked by OS policy or missing privileges.
- On non-Linux POSIX systems, process enumeration uses a fallback path instead of `/proc`.
- Sandboxed environments can still restrict enumeration or signal delivery even when the native API path is implemented.
