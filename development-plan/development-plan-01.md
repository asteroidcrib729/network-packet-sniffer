# Development Plan 01 — GUI repair and modernization

Updated: 2026-10-26. I built the original application in Q4 2023. Version 0.5.0
completes the local implementation below. External acceptance limits remain
explicit in Plan 02; checked boxes do not claim results on unavailable systems.

## Navigation

- [Section 01 — Scope](#section-01--scope)
- [Section 02 — Repairs](#section-02--repairs)
- [Section 03 — Native capture acceptance](#section-03--native-capture-acceptance)
- [Section 04 — Dynamic IP reputation](#section-04--dynamic-ip-reputation)
- [Section 05 — Quality checks](#section-05--quality-checks)
- [Section 06 — Completion criteria](#section-06--completion-criteria)

## Section 01 — Scope

- [x] Keep one dark Tkinter GUI with OOP and no image assets.
- [x] Remove the duplicate console app; preserve original source in Git history.
- [x] Keep application code in `src/network_packet_sniffer`, with separate tests,
  minimal package entry points/data paths, and zero runtime package dependencies.
- [x] Introduce uv, `pyproject.toml`, `.python-version`, and `uv.lock`.
- [x] Replace Scapy/Npcap with built-in Pktmon.
- [x] Add dynamic reputation after native capture acceptance.

Installer implementation is tracked separately in Plan 03. Payload inspection,
injection, firewall changes, servers, databases, accounts, and other operating
systems remain outside this project's scope.

## Section 02 — Repairs

| Original problem | Current repair and evidence |
| --- | --- |
| Workers touching Tk | Queues and `after()`; thread-identity GUI tests |
| Overlapping captures | One worker, locked settings, overlap rejection |
| Uncoordinated shutdown | Stop event, owned ConPTY interrupt, draining, worker joins |
| Incomplete adapter choices | Structured Windows/Pktmon inventory, including index zero |
| Missing route fields | Explicit unavailable text; address/gateway/mask fixtures |
| Slow discovery | Hidden built-in .NET query: measured 6.205 → 0.656 seconds, matching shared-interface address sets |
| Invalid duration/menu input | GUI-only, whole-number 1–3,600 second validation |
| Hidden capture/log errors | Preserved inline traffic-panel errors |
| Work repeated per packet | Indexed reputation snapshots and per-session alert deduplication |
| Unverified malicious-IP claims | Old list removed; attributed, refreshable source evidence only |
| Unbounded history/logs | 1,000-record queue, about 2,000 lines, four approximately 1 MB logs |
| Swallowed log failures | Open/write/close regressions and visible error events |
| Traffic files tracked | Original log retained under ignored `logs/`; cache and ETL/PCAP ignored |
| Fragile terminal headers | Bounded cursor/erase/redraw decoding and damaged-header recovery |
| Duplicate heading / misplaced completion | Native title retained; completion badge inside live traffic |
| Scrollbar grip / unnecessary input | Plain thumbs; independent overflow-only activation |
| Stretched text / extra console | System DPI awareness and windowed Python UAC startup |

The original log remains unchanged locally, SHA-256:
`1c4d1d507042d8fcb10e38e5020f0d55b6ed0dca00465cc346203249813afa10`.

## Section 03 — Native capture acceptance

The earlier Npcap-install proposal is superseded by [Plan 02](development-plan-02.md).
Installing Npcap is not an outstanding task.

- [x] Run without calling Wireshark/TShark/Dumpcap or loading a Npcap backend.
- [x] Verify native adapter selection and selected address/route fields.
- [x] Observe live IPv4/IPv6 and controlled alerts before capture ends.
- [x] Verify timeout, idle Stop, restart, existing-session refusal, and GUI closure.
- [x] Verify optional logging, rotation, write failures, and worker/handle cleanup.
- [x] Complete a 60-second GUI capture: 2,147 packets, zero display drops, three
  undecoded snapshots, central completion badge, vertical scrolling active,
  horizontal scrolling inactive, and Pktmon stopped cleanly.
- [x] Verify a fresh source-copy environment without copying caches, logs, or `.venv`.

Other machines, real adapter disconnection, additional builds/VPNs/locales, and
newer native APIs need external checks in Plan 02. Local fixtures are not those tests.

## Section 04 — Dynamic IP reputation

### Provider and results

- [x] Select The Spamhaus Project's IPv4/IPv6 DROP feeds after reviewing
  [purpose/update guidance](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
  and [terms](https://www.spamhaus.org/blocklists/drop-fair-use-policy/).
- [x] Match CIDRs locally and retain multiple evidence IDs for one range.
- [x] Record address, CIDR, source/category, evidence, fetch time, expiry, and
  `listed`, `not listed`, `stale`, `unknown`, `lookup failed`, and `excluded` states.
- [x] Never equate unlisted with safe or a range listing with a packet attack.
- [x] Remove the old 2023 address file, matching class, record field, and GUI control.

### Fetching and cache

- [x] Standard-library provider/service classes, one bounded refresh worker.
- [x] Two fixed HTTPS bulk endpoints only; no captured-address uploads.
- [x] Certificate verification, timeouts/deadline, no redirects, response/row
  limits, and schema/address/evidence validation.
- [x] Automatic daily refresh while enabled, at least hourly attempt cooldown,
  persistent HTTP 429 delays, and cross-process update locking.
- [x] Bounded rows/cache/alert state and fully validated atomic replacement.
- [x] Old snapshots retained after HTTP, schema, timeout, or disk failure.
- [x] Original attribution, dates, and copyright preserved in cache and GUI.
- [x] Per-family freshness based on both source generation and fetch time;
  visible expiry/failure state and explicit stale evidence.
- [x] Capture continues while offline, updating, rate limited, or disabled.
- [x] No API keys are needed; `.env` configuration is not applicable.
- [x] Individual-address APIs are intentionally absent. Local/private/reserved/
  multicast addresses are excluded, and no address-upload request path exists.

### Alerts and acceptance

- [x] Feed enablement, explicit Update feeds, attributed status controls.
- [x] Category, CIDR, evidence, fetch time, expiry, and freshness in notices.
- [x] Deduplicate per address/range/session, retaining at most 4,096 keys;
  further notices are counted as suppressed while packets continue.
- [x] Completed snapshots apply to future packets without blocking capture or Tk.
- [x] Offline tests cover both families/CIDR boundaries, exclusions, expiry,
  malformed data, multiple evidence records, failures/rate limits, atomic/disk
  failures, concurrency, cancellation, and GUI responsiveness.
- [x] Download each real feed once, then reuse saved responses for validation:
  1,778 unique ranges, original attribution retained, zero address uploads.
  IPv4 data was stale and IPv6 fresh; the application reports that accurately.

## Section 05 — Quality checks

- [x] Pass all 113 tests on Python **3.14.7 exactly**; other versions are no
  longer supported or selected for this project.
- [x] Use read-only, pinned Windows Server 2022/2025 CI for **3.14.7 only**,
  exact-version assertion, locked sync, tests, lint, formatting, lock and build
  checks. Hosted Windows checks and installer preview now pass; see Plan 02
  Section 10 for the run evidence.
- [x] Observe a longer live capture and its processing/display counters. Synthetic
  overflow tests separately prove optional logs retain processed records.
- [x] Review IPv6 extensions: keep outer endpoints and `Unknown` where transport
  is ambiguous; add an explicit regression rather than guessing.
- [x] Profile and improve adapter discovery through built-in .NET inventory.
- [x] Verify current stable releases: uv/uv_build 0.13.5 and Ruff 0.17.2. Pin Ruff
  and the build backend exactly; keep `==3.14.7` in package metadata and startup.
- [x] Keep small config/CI, no image assets, no static address list, and no
  additional service platform. Package build support introduces no runtime package.
- [x] Verify a new source-copy environment and isolated wheel installation on
  3.14.7, including the windowed entry point and writable data paths.
- [x] Repeat live GUI capture after the source move: 80 packets, no capture error
  or display drops, one undecoded snapshot, no console, and clean Pktmon shutdown.

## Section 06 — Completion criteria

Repair, native-capture, GUI, and reputation implementation is locally verified as
recorded here. Earlier local fresh-environment checks used a source snapshot;
hosted checks now validate committed source as recorded in Plan 02 Section 10.

Hosted CI has passed. Unavailable hardware/Windows tests remain unchecked in
Plan 02. Console-stream limits,
source coverage/freshness, and cross-monitor DPI limits remain in the [README](../README.md).
