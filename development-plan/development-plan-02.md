# Development Plan 02 — Native Windows live capture and dark interface

Updated: 2026-10-26. The version 0.3.0 evidence below is retained as history;
Section 08 records the completed version 0.4.0 implementation; Section 09 records
the current 0.5.0 source layout and exact Python requirement.

I am changing the capture direction: my application must work without installing
Npcap, Wireshark, or another capture package/driver. Live packet updates remain a
requirement. Capturing first and displaying results only after Stop is not an
acceptable replacement.

**Implemented in version 0.3.0:** the application now uses built-in Pktmon for
live capture. Scapy and the Npcap dependency have been removed. The dark-only
interface and automatic UAC startup flow are implemented. Section 07 records
actual elevated acceptance results and remaining limits.

## Navigation

- [Section 01 — Npcap source review](#section-01--npcap-source-review)
- [Section 02 — Windows alternatives](#section-02--windows-alternatives)
- [Section 03 — Evidence from this machine](#section-03--evidence-from-this-machine)
- [Section 04 — Live capture migration](#section-04--live-capture-migration)
- [Section 05 — Dark-only interface](#section-05--dark-only-interface)
- [Section 06 — Acceptance criteria](#section-06--acceptance-criteria)
- [Section 07 — Implementation and acceptance](#section-07--implementation-and-acceptance)
- [Section 08 — Version 0.4.0 completion](#section-08--version-040-completion)

## Section 01 — Npcap source review

I inspected the public Npcap repository at commit
`ac3db0346a2ff652e174e15756193ea055f042d5`, including its README, license, user-mode
DLL implementation, kernel initialization, packet reads, and loopback capture.
I did not copy Npcap source into this project or download/build/install its driver.

| Source reviewed | What it establishes |
| --- | --- |
| [LICENSE](https://github.com/nmap/npcap/blob/ac3db0346a2ff652e174e15756193ea055f042d5/LICENSE) | Publicly viewable source does not grant unrestricted reuse or redistribution. |
| [Packet32.cpp](https://github.com/nmap/npcap/blob/ac3db0346a2ff652e174e15756193ea055f042d5/packetWin7/Dll/Packet32.cpp) | The user-mode library starts/opens the capture service/device and uses reads and device-control operations. Relevant symbols include `PacketStartService` and `PacketOpenAdapterNPF`. |
| [Packet.c](https://github.com/nmap/npcap/blob/ac3db0346a2ff652e174e15756193ea055f042d5/packetWin7/npf/npf/Packet.c) | The kernel component creates a device, registers read dispatch, and registers an NDIS filter with `NdisFRegisterFilterDriver`. |
| [Read.c](https://github.com/nmap/npcap/blob/ac3db0346a2ff652e174e15756193ea055f042d5/packetWin7/npf/npf/Read.c) | Kernel-side processing copies and reports packets from network buffer lists. |
| [Loopback.c](https://github.com/nmap/npcap/blob/ac3db0346a2ff652e174e15756193ea055f042d5/packetWin7/npf/npf/Loopback.c) | Loopback support uses Windows Filtering Platform callouts registered in the kernel. |

Npcap's own [architecture documentation](https://npcap.com/guide/npcap-internals.html)
also describes the NPF kernel driver, Packet.dll, and Wpcap.dll relationship.
Consequently, bundling a DLL, compiling the same source, or translating its
user-mode wrapper into Python would not eliminate its driver dependency.

My route to no extra installation is to use capture facilities already supplied
by Windows. There is still an operating-system networking/driver layer involved;
I am avoiding an additional driver installation, not bypassing the kernel.

## Section 02 — Windows alternatives

| Approach | Live updates | Extra capture installation | Main constraint |
| --- | --- | --- | --- |
| Built-in Pktmon console, real-time mode | Supported by Microsoft | None on a supported Windows installation | Text output needs validated parsing, pipe-latency checks, administrative access, and careful ownership of the system-wide session. |
| Native Packet Monitor streaming API | Binary packets delivered to callbacks | None when the required APIs already exist | Exports vary by Windows build; the documented streaming API is absent from this machine's DLL. |
| Winsock raw sockets with `SIO_RCVALL` | Yes, at the IP layer | No extra capture driver | Administrative privilege, no Ethernet/ARP frames, and different IPv4/IPv6 receive semantics; not a transparent Npcap replacement. |
| Pktmon ETL capture and PCAPNG conversion after Stop | Results after capture | None when Pktmon is present | Does not satisfy the live-update requirement. |
| A custom NDIS/WFP driver | Technically possible | A new driver would need installation | Conflicts with both simplicity and the no-extra-driver requirement. |

Microsoft documents Pktmon as an
[in-box Windows capture tool](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon).
Its [start command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start)
supports `--log-mode real-time`, which prints events and packets while capturing
and creates no ETL file. This is the first compatibility path to validate for the
current Windows 10 machine.

Microsoft also documents
[independent sessions](https://learn.microsoft.com/en-us/windows/win32/pktmon/packetmonitor/nf-packetmonitor-packetmonitorcreatelivesession)
and [binary real-time streams](https://learn.microsoft.com/en-us/windows/win32/pktmon/packetmonitor/nf-packetmonitor-packetmonitorcreaterealtimestream).
Those offer a cleaner structured interface on systems that expose the required
functions, but an unconditional switch would leave this machine unsupported.

I will not substitute raw sockets and silently claim equivalent IPv6 coverage.
Microsoft documents [SIO_RCVALL](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-rcvall)
for receiving IP traffic, while its
[raw-socket documentation](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2)
explains that IPv6 receive calls omit the IPv6 header. These differences need
explicit implementation and validation rather than assuming `Scapy.sniff()` can
simply run without Npcap.

## Section 03 — Evidence from this machine

The initial checks below were read-only and unprivileged. Subsequent elevated
live acceptance results are recorded in Section 07. No capture software or driver
was installed.

| Check | Observed result |
| --- | --- |
| Windows build | 19045 |
| `pktmon.exe` | Present; version `10.0.19041.3636` |
| `Pktmonapi.dll` | Present; version `10.0.19041.7802` |
| `pktmon start help` | Advertises `real-time`, component selection, and packet truncation controls |
| `pktmon list help` | Advertises JSON component enumeration |
| Documented native streaming/session exports | Ten required `PacketMonitor*` symbols tested; none present |
| Current execution token | Not an administrator |
| `pktmon status` / `pktmon list --json` | Unable to communicate with the Pktmon driver; system reported file not found |

The executable's presence and help output establish an available command
interface, not a successful live capture. The driver/session queries did not
work in this execution context. I cannot infer the exact cause from that error
alone, or claim that elevation will necessarily resolve it.

## Section 04 — Live capture migration

### Compatibility spike

- [x] Review Npcap's source architecture and license without incorporating its code.
- [x] Identify Microsoft's built-in real-time capture interfaces.
- [x] Check local executable help and native streaming exports.
- [x] Preserve live packet updates as a required behavior.
- [x] On an authorized elevated Windows session, verify built-in Pktmon status and
  adapter enumeration without installing Npcap or another capture tool.
- [x] Verify real-time IPv4 and IPv6 output through a private pseudoconsole,
  including whether output is flushed promptly when there is little traffic.
- [x] Record representative outputs and versions for parser fixtures. Do not
  guess a stable format from documentation screenshots.
- [ ] Compare supported Windows versions/locales before declaring compatibility.

### Small backend implementation

- [x] Implement `PktmonBackend` behind the existing controller interface.
- [x] Use the absolute Windows system executable path and argument lists with
  `shell=False`; keep helper windows hidden.
- [x] Resolve the selected adapter to its exact Pktmon component ID through
  structured component data. Capture at the intended NIC to avoid counting every
  traversal through the networking stack as another network packet.
- [x] Use the live stream only. Keep ETL-to-PCAPNG postprocessing outside the
  normal capture flow.
- [x] Read output incrementally off the Tk thread with bounded buffers and
  prompt Stop/time-limit checks, including idle streams and partial lines.
- [x] Parse IPv4/IPv6 addresses, protocol, lengths, timestamps, and available
  transport ports into `PacketRecord`; retain honest unknown fields when output
  lacks a value. Do not manufacture packet details.
- [x] Count damaged headers and undecoded/non-IP snapshots, clearing pending data
  so summaries cannot attach to the wrong packet. Report a consistently unsupported
  initial header format and other parser failures explicitly.
- [x] Preserve the watchlist, controller queues, rotating metadata logs, and dark GUI.
- [x] Replace Scapy's adapter/route enumeration with a built-in Windows interface
  using structured data; do not retain localized `ipconfig` parsing.
- [x] Once no runtime use remains, remove Scapy and regenerate the uv lockfile.

### Ownership and lifecycle

- [x] Before using the legacy console mode, detect an existing Pktmon session.
  Refuse to take it over; do not reset filters, unload the driver, or stop another
  application's capture.
- [x] Own a private pseudoconsole capture process and signal that process to stop. The
  application never invokes global `pktmon stop` or `unload`; a second capture
  is refused when Pktmon is already active, without stopping the first.
- [x] Leave global filters unchanged. Refuse capture when existing filters are
  present rather than silently using or deleting them.
- [x] Ensure errors, manual Stop, timeout, and GUI close release the owned session,
  child process, pipe reader, and buffers, with no orphan capture.
- [x] Request administrator privileges automatically before creating the main
  window. Use normal UAC; cancellation exits. Remove the in-app elevation button
  and prevent repeated elevation prompts if the relaunched process lacks privileges.
- [x] Record the native API decision: retain the tested console backend. This
  machine lacks the required exports. A newer-build binary adapter remains
  conditional future work, requiring a suitable host and evidence of simplification.

I will keep this implementation to one native capture module plus the existing
GUI/controller code where practical. I will not add a backend service, compiler
toolchain, custom driver, large UI package, or copied Npcap code.

## Section 05 — Dark-only interface

- [x] Use one explicit dark Tk/ttk palette independent of the Windows app theme.
- [x] Style the window contents, controls, entries, combobox, dropdown list,
  scrollbars, selection, and packet display.
- [x] Use an amber alert color readable on the dark packet background.
- [x] Keep validation feedback inside the dark window instead of native message
  boxes whose theme can follow Windows' light setting.
- [x] Request the dark native title bar with the documented DWM attribute.
- [x] Add a hidden-window regression checking the palette and dropdown background.
- [x] Pass the expanded offline suite, Ruff lint, and formatting checks (see Section 07).

Windows controls the native frame/title bar. The app requests dark framing when
supported; application contents always use the dark palette. I do not change
the user's Windows theme or registry settings.

## Section 06 — Acceptance criteria

- [ ] Start from a Windows machine with no Npcap, Wireshark, or other added
  capture software/driver and complete the documented uv setup.
- [x] Show live IPv4 and IPv6 packet rows before capture ends.
- [x] Demonstrate watchlist alerts while capture is running.
- [x] Demonstrate timely idle Stop, timeout, restart, and clean window closure.
- [x] Prove that another application's Pktmon session and filters are preserved.
- [x] Verify bounded queue/disk use, parser errors, permission errors, and offline
  operation with no reputation service involved.
- [x] Document exact Windows build support and any native-component limitation.
- [x] Remove the old capture dependency and its installation instructions only
  when the replacement actually passes these checks.

The native backend, dark interface, and UAC flow are implemented. Remaining
cross-version/locale checks are separated from verified results
below. This plan supersedes Section 03's Npcap-based direction in
[Plan 01](development-plan-01.md).


## Section 07 — Implementation and acceptance

I implemented the native backend in `pktmon.py`, kept the controller/models in
`sniffer.py`, and retained the dark Tkinter GUI in `main.py`. A small
`windows_console.py` module binds the standard-library `ctypes` API to Windows
ConPTY. No Npcap source,
custom driver, third-party capture installation, or runtime Python dependency
is included. `uv.lock` now contains only the project and the Ruff development tool.

### Verified locally on 2026-10-25

| Check | Evidence |
| --- | --- |
| Environment | Windows 10 build 19045, Python 3.14.7, Pktmon 10.0.19041.3636 |
| Privileged execution | Normal Windows UAC elevation produced an administrator token; UAC remained enabled |
| Adapter discovery | Seven adapters mapped by interface index/component identity; Wi-Fi selected its Ethernet translation component |
| Initial controller validation | Before the pseudoconsole refinement, first IPv4 packet arrived around 1.3 seconds after launch |
| Initial timed capture | The redirected-output prototype completed a three-second capture with 1,523 IPv4 summaries and no capture errors |
| Controlled alerts | Temporary local IPv4 and IPv6 test watchlists produced alerts while capture remained active |
| Manual Stop | Initial prototype Stop completed about 0.5 seconds after request; final pseudoconsole Stop/close checks are below |
| Existing session | Starting a second capture was refused while the first remained running |
| Idle Stop | Final pseudoconsole run: disconnected Ethernet stopped in 0.113 seconds with zero packets |
| Live IPv6 | One link-local UDP record and controlled watchlist alert arrived before capture ended, using an existing Hyper-V adapter |
| Real Tkinter flow | Final run: four live packet rows/alerts observed before window close; dark palette confirmed |
| Window close | Final pseudoconsole run: real GUI close stopped the worker and capture in 0.177 seconds |
| Final state | Pktmon reported not running; filters still reported None; no remaining Pktmon process |
| Automated verification | All 53 tests passed, including terminal redraw/partial-protocol regressions and a real non-capture Windows pseudoconsole test; Ruff and locked dependency checks passed |

Counts and timing describe those particular short test runs, not guaranteed
throughput/latency. Test captures saved no payload files. Temporary diagnostics
and test watchlists are kept under ignored `.uv-cache/validation/`; the repository
evidence here includes aggregate results rather than observed endpoint addresses.
The live alert test used a controlled local address and does not establish the
reputation of the historical watchlist.

A busy-stream acceptance failure exposed a shutdown backpressure bug. I fixed
it by continuing to drain/discard stdout while the owned Pktmon process exits,
and added a regression that would block if the pipe stopped draining. An idle
adapter exposed a separate startup issue: waiting for `Processing...` could wait
for traffic. I now recognize the successful `Collected Data:` startup response,
and an idle-startup regression verifies Stop does not depend on a first packet.

Low-volume IPv6 also exposed redirected-output and terminal-framing limitations.
I switched the capture client to a private Windows pseudoconsole, then verified
its output framing against actual terminal bytes. The incremental decoder handles
split UTF-8/control sequences, carriage redraws, bounded escape/line buffers, and
repeated headers. A regression prevents a partially painted protocol label from
being published as a false `Unknown`. Hyper-V companion component IDs and its
separate drop diagnostics are handled without changing adapter/network settings.
I signal Ctrl+C through only the owned pseudoconsole input and keep output draining
while the process and terminal close. No global Pktmon stop/unload is used.

The console interface can batch updates and omit intermediate summaries under
load. These tests establish a working live diagnostic GUI, not lossless capture
or guaranteed throughput. Other Windows/adapter combinations remain separate work.

### Remaining acceptance limits

- [x] Observe live IPv6 and a controlled alert before capture ends. The final test
  sent one link-local UDP datagram through an existing virtual adapter. IPv6
  UDP/ICMPv6, scope, and mixed-address parsing are also covered offline. No adapter
  or network settings were changed.
- [ ] Validate other Windows builds, adapters/VPNs, and locales. Supported Python
  branches are now covered locally in Section 08.
  The current status/parser intentionally supports the English format verified here.
- [ ] Repeat a clean-checkout setup on another Windows machine. This machine had
  no Npcap provider during validation; I did not uninstall unrelated existing tools.
- [ ] Validate actual adapter-disconnection recovery during a live capture.
- [x] Add dynamic reputation data as planned in Plan 01 Section 04; see Section 08.

### Startup elevation update (2026-10-26)

The application now checks its administrator token before constructing Tk or
loading adapters. A normal launch requests UAC automatically using the current
Python interpreter and an absolute, quoted script path. An already elevated
launch opens the GUI directly. Cancellation or launch failure exits without
opening the main window, and a retry marker prevents repeated prompts if the
child process does not receive administrator privileges. The in-app elevation
button has been removed; the interface remains dark only.

All 61 automated tests passed after this change. Startup tests mock elevation,
including cancellation, Windows launch failures, argument quoting, and the retry
guard; they do not display UAC prompts. Ruff and the locked dependency check
passed. The live capture evidence above predates this startup change.

### Interface and terminal decoder repair (2026-10-26)

- [x] Request system DPI awareness before constructing Tk. Use system fonts,
  scaled spacing, a compact capture panel, counter cards, a capture-state badge,
  an empty state, and colored UTC-time/protocol/alert text. No third-party GUI
  framework, runtime package, or image asset was introduced.
- [x] Preserve manual scroll position while packets arrive; follow the stream
  again when the user returns to the bottom.
- [x] Elevate through the current environment's `pythonw.exe`, retaining normal
  UAC. An already elevated console Python process detaches itself before opening
  Tk. Verify a real windowed launch has no attached console.
- [x] Reproduce the Wi-Fi failure. ConPTY encoded spaces as cursor-right escape
  commands, which the old decoder discarded. Captured examples became
  `TypeEthernet` and `Filter 0,OriginalSize`, triggering the strict header error.
- [x] Decode horizontal cursor movement, absolute columns, erases, and overwrites
  with bounded buffers. Deduplicate snapshots by stable identity, including
  chunk boundaries and redraws with changed spacing.
- [x] Skip/count an isolated damaged header and reset pending state. Refuse an
  initial stream whose first 20 headers all fail; do not manufacture packet data.
- [x] Complete a 25-second native Wi-Fi capture: 305 packets, no header failure,
  and Pktmon inactive afterward.
- [x] Complete an elevated windowed GUI capture: 126 packets rendered, matching
  packet counter, no capture error, no attached console, visible Start control,
  and clean Pktmon shutdown. Inspect the layout at 200% desktop scaling.
- [x] Pass all 67 offline/native-console regressions, Ruff, and the lock check.

The DPI setting is system-aware for Tk 8.6. Automatic layout/font adaptation
between monitors with different scaling remains future work; restart on the
target monitor. Capture remains a parsed console diagnostic stream with the
acceptance limits listed above.

## Section 08 — Version 0.4.0 completion

### Completed implementation

- [x] Remove the duplicate in-window application heading; keep the native title.
- [x] Set the Clam native thumb's `gripsize` to zero. Preserve stable gutters, ignore
  input while an axis fits, and activate/deactivate it after overflow, clear, or resize.
- [x] Put CAPTURE ENDED/STOPPED in the live-traffic badge. Keep errors and loading
  details in that panel instead of an unrelated bottom-left footer.
- [x] Implement the complete attributed feed/cache/local-match/alert path in
  `reputation.py`, with standard-library HTTPS and no captured-address uploads.
- [x] Validate both DROP families, retain original metadata/copyright, support
  multiple SBL records for the same CIDR, and preserve prior data on failed updates.
- [x] Enforce time/size/row/cache limits, cross-process locking, daily updates,
  a persistent hourly minimum cooldown, and HTTP 429 seconds/date retry delays.
- [x] Show per-family fresh/stale state, source category, evidence, fetched time,
  expiry, disabled/offline/failure state, and bounded per-session notice suppression.
- [x] Version 0.4.0 kept the old list disabled by default; version 0.5.0 removes it
  completely, as recorded in Section 09 below.
- [x] Replace slow NetTCPIP inventory with built-in .NET enumeration through a
  hidden PowerShell helper. Preserve exact interface mapping and IPv4 masks.
- [x] Add pinned/read-only Windows CI for Python 3.12/3.13/3.14 and Windows Server
  2022/2025; keep live capture and real provider downloads outside normal CI/tests.
- [x] Rewrite the README and Plan 01 around the final behavior and actual limits.
- [x] Keep five runtime modules, zero third-party runtime packages, and no image assets.

### Acceptance obtained locally

| Check | Result |
| --- | --- |
| Offline/native-console suite | All 98 tests passed on Python 3.12.15, 3.13.17, and 3.14.9; the original 3.14.7 environment also passes |
| Dependency/tooling review | uv 0.13.5 re-resolved the lock; Ruff 0.17.2 remains newest resolved compatible; no runtime dependency added |
| Fresh environment | New source snapshot, new `.venv`, locked sync using downloaded artifacts, tests/lint/format/lock checks; no previous cache/log/settings copied |
| Real provider response | One download per fixed feed, saved responses reused for validation; 1,778 unique CIDRs with evidence and original copyright retained |
| Real source freshness | IPv4 snapshot was stale and IPv6 fresh; downloading did not falsely relabel old data as fresh |
| Privacy | No captured address or test-listed destination was uploaded or contacted |
| Background discovery | Previous query 6.205 s; .NET query 0.656 s. All seven shared interface address sets match; an additional loopback entry is harmlessly excluded by native component selection |
| Complete GUI discovery | Adapters ready in 1.089 s during the live acceptance run |
| Longer live GUI capture | 60-second capture, 2,147 IP summaries, zero display drops, three undecoded snapshots, no capture error |
| Packet latency | First live record 1.393 s after requesting capture in this run |
| Completion UI | CAPTURE ENDED badge inside traffic; duplicate footer hidden; vertical scrollbar active and horizontal inactive for fitting rows |
| Windowed startup | Administrator token confirmed, attached console absent, UAC mechanism retained |
| Capture cleanup | Pktmon inactive afterward, global filters still None; only the owned process was interrupted |
| Protected original log | SHA-256 still `1c4d1d507042d8fcb10e38e5020f0d55b6ed0dca00465cc346203249813afa10` |

The fresh source snapshot validates the current uncommitted work. It is not
described as a clean checkout of a published ref. Its package cache started empty;
the locked development tool was downloaded into the new environment.

### External acceptance still open

- [ ] Run live capture on other Windows builds/locales, VPNs, and adapters.
- [ ] Repeat setup/live acceptance on another machine with no unrelated capture tools.
- [ ] Exercise physical adapter disconnection and recovery during a real capture.
  I did not disconnect or reconfigure the user's active network to simulate this.
- [x] Run the prepared CI matrix after pushing the source; both Windows runners
  pass. Section 10 records the actual hosted run and installer preview evidence.
- [ ] Validate automatic cross-monitor DPI adaptation before implementing/claiming it.

These are environment/hardware/hosted-validation limits, not unchecked claims
that the implemented reputation or UI work is incomplete. Future native binary
APIs are a separately justified alternative, not another required backend.


## Section 09 — Version 0.5.0: source layout and exact Python requirement

This section supersedes earlier Python support, root-module launch commands, and
historical-list options. Earlier test/capture results above remain dated evidence
of earlier versions; they do not define the current supported Python versions.

- [x] Remove `watchlist.txt`, its loader/matcher, controller configuration, record
  field, GUI checkbox, and obsolete tests. Attributed DROP feed alerts remain.
- [x] Move application code into `src/network_packet_sniffer` with relative
  imports, package entry points, and a small writable-data location helper.
- [x] Install a windowed `network-packet-sniffer` GUI launcher with uv. Relaunch
  elevation through the same environment's `pythonw -m network_packet_sniffer`.
- [x] Preserve repository `cache/` and `logs/` for editable installs. Installed
  wheels use Local AppData, outside source/site-packages and independent of CWD.
- [x] Pin `.python-version`, package `requires-python`, startup validation, and
  both Windows CI runners to **3.14.7 only**, including an exact-version CI check.
- [x] Recheck current stable releases: Ruff 0.17.2, uv/uv_build 0.13.5,
  checkout v7.0.1, and setup-uv v10.3.2. Existing action pins remain current.
- [x] Pin Ruff and uv_build exactly, regenerate the lock, target Python 3.14 in
  Ruff, and build the source package and wheel. No runtime dependency was added.

### Validation obtained locally

| Check | Result |
| --- | --- |
| Exact interpreter | CPython 3.14.7 final; startup regression rejects other patches/minors and prereleases before elevation or GUI creation |
| Current test suite | All 99 tests pass, including attributed GUI alerts with no static address file |
| Fresh setup | New source snapshot, empty package cache, new 3.14.7 environment, locked sync, all 99 tests, lint, format, and lock checks pass |
| Artifacts | Source distribution and wheel build successfully; metadata requires `==3.14.7`, with zero runtime dependencies |
| Artifact contents | No logs, caches, environment files, or old address list included |
| Installed wheel | Imports work outside the repository; GUI entry point resolves; data uses Local AppData; generated EXE has Windows GUI subsystem 2 |
| CI interpreter availability | uv 0.13.5 lists an exact Windows x64 CPython 3.14.7 download; subsequent hosted success is recorded in Section 10 |
| Live GUI after refactor | Three-second capture: 80 processed summaries, zero display drops, one undecoded snapshot, no capture error |
| Startup and completion | Administrator token present, no console attached, CAPTURE ENDED badge, redundant status hidden |
| Capture cleanup | Pktmon inactive afterward; global filters remain None |
| Protected original log | SHA-256 remains `1c4d1d507042d8fcb10e38e5020f0d55b6ed0dca00465cc346203249813afa10` |

Only Python 3.14.7 was used for this update's execution and validation. The fresh
environment reused the verified exact interpreter and downloaded the pinned
development/build artifacts. The wheel acceptance uses a second isolated 3.14.7
environment. Results validate the local uncommitted source, not a published ref.
External hardware/build/locale acceptance remains as listed in Section 08.
Subsequent hosted-CI evidence is recorded in Section 10.

## Section 10 — Implementation audit before Git delivery

On 2026-10-26, the application implementation in Plans 01 and 02 was audited
against the current source. No application implementation checkbox remains open.
The current suite passes all 113 tests on Python 3.14.7; lint, formatting,
workflow syntax, and protected-log checks also pass.

The unchecked external acceptance items remain explicit: other Windows builds,
locales/adapters, a separate clean machine, real physical disconnection, and
mixed-monitor DPI behavior. They are not represented as completed by committing
the implemented code.

### First hosted acceptance after delivery

Source commit: `623c95bfed522628315395cf673aa0fae97e9555` on `main`.

| Check | Hosted result |
| --- | --- |
| Windows CI matrix | [Run 40290432647](https://github.com/asteroidcrib729/network-packet-sniffer/actions/runs/40290432647): Windows Server 2022 and 2025 both pass on Python 3.14.7 |
| Checks per runner | All 113 tests, exact interpreter assertion, lint, formatting, lock validation, and wheel/source build pass |
| Installer preview | [Run 40290458457](https://github.com/asteroidcrib729/network-packet-sniffer/actions/runs/40290458457): build and EXE install/GUI/close/uninstall smoke pass; draft job intentionally skipped |
| Downloaded artifact | `installers-40290458457-1`, artifact ID `12635757362`; actual EXE, MSIX, and source ZIP downloaded and all release-manifest/SHA256SUMS checks pass |
| Source provenance | Artifact source commit matches `623c95b`; `source_dirty=false`, Python 3.14.7, PyInstaller 6.22.3, Inno Setup 7.1.0 |

This closes the hosted CI acceptance item. The installer MSIX remains preview
signed: structure/CMS checks passed, but certificate trust and installation were
not performed. No Git tag, draft release, or published release was created by
the branch preview run. Production signing and other-machine/live-network checks
retain the separate limits in Plan 03.
