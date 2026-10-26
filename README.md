# Network Packet Sniffer

I built the original version in Q4 2023 as an academic project. Version **0.5.0**
keeps it a small, object-oriented Windows desktop application built with Tkinter.
It shows live IPv4/IPv6 summaries through built-in Pktmon and matches addresses
against attributed reputation feeds locally.

I do not require Wireshark, TShark, Dumpcap, Npcap, Scapy, an additional capture
driver, an API key, a server, or a database. Python's standard library supplies
the runtime. Astral uv manages the exact Python version, package installation,
and the locked development tool, Ruff.

## Navigation

- [Requirements](#requirements)
- [Install and run](#install-and-run)
- [Windows installers](#windows-installers)
- [Using the interface](#using-the-interface)
- [Reputation and alerts](#reputation-and-alerts)
- [Capture behavior and limits](#capture-behavior-and-limits)
- [Files and privacy](#files-and-privacy)
- [Code organization](#code-organization)
- [Development and verification](#development-and-verification)
- [Troubleshooting](#troubleshooting)
- [License and attribution](#license-and-attribution)

## Requirements

- Windows with built-in Pktmon real-time capture and ConPTY support. Live capture
  has been verified on **Windows 10 build 19045 with English Pktmon output**.
  Other Windows builds, VPNs, and localized output need separate acceptance.
- **CPython 3.14.7 exactly**, with Tcl/Tk. Other patch, minor, and major versions
  are rejected. The Python pin, package metadata, startup check, and CI agree.
- A current [Astral uv installation](https://docs.astral.sh/uv/getting-started/installation/).
- An administrator token. The application requests normal UAC elevation before
  constructing its window. UAC can remain enabled.
- Internet access for setup and feed updates. Capture, cached range matching,
  and cached reputation alerts work offline.

Pktmon is an [in-box Windows capture tool](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon).
I use its [real-time mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start)
instead of installing or distributing another capture driver.

## Install and run

Open PowerShell in the repository:

```powershell
uv --version
uv python install 3.14.7
uv sync --locked --python 3.14.7
uv run --locked network-packet-sniffer
```

Approve the Windows UAC prompt. An already elevated launch opens directly;
cancelling elevation exits before the main window opens. The elevated child uses
the same environment's **pythonw.exe**, so it does not spawn a console window.
A PowerShell window you opened yourself remains your shell. After syncing, I can
also double-click `.venv\Scripts\network-packet-sniffer.exe` to open the GUI
without opening a terminal. `uv run --locked pythonw -m network_packet_sniffer`
is an equivalent module launch; the old root-level `main.py` command is retired.

For the runtime alone, omit the development tool:

```powershell
uv sync --locked --no-dev
uv run --locked --no-dev network-packet-sniffer
```

No environment activation or `.env` file is needed. The app does not change UAC,
firewall rules, execution policy, adapters, or installed drivers. To check Tcl/Tk,
run `uv run --locked python -m tkinter` and close its test window.

## Windows installers

I also provide an EXE setup installer and sideload MSIX that bundle **Python
3.14.7**, Tcl/Tk, the application, a source archive, and license notices. Installed
users do not need Python or uv. Both retain live Pktmon capture, automatic
administrator startup, and the dark Tkinter interface.

Local outputs are in the ignored **`packaged-releases/0.5.0/`** directory.
The EXE is unsigned in preview mode; the MSIX has a self-signed development
certificate and needs explicit trust before installation. Production certificate
signing is supported. The scripts do not change certificate trust or UAC settings.

The [packaging guide](packaging/README.md) covers building, installation, preview
trust, production secrets, checksums, smoke tests, and the draft/publish workflows.
These are sideload packages; Microsoft Store certification is not claimed.

## Using the interface

1. Let background adapter discovery finish, then choose an adapter. Adapters
   with an IPv4 gateway appear first. Available addresses, gateway, and masks
   are shown; missing fields say **Not available**.
2. Enter a whole-number duration between **1 and 3,600 seconds**.
3. Optionally enable **Save rotating log**, which is off by default.
   **Reputation feeds** are enabled by default and can be disabled independently.
4. Select **Start capture**. Rows, counters, and attributed alerts update live.
5. Select **Stop** to finish early. Closing stops the owned capture and waits
   for capture, discovery, and reputation workers to finish.
6. **Refresh** discovers adapters again after capture. **Clear view** removes
   displayed rows without deleting logs or resetting session totals.

The app has one dark theme, system fonts, scaled spacing, and no image assets.
Scrollbars have plain thumbs without decorative grips. They reserve stable gutters
and accept input only when their axis overflows; clearing/resizing updates them.
Scrolling up preserves your position. Returning to the bottom resumes following.

Capture state appears beside **Live traffic · UTC**. Completed captures show
**CAPTURE ENDED** there. Loading details and errors stay inside the traffic panel.
The native title identifies the application without a duplicate page heading.

| Counter | Meaning |
| --- | --- |
| Packets observed | Processed IP summaries, not a wire-level packet total |
| Alert rows | Rows with a new attributed reputation notice |
| Display skipped | Processed records omitted because the display queue was full |
| Non-IP / undecoded | Unsupported, damaged, or undecoded selected-edge snapshots |

The view displays UTC time of day; saved metadata keeps the full ISO timestamp
and date. Timestamp, protocol, and alert colors distinguish fields.

I request [system DPI awareness](https://learn.microsoft.com/en-us/windows/win32/hidpi/setting-the-default-dpi-awareness-for-a-process)
before creating Tk to avoid bitmap-stretched text. Restart on the target monitor
after moving between displays with different scaling. Automatic per-monitor
font/layout adaptation has not been validated.

## Reputation and alerts

I use the IPv4/IPv6 **DROP** feeds from **The Spamhaus Project**:

- [IPv4 feed](https://www.spamhaus.org/drop/drop_v4.json)
- [IPv6 feed](https://www.spamhaus.org/drop/drop_v6.json)
- [Purpose and update guidance](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- [Provider terms](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)

The source describes particular listed networks; it is not a complete catalogue
of dangerous IPs. Each notice identifies source/category, CIDR, SBL evidence,
fetch time, expiry, and freshness. A listing does not establish that a particular
captured packet is an attack.

Only two fixed HTTPS feeds are requested. **Captured addresses are never uploaded**,
and the app never connects to a listed address to test it. Matching uses local
IPv4/IPv6 prefix indexes. Private, reserved, local, and multicast addresses are
excluded from public reputation matching.

**Reputation feeds** enables/disables matching and updates. **Update feeds** requests
an update when available. Work runs off Tk/capture threads. I check automatically
on startup and daily while enabled, enforce at least one hour between attempts,
honor HTTP 429 retry delays, and preserve cooldown across restarts/windows.
There is no per-address API or API-key configuration.
Control choices apply to this launch; feed data and the cooldown persist on disk.

Both feeds must validate before an atomic cache replacement. Requests have
timeouts, redirects are rejected, each response is limited to 2 MB, and at most
20,000 source rows are accepted. The combined cache is limited to 4.1 MB. Original
provider metadata, dates, and copyright remain in the ignored cache; source credit
also appears in the GUI. A process-held lock prevents concurrent cache updates.

| Lookup state | Meaning |
| --- | --- |
| Listed | A matching range exists in a fresh source snapshot |
| Not listed | No range matched this fresh snapshot; this does **not** mean safe |
| Stale | The relevant snapshot expired; retained matching evidence says **STALE** |
| Unknown | No snapshot is available, or matching is disabled |
| Lookup failed | Updating failed without a usable snapshot |
| Excluded | The address is outside public-address matching scope |

Freshness is separate for IPv4/IPv6. I use a 26-hour lifetime from the earlier
of fetch time and provider generation time: downloading old data cannot make it
fresh. Failed updates keep validated cached evidence and display the error.
Expired matching evidence remains explicitly stale.

Notices are deduplicated per address/range/session with 4,096 retained keys.
Further notices are counted as suppressed in reputation status while packets
continue. New snapshots apply to subsequent packets; older rows are not
retrospectively reclassified.

I removed the old academic IP list, its checkbox, and its matching logic.
All reputation notices now come from the attributed, refreshable feeds above.

## Capture behavior and limits

A capture worker owns one Pktmon client in a private Windows pseudoconsole.
Bounded framing handles UTF-8 chunks, cursor-positioned spaces, erases, redraws,
and partial lines. Stable header identities prevent duplicate redraw records.
I extract the first supported IP summary from each selected-edge snapshot.

For Wi-Fi I select the native translator's decrypted Ethernet side. Raw Wi-Fi,
duplicate edges, and separate drop diagnostics are ignored. Hyper-V can report
selected traffic under companion component IDs; Pktmon's selection is authoritative.
Available ports are retained. Ambiguous IPv6 extension/protocol summaries remain
`Unknown` instead of guessing a protocol from ports.

A damaged header resets pending state and increments the undecoded count without
terminating a working stream. If the first 20 observed headers are all unsupported,
capture reports a format error. Unsupported session status or pre-existing global
filters causes an explicit refusal.

I do not take over another capture or reset its filters. Stop sends Ctrl+C only
through the owned console and drains output during shutdown. The app never uses
global `pktmon stop` or `unload` commands.

Pktmon internally snapshots 128 bytes to obtain summaries. GUI/logs omit payload
text. Original sizes can include link-layer overhead. Local capture clock values
are converted to UTC with millisecond precision.

Duration starts when Pktmon confirms startup. Setup/shutdown add time; final
buffered output can be discarded during cleanup. ETW losses, console batching,
omitted terminal summaries, and display queue overflow are separate limitations.
This is a diagnostic/learning tool, not a lossless archive, TLS decryptor, firewall,
or intrusion-prevention system.

## Files and privacy

| Local path | Purpose |
| --- | --- |
| `logs/traffic.log` and `.1`–`.3` | Optional metadata log and three rotating backups, approximately 1 MB each |
| `logs/legacy-traffic.txt` | Preserved academic log; not read by the app |
| `cache/reputation.json` | Validated source data, attribution, and fetch time |
| `cache/refresh.json` / `reputation.lock` | Persistent cooldown and process-held update lock |
| `.venv/`, `.uv-cache/`, `.ruff_cache/` | Local environment/development caches |

These paths are relative to the repository when running its editable installation.
A wheel installed outside the repository uses `%LOCALAPPDATA%\NetworkPacketSniffer`
for `cache/` and `logs/` instead; data is never written into the installed package.
The preserved academic log stays in its original ignored repository location.

Logs may contain IPs, ports, protocols, sizes, timestamps, and source evidence.
The view holds about 2,000 lines; its queue holds 1,000 records. Logging receives
processed records before display overflow handling. Feed caches contain provider
ranges, not captured-destination history.

Logs, caches, `.env` files, and ETL/PCAP captures are ignored by Git. I preserved
the original log unchanged locally; removing a tracked file does not erase Git
history. Inspect traffic only where you have permission.

## Code organization

```text
network-packet-sniffer/
├── src/
│   └── network_packet_sniffer/
│       ├── __init__.py
│       ├── __main__.py       # Windowed module entry point
│       ├── main.py           # Dark Tkinter GUI and automatic UAC startup
│       ├── sniffer.py        # Controller, records, deduplicated alerts, logging
│       ├── pktmon.py         # Windows inventory, parser, capture lifecycle
│       ├── windows_console.py # Standard-library ConPTY binding
│       ├── reputation.py     # HTTPS feeds, freshness, local matching, cache
│       └── paths.py          # Writable data location
├── tests/                    # Offline and native-console regressions
├── packaging/                # EXE/MSIX recipes, release scripts, licensing
├── development-plan/         # Implementation evidence and external limits
├── .github/workflows/ci.yml   # Windows checks on Python 3.14.7 only
├── .python-version           # Exact interpreter pin
├── pyproject.toml            # Metadata, GUI entry point, dependencies
├── uv.lock                   # Reproducible development resolution
├── LICENSE                   # Apache-2.0
├── NOTICE                    # Original author attribution
└── README.md
```

All application Python code lives in `src/network_packet_sniffer`; tests stay in
`tests/`. `uv sync` installs the package in editable mode, so edits apply directly.
I use uv's native `uv_build` backend to create the Windows GUI launcher and
ordinary wheels/source distributions. It is a build-time dependency only.
The application still has zero third-party runtime packages and no tracked image
assets. Installer artwork is generated while building; build helpers live in
`src/release_tools` and are excluded from the installed Python application wheel.

## Development and verification

```powershell
uv sync --locked --python 3.14.7
uv run --locked python -m unittest discover -s tests -v
uv run --locked ruff check .
uv run --locked ruff format --check .
uv lock --check
uv build
```

The suite does not request elevation, contact a reputation server, or start live
capture. It uses synthetic text, fake providers/processes, and real hidden Tkinter
windows. A native-console smoke test runs local `cmd.exe echo` in an owned
pseudoconsole. GUI tests report skips if no display is available.

All **113 tests pass on Python 3.14.7**. Package-layout validation includes a fresh
source-copy setup, wheel build/install, and windowed startup. A final three-second
GUI capture processed 80 packets with no capture error or display drops, one
undecoded snapshot, no attached console, and clean Pktmon shutdown.
Earlier native acceptance recorded a 60-second GUI capture with 2,147 processed
packets, zero display drops, and clean shutdown. The feed check correctly showed
stale IPv4 and fresh IPv6 data. Detailed current results and earlier acceptance
are recorded in [Plan 02](development-plan/development-plan-02.md).

CI uses read-only permissions and pinned actions on Windows Server 2022/2025,
with **3.14.7 as its sole Python version**. It checks the interpreter, locked sync,
tests, lint, formatting, lockfile, and package build. Both runners passed
[hosted CI](https://github.com/asteroidcrib729/network-packet-sniffer/actions/runs/40290432647).
The [hosted installer preview](https://github.com/asteroidcrib729/network-packet-sniffer/actions/runs/40290458457)
also passed build and EXE install/launch/uninstall checks; downloaded installer
and source checksums were verified. See Plan 02 Section 10 for source provenance.
Those checks do not establish live capture compatibility on other systems.

I checked stable releases on 2026-10-26: [Ruff 0.17.2](https://github.com/astral-sh/ruff/releases/tag/0.17.2),
[uv 0.13.5](https://github.com/astral-sh/uv/releases/tag/0.13.5), and
[uv_build 0.13.5](https://pypi.org/project/uv-build/0.13.5/). Ruff and the build
backend are pinned exactly. uv 0.13.5 is pinned in CI; my existing global uv
installation is not overwritten by project setup.
For an intentional update, edit the relevant exact pin, run `uv lock --upgrade`
and `uv sync --locked`, repeat checks, and review the lockfile. Python remains
3.14.7 unless that explicit project requirement is changed.

[Plan 01](development-plan/development-plan-01.md) records repairs and reputation;
[Plan 02](development-plan/development-plan-02.md) records native evidence and tests
that still require another machine or network setup.
[Plan 03](development-plan/development-plan-03.md) records installer implementation,
local acceptance, signing boundaries, and release workflows.

## Troubleshooting

| Symptom | What I check |
| --- | --- |
| UAC cancelled | Launch again and approve the normal prompt; cancellation opens no main window |
| Wrong Python version | Run `uv python install 3.14.7` and `uv sync --locked --python 3.14.7`; do not select another patch |
| Missing `pythonw.exe` or Tk | Recreate the uv environment with a Python build including Tcl/Tk |
| Extra console | Use `uv run --locked network-packet-sniffer`; an existing PowerShell is your own shell |
| No adapters | Wait for discovery, inspect the inline error, then Refresh; admin access and compatible Pktmon are required |
| Pktmon in use / filters found | Resolve through the owner; the app does not take over |
| No packet rows | Confirm the selected adapter carries traffic; idle capture remains stoppable |
| Unsupported format/status | Only the tested English Pktmon format is currently accepted |
| Update feeds unavailable | Refresh is active, disabled, or still in cooldown |
| Stale data after a successful download | The provider generation time is old; downloading does not reset its age |
| Offline / HTTP failure | Cached evidence retains accurate freshness and the update error appears inline |
| Corrupt cache or incorrect clock | Correct the clock; a bad cache is rejected and replaced on the next allowed refresh |
| Closing takes time | The app waits for owned capture/discovery/HTTPS workers with bounded network waits |
| Blurry text after moving monitors | Restart on the target display for its startup DPI |
| Old captures in the folder | They are not needed to run; inspect ownership/content before removing them |

## License and attribution

Copyright **2023–2026 Faraz Hussain**. I release this project under the
[Apache License 2.0](LICENSE), with original author credit in [NOTICE](NOTICE).
Redistributed source must preserve relevant attribution notices; derivative
distributions must include the NOTICE attribution as the license requires.
Bundled third-party components retain their own licenses and notices.
