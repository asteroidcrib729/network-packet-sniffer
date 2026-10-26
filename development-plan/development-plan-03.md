# Development Plan 03 — Windows installers and attributed open-source release

Updated: 2026-10-26. Application version: **0.5.0**. This plan records the local
packaging implementation, with external signing/installation/hosting acceptance
kept separate from checks that were actually performed.

## Section 01 — Distribution and source

- [x] Create and Git-ignore `packaged-releases/` for tool downloads, temporary
  build work, installers, certificates, checksum manifests, and test output.
- [x] Add a locked, separate packaging dependency group using PyInstaller 6.22.3.
- [x] Bundle CPython **3.14.7 final exactly**, Tcl/Tk, the standard library/native
  dependencies, and the application without requiring Python/uv at installation.
- [x] Build one windowed administrator application for both installer formats.
- [x] Fix bundled elevation to relaunch its own executable; preserve source-mode
  `pythonw -m` elevation and avoid writes into frozen installation directories.
- [x] Include an allowlisted exact source ZIP in both installers and as an asset.
  Exclude logs, caches, `.env`, private keys, environments, and bytecode.
- [x] Record the source commit and dirty state, deterministic source digest,
  exact interpreter/runtime/tool versions, asset sizes/hashes, and signing mode.
- [x] Isolate DLL search and build caches; reject unrelated DLL origins. A first
  local build revealed a Java PATH CRT dependency; the corrected build passes
  origin checks and does not copy that unrelated runtime.

## Section 02 — EXE and MSIX

- [x] Verify the official Inno Setup 7.1.0 compiler download by pinned SHA-256 and
  publisher signature before installing it into ignored build-tool storage.
- [x] Create a dark EXE setup wizard, Program Files installation, Start menu
  shortcut, source/notices, and standard uninstall flow.
- [x] Create and semantically validate a Windows x64 MSIX using Windows SDK
  MakeAppx, with package version, generated artwork, full-trust and elevation
  declarations. This is a sideload package, not a Store submission.
- [x] Support ephemeral self-signed preview MSIX signing, export only the public
  CER, and delete the temporary certificate/private key after building. Leave
  trusted certificate stores unchanged. Preview EXEs remain unsigned.
- [x] Support production PFX signing, RFC 3161 timestamps, verification, and exact
  publisher matching. Missing/invalid credentials fail rather than downgrade.
- [x] Add SHA256SUMS and release-manifest verification, package-content checks,
  CMS signature verification, and EXE install/window/close/uninstall smoke tests.
- [x] Refuse install smoke tests that could replace an existing installation;
  require an administrator test process to control the elevated test GUI.

## Section 03 — Repository workflows

- [x] Add manual/tag-triggered installer builds with exact Python 3.14.7, pinned
  actions/uv, unit/lint/format/lock checks, both installers, EXE smoke, and artifacts.
- [x] Keep ordinary builds read-only; restrict release-write permission to the
  draft job. Decode production credentials only into runner temporary storage.
- [x] Allow branch previews without creating tags/releases. Require an existing
  matching version tag at the exact source commit for drafts.
- [x] Create/refresh drafts for the same source commit without overwriting
  published releases. Remove obsolete draft assets after a successful refresh.
- [x] Add manual draft publication that downloads and verifies actual assets,
  checks source/tag/checksum consistency, and checks production signatures.
- [x] Require production certificate signing for stable publication; preview
  signing can be published only as a prerelease.
- [x] Serialize draft/build/publish workflows and document fresh-run requirements
  after workflow changes.

## Section 04 — License and attribution

- [x] Add the unmodified Apache License 2.0 and a NOTICE crediting original author
  **Faraz Hussain**, the repository, and the project's Q4 2023 academic origin.
- [x] Set SPDX license, license files, and author metadata in `pyproject.toml`.
- [x] Include license/NOTICE files in distributions and installers. Preserve
  interpreter, Tcl/Tk, native component, Inno, and PyInstaller bootloader notices.
- [x] Explain attribution under the standard license without adding a custom
  advertising restriction or promising mandatory UI credit.

## Section 05 — Local evidence and remaining acceptance

| Check | Result |
| --- | --- |
| Interpreter | CPython 3.14.7 final for all execution/build/test work |
| Automated suite | All 113 tests pass, including frozen elevation/data paths, source exclusions, DLL-origin/subsystem checks, tag safeguards, and checksum tampering |
| Source quality | Ruff lint/format and lock checks pass; PowerShell scripts parse |
| Workflow syntax | All workflows pass checksum-verified actionlint 1.7.12 |
| Local builds | Both EXE and signed preview MSIX are generated successfully |
| EXE acceptance | Temporary installation creates the bundled Tk window, closes with exit 0, and uninstalls successfully |
| MSIX acceptance | MakeAppx validation, required payload/capability checks, CMS signature check, and signer matching pass; device trust/installation is not claimed |
| Attribution/source | LICENSE, NOTICE, component terms, and the source ZIP are present; no private key is shipped |
| Original data | Preserved academic log remains unchanged; captures/cache contents are not packaged |

- [ ] Test MSIX installation and activation after explicitly establishing signer
  trust on a dedicated test machine. No trust or UAC setting was changed here.
- [ ] Exercise production signing with the owner's actual trusted certificate;
  no production PFX, password, or publisher identity was supplied.
- [ ] Run and inspect hosted build/draft/publish workflows after the reviewed
  source is committed/pushed/tagged. No repository release was published here.
- [ ] Repeat both installation formats and live capture on another clean Windows
  machine. Other builds/adapters/locales retain Plan 02's acceptance limits.

The local artifacts accurately identify the current source as uncommitted. They
are preview builds, not artifacts claimed to originate from a published tag.
See the [packaging guide](../packaging/README.md) for exact operator steps.
