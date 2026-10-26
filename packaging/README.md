# Windows installers and repository releases

I build the EXE installer and sideload MSIX from the same windowed, one-directory
PyInstaller bundle. Both include **CPython 3.14.7**, Tcl/Tk, the application, its
source ZIP, LICENSE, NOTICE, and third-party license texts. Installed users need
neither Python nor uv, Wireshark, Npcap, nor another capture driver. Windows must
provide compatible Pktmon and ConPTY; the application still requires elevation.

## Local build

Build on Windows x64 with Python **3.14.7 final exactly**, Tcl/Tk, uv, and the
Windows SDK's x64 MakeAppx and SignTool tools. The SDK must be installed before
building. The script selects the newest installed SDK and records its version.

```powershell
uv python install 3.14.7
uv sync --locked --group packaging --python 3.14.7
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/build-installers.ps1
```

That execution-policy argument applies only to this build process; it does not
change machine/user policy. `bootstrap-inno.ps1` downloads **Inno Setup 7.1.0**
from its official immutable release, checks its pinned SHA-256 and publisher
signature, and installs the compiler for the current user inside
`packaged-releases/.tools/InnoSetup`. Its tool installation has its own normal
uninstall registration. To use an existing compiler, supply `-Iscc <ISCC.exe>`.

Python packaging tools are locked in the separate `packaging` dependency group.
PyInstaller **6.22.3** is a build dependency, not a runtime dependency installed on
the user's computer. The build uses a normal windowed executable with an
administrator manifest. It avoids extracting a privileged one-file executable
into a temporary directory on every launch.

The freezer runs with a restricted process-local DLL search PATH and its own
ignored cache. An inspection step rejects DLLs from unrelated installations and
checks the windowed subsystem and embedded administrator manifest.

The default build creates preview artifacts under **`packaged-releases/0.5.0/`**:

| File | Purpose |
| --- | --- |
| `NetworkPacketSniffer-0.5.0-x64-setup.exe` | Dark Inno Setup installer, Start menu entry, and uninstaller |
| `NetworkPacketSniffer-0.5.0-x64.msix` | Signed preview sideload package |
| `NetworkPacketSniffer-0.5.0-source.zip` | Allowlisted exact source, tests, build recipes, workflows, metadata, and notices |
| `NetworkPacketSniffer-0.5.0-preview.cer` | Public development certificate for this build; never a private key |
| `release.json` | Source commit/dirty state, source digest, tools, runtime versions, signing mode, and asset sizes/hashes |
| `SHA256SUMS.txt` | SHA-256 of the assets and release manifest |
| `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.txt` | Project attribution and component notices |

The source archive is also installed beside the application. It includes only
the explicit source/documentation/configuration directories, never local capture
logs, feed caches, `.env` files, bytecode, environments, or private signing keys.
All build work, tool downloads, local installers, and test output stay inside
the Git-ignored `packaged-releases/` directory. The version comes from
`pyproject.toml`; paths above change when that version changes.

## Install and run

Choose **one installer format** for normal use. The EXE installs under Program
Files, creates a Start menu shortcut, and supports Windows' normal uninstall
flow. Setup and the application request administrator privileges. UAC can remain
enabled. The application has no attached terminal and stays dark; the EXE setup
wizard is dark too. Windows' own App Installer controls the MSIX installation UI.

The application stores writable data in Local AppData, outside its install
directory. MSIX can redirect that data into its package-specific app data area;
uninstalling MSIX can remove that package data. EXE uninstall does not remove the
separate Local AppData cache/log directory. The original repository's academic
log is never included or modified by packaging.

### Preview signature and certificate trust

The default **Preview** build leaves the EXE unsigned and signs the MSIX with an
ephemeral self-signed code-signing certificate. It exports only the public CER,
then removes the temporary certificate and private key from the build account.
No trusted-root or Trusted People store is modified, and no private key is
uploaded. Each preview build has a new certificate, so it is not a persistent
production publisher identity.

Windows requires an MSIX signer to be trusted before installation. A self-signed
preview is not automatically trusted. Inspect the CER subject and SHA-1
thumbprint against `release.json`, verify the downloaded checksums, and use a
dedicated test machine if choosing to trust that preview certificate. Windows'
certificate import UI can place that public certificate in the local computer's
**Trusted People** store with administrator consent. Then open the MSIX or use
`Add-AppxPackage -Path <package.msix>`. Remove the preview trust entry after the
test if it is no longer needed. The build/test scripts do not do this for you.

The MSIX declares `runFullTrust` and `allowElevation`. This is a **sideload desktop
package**, not a Microsoft Store submission or Store certification claim.
Production signing does not remove capture's administrator requirement.

### Production signatures

Use your own trusted code-signing PFX and matching full publisher subject:

```powershell
# Set WINDOWS_SIGNING_PASSWORD through your secure local secret mechanism.
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/build-installers.ps1 `
  -SigningMode Certificate -PfxPath C:\private\publisher.pfx `
  -Publisher 'CN=Your actual certificate subject'
```

Certificate mode signs the application EXE, setup EXE, and MSIX using SHA-256 and
RFC 3161 timestamping. SignTool verifies production signatures and trust. Missing
credentials, an untrusted certificate, failed timestamping, or a publisher
mismatch fails the build; it never silently falls back to preview signing. Keep
private keys outside the release output directory.

## Local acceptance

```powershell
# Run from an administrator PowerShell to control the elevated test window.
./packaging/test-installers.ps1 -ReleaseDirectory packaged-releases/0.5.0 -InstallExe
```

The test verifies checksums, package contents, version/elevation declarations,
and the MSIX CMS signature without granting certificate trust. It installs the
EXE into a unique directory inside `packaged-releases/.validation`, opens its
actual Tk window, closes it, and uninstalls the test copy. It refuses to run the
EXE installation test if an existing EXE installation could be affected.
Without `-InstallExe`, it performs read-only artifact verification.

MSIX structure/signature checks do **not** claim successful MSIX installation.
Installation/activation under trusted signing and another clean Windows machine
remain separate acceptance steps. Local build results also do not prove a hosted
workflow succeeded.

## GitHub workflows

### Build Windows installers

[build-installers.yml](../.github/workflows/build-installers.yml) runs manually or
when a `v*` tag is pushed. It pins Python 3.14.7, uv and action commits, runs tests,
lint, formatting and lock checks, builds both formats, performs EXE install/launch/
uninstall smoke tests, and uploads a 30-day Actions artifact.

- **Branch preview:** select the reviewed branch, leave `create_draft=false`,
  and choose `signing_mode=preview`. No tag or repository release is created.
- **Draft release:** commit and push the reviewed code first. Create and push an
  existing matching tag, currently **`v0.5.0`**, at that commit. A tag push builds
  a preview and drafts the release automatically. A manual build with
  `create_draft=true` requires that same matching tag already point to the
  selected commit. A version number is not a branch/ref to invent implicitly.
- **Production draft:** select the matching tag/commit, choose
  `signing_mode=certificate`, and set `create_draft=true`. Configure the secrets
  and variable below first. An existing draft can be refreshed only for the same
  source commit; published releases are never overwritten. Obsolete preview
  assets are removed from a refreshed draft after successful upload.

| Repository setting | Value |
| --- | --- |
| Secret `WINDOWS_SIGNING_PFX_BASE64` | Base64 encoding of the production code-signing PFX |
| Secret `WINDOWS_SIGNING_PASSWORD` | PFX password |
| Variable `WINDOWS_PUBLISHER` | Exact certificate subject, including `CN=` and any other subject fields |

The PFX is decoded only in runner temporary storage, removed in `finally`, and
excluded from artifact upload patterns. Only the draft job has release-write
permission. Build jobs use read-only repository permissions.

### Publish verified draft release

[publish-release.yml](../.github/workflows/publish-release.yml) is manual. Enter
the existing tag, for example `v0.5.0`, and choose whether it is a prerelease.
It downloads the draft's actual assets, checks all hashes and source/tag metadata,
verifies production signatures when present, and then publishes that draft.
**Stable publication requires certificate mode.** Preview packages can be
published only as prereleases. Neither workflow creates Git tags implicitly.

The two workflows share a concurrency group so building/updating a draft and
publishing cannot overlap. A changed workflow needs a fresh run; rerunning an
old run keeps its old workflow/source selection.

## Attribution and third-party terms

The project uses the unmodified [Apache License 2.0](../LICENSE) with an original
author [NOTICE](../NOTICE). Source redistributions must retain relevant copyright
and attribution notices; derivative distributions must carry the NOTICE
attribution as required by the license. There is no additional custom advertising
or mandatory UI-credit clause.

Bundled components keep their own licenses. The build collects the interpreter's
license and actual Tcl/Tk notices, plus PyInstaller's bootloader exception and
build-tool notices. Additional native-component license texts are kept in
`packaging/licenses/` from CPython 3.14.7's installed licensing documentation,
[OpenSSL 3.5.7](https://github.com/openssl/openssl/blob/openssl-3.5.7/LICENSE.txt),
[zlib-ng](https://github.com/zlib-ng/zlib-ng/blob/2.2.5/LICENSE.md),
[LibTomMath](https://github.com/libtom/libtommath/blob/v1.3.0/LICENSE), and
the verified Inno Setup 7.1.0 distribution. Runtime native versions are recorded
in build provenance; CI Python distributions can bundle different Tcl/Tk builds.
Windows Pktmon/system tools and Spamhaus feed data are not redistributed.
Microsoft runtime redistributables retain their component terms in the bundled
Python license documentation.
