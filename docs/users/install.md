# Install

Hardline ships prebuilt release archives for Linux, macOS, and Windows on every tagged release. If you prefer to build from source, jump to [Getting Started](getting-started.md#build-from-source).

## Download A Release

Releases live at:

```text
https://github.com/karvashish/hardline/releases
```

Each tag publishes eight archives: six binary builds and one tarball per starter profile. Pick the one that matches your machine:

| Archive | For |
| --- | --- |
| `hardline-<tag>-linux-amd64.tar.gz` | Linux on x86_64 |
| `hardline-<tag>-linux-arm64.tar.gz` | Linux on arm64 (Graviton, Ampere, Raspberry Pi 4/5, etc.) |
| `hardline-<tag>-darwin-amd64.tar.gz` | macOS on Intel (x86_64) |
| `hardline-<tag>-darwin-arm64.tar.gz` | macOS on Apple Silicon (M1/M2/M3/M4) |
| `hardline-<tag>-windows-amd64.zip` | Windows on x86_64 |
| `hardline-<tag>-windows-arm64.zip` | Windows on arm64 (Surface Pro X, Snapdragon X) |
| `starter-secure-ubuntu-24.04-lts-<tag>.tar.gz` | The example Ubuntu 24.04 hardening profile |
| `starter-secure-rocky-9-<tag>.tar.gz` | The example Rocky Linux 9 hardening profile |

Every archive has a companion `.sha256` file published next to it. Always verify before extracting.

## Linux

Hardline is installed system-wide under `/etc/hardline`. Everything sensitive - binaries, external plugins, and (if you generate one) your profile signing key - lives in that single root-owned directory. Hardline refuses to load external plugins from a world-writable directory, so getting permissions right here matters.

### Download And Verify

```bash
VERSION=v0.1.2   # replace with the release tag you want
OS=linux
ARCH=amd64   # or arm64

curl -LO "https://github.com/karvashish/hardline/releases/download/${VERSION}/hardline-${VERSION}-${OS}-${ARCH}.tar.gz"
curl -LO "https://github.com/karvashish/hardline/releases/download/${VERSION}/hardline-${VERSION}-${OS}-${ARCH}.tar.gz.sha256"

sha256sum -c "hardline-${VERSION}-${OS}-${ARCH}.tar.gz.sha256"
```

### Extract Into `/etc/hardline`

```bash
sudo mkdir -p /etc/hardline
sudo tar -xzf "hardline-${VERSION}-${OS}-${ARCH}.tar.gz" \
    -C /etc/hardline --strip-components=1

sudo chown -R root:root /etc/hardline
sudo chmod 0755 /etc/hardline /etc/hardline/plugins
sudo chmod 0755 /etc/hardline/hardline /etc/hardline/profiletool
sudo chmod 0644 /etc/hardline/plugins/*.so
```

The resulting layout:

```text
/etc/hardline/
  hardline              # main CLI                     0755 root:root
  profiletool           # signing + manifest helper    0755 root:root
  plugins/              # external plugin directory    0755 root:root
    firewall_template.so                               0644 root:root
  README.md
  LICENSE
```

### Put Hardline On Your PATH

External plugins are loaded from a `plugins/` directory *adjacent* to the `hardline` binary. Keep the real binaries under `/etc/hardline` and symlink them into `/usr/local/bin` - Go resolves the symlink before looking for `plugins/`, so loading still works:

```bash
sudo ln -sf /etc/hardline/hardline    /usr/local/bin/hardline
sudo ln -sf /etc/hardline/profiletool /usr/local/bin/profiletool

hardline version
```

If you copy the binary somewhere without its sibling `plugins/`, the external `firewall_template.so` plugin stops loading. Built-in plugins (`packages_apt`, `packages_dnf4`, `packages_dnf5`, `template`, `service`, `firewall`, `file_meta`, `audit`, `ssh`) still work, but any profile step that lists `firewall_template` as its plugin will fail.

### Profile Signing Key (Optional)

If you author your own profiles, keep the private signing key in the same root-owned directory - not in your home folder:

```bash
sudo profiletool keygen \
    --private-out /etc/hardline/profile_signing.key \
    --public-out  /etc/hardline/profile_signing_pub.pem

sudo chmod 0600 /etc/hardline/profile_signing.key
sudo chmod 0644 /etc/hardline/profile_signing_pub.pem
```

`/etc/hardline/profile_signing_pub.pem` is also where `hardline verify-profile --allow-local-key` looks for a locally-trusted public key, so keeping both halves here means verify and sign both just work.

`keygen` always writes a third copy of the public key to `internals/verify/profile_signing_pub.pem` **relative to the current working directory**, creating that directory if it does not exist. That path is the source-tree location of the key embedded into the `hardline` binary at build time, so the behavior only makes sense from a repo checkout. When you run `keygen` from an installed binary, `cd` to a scratch directory first and delete the stray `internals/` tree it leaves behind.

### Download The Example Profile

Each starter profile is shipped as its own archive so you can try Hardline without cloning the repo. Swap `starter-secure-rocky-9` in for a RHEL-family target; the archive extracts to a directory of that name either way:

```bash
VERSION=v0.1.2   # replace with the release tag you want
curl -LO "https://github.com/karvashish/hardline/releases/download/${VERSION}/starter-secure-ubuntu-24.04-lts-${VERSION}.tar.gz"
curl -LO "https://github.com/karvashish/hardline/releases/download/${VERSION}/starter-secure-ubuntu-24.04-lts-${VERSION}.tar.gz.sha256"
sha256sum -c "starter-secure-ubuntu-24.04-lts-${VERSION}.tar.gz.sha256"
tar -xzf "starter-secure-ubuntu-24.04-lts-${VERSION}.tar.gz"

hardline verify-profile starter-secure-ubuntu-24.04-lts
```

## macOS

Both macOS architectures are published - `darwin/amd64` for Intel Macs, `darwin/arm64` for Apple Silicon. Unlike Windows, macOS supports external plugins, so the archive ships `firewall_template.so` alongside the binaries.

The install follows the same root-owned `/etc/hardline` layout as [Linux](#linux), with these macOS-specific differences: verify with `shasum`, own the tree as `root:wheel` (macOS has no `root` group - GID 0 is `wheel`), and clear the Gatekeeper quarantine flag, which is set on archives downloaded through a browser.

```bash
VERSION=v0.1.2   # replace with the release tag you want
ARCH=arm64   # or amd64 on Intel Macs

curl -LO "https://github.com/karvashish/hardline/releases/download/${VERSION}/hardline-${VERSION}-darwin-${ARCH}.tar.gz"
curl -LO "https://github.com/karvashish/hardline/releases/download/${VERSION}/hardline-${VERSION}-darwin-${ARCH}.tar.gz.sha256"
shasum -a 256 -c "hardline-${VERSION}-darwin-${ARCH}.tar.gz.sha256"

sudo mkdir -p /etc/hardline
sudo tar -xzf "hardline-${VERSION}-darwin-${ARCH}.tar.gz" \
    -C /etc/hardline --strip-components=1

sudo chown -R root:wheel /etc/hardline
sudo chmod 0755 /etc/hardline /etc/hardline/plugins
sudo chmod 0755 /etc/hardline/hardline /etc/hardline/profiletool
sudo chmod 0644 /etc/hardline/plugins/*.so
sudo xattr -dr com.apple.quarantine /etc/hardline 2>/dev/null || true

sudo mkdir -p /usr/local/bin
sudo ln -sf /etc/hardline/hardline    /usr/local/bin/hardline
sudo ln -sf /etc/hardline/profiletool /usr/local/bin/profiletool

hardline version
```

The same rules as Linux apply from here: external plugins load from the `plugins/` directory next to the resolved binary (see [Put Hardline On Your PATH](#put-hardline-on-your-path)), and the optional [profile signing key](#profile-signing-key-optional) and [example profile](#download-the-example-profile) steps are identical.

## Windows

On Windows, pick the matching `.zip`:

```powershell
$Version = "v0.1.2"   # replace with the release tag you want
$Arch = "amd64"   # or "arm64"
$Archive = "hardline-$Version-windows-$Arch.zip"
Invoke-WebRequest -Uri "https://github.com/karvashish/hardline/releases/download/$Version/$Archive" -OutFile $Archive
Invoke-WebRequest -Uri "https://github.com/karvashish/hardline/releases/download/$Version/$Archive.sha256" -OutFile "$Archive.sha256"

# Verify the hash
$Expected = (Get-Content "$Archive.sha256").Split()[0]
$Actual   = (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLower()
if ($Expected -ne $Actual) { throw "SHA256 mismatch" }

Expand-Archive -Path $Archive -DestinationPath .
cd "hardline-$Version-windows-$Arch"
.\hardline.exe version
```

Add the extracted directory to `PATH` via **System Properties → Environment Variables**, or use `$env:PATH` for the current shell session.

**External plugins are not supported on Windows** - the Windows builds are statically linked with CGO disabled, and Go's plugin system only works on Linux, FreeBSD, and macOS. Built-in plugins (`packages_apt`, `packages_dnf4`, `packages_dnf5`, `template`, `service`, `firewall`, `file_meta`, `audit`, `ssh`) are compiled into the binary and work normally. Hardline on Windows is intended as a workstation CLI for managing remote Linux hosts over SSH - not for applying profiles to a Windows host. See the [Platform Support](#platform-support) table below for the full matrix.

## Platform Support

| Platform | `hardline` CLI | `profiletool` | Built-in plugins | External plugins |
|---|---|---|---|---|
| Linux amd64 | yes | yes | yes | yes |
| Linux arm64 | yes | yes | yes | yes |
| macOS amd64 | yes | yes | yes | yes |
| macOS arm64 | yes | yes | yes | yes |
| Windows amd64 | yes | yes | yes | **no** |
| Windows arm64 | yes | yes | yes | **no** |

Hardline applies configuration to remote Linux hosts over SSH. The Windows builds exist so you can run the CLI from a Windows workstation to manage Linux targets - they are not intended for applying profiles *to* a Windows host.

External plugins are unsupported on Windows by design. Go's plugin system (`-buildmode=plugin`) is only available on Linux, FreeBSD, and macOS, and the Windows builds are compiled with `CGO_ENABLED=0` for a fully static binary. Any profile step that tries to load an external plugin (for example `firewall_template.so`) will fail at runtime with a `plugin: not implemented` error. Built-in plugins (`packages_apt`, `packages_dnf4`, `packages_dnf5`, `template`, `service`, `firewall`, `file_meta`, `audit`, `ssh`) are compiled into the binary and remain available on every platform.

## Verify The Install

Once `hardline` is on your `PATH`, confirm it works:

```bash
hardline version
hardline --help
```

If `hardline version` prints a build that matches the tag you downloaded, you're ready. Continue to [Getting Started](getting-started.md) for the verify → plan → apply → rollback flow.

## Build From Source

If you want to build from a checkout instead of downloading a release, see the [Build From Source](getting-started.md#build-from-source) section of Getting Started. You'll need Go 1.26.1 or newer.
