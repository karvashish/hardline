# Install

Hardline ships prebuilt release archives for Linux and Windows on every tagged release. If you prefer to build from source, jump to [Getting Started](getting-started.md#build-from-source).

## Download A Release

Releases live at:

```text
https://github.com/karvashish/hardline/releases
```

Each tag publishes five archives. Pick the one that matches your machine:

| Archive | For |
| --- | --- |
| `hardline-<tag>-linux-amd64.tar.gz` | Linux on x86_64 |
| `hardline-<tag>-linux-arm64.tar.gz` | Linux on arm64 (Graviton, Ampere, Raspberry Pi 4/5, etc.) |
| `hardline-<tag>-windows-amd64.zip` | Windows on x86_64 |
| `hardline-<tag>-windows-arm64.zip` | Windows on arm64 (Surface Pro X, Snapdragon X) |
| `starter-secure-ubuntu-24.04-lts-<tag>.tar.gz` | The example Ubuntu 24.04 hardening profile |

Every archive has a companion `.sha256` file published next to it. Always verify before extracting.

## Linux

Hardline is installed system-wide under `/etc/hardline`. Everything sensitive — binaries, external plugins, and (if you generate one) your profile signing key — lives in that single root-owned directory. Hardline refuses to load external plugins from a world-writable directory, so getting permissions right here matters.

### Download And Verify

```bash
VERSION=v0.1.0
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

External plugins are loaded from a `plugins/` directory *adjacent* to the `hardline` binary. Keep the real binaries under `/etc/hardline` and symlink them into `/usr/local/bin` — Go resolves the symlink before looking for `plugins/`, so loading still works:

```bash
sudo ln -sf /etc/hardline/hardline    /usr/local/bin/hardline
sudo ln -sf /etc/hardline/profiletool /usr/local/bin/profiletool

hardline version
```

If you copy the binary somewhere without its sibling `plugins/`, the external `firewall_template.so` plugin stops loading. Built-in plugins (`packages`, `template`, `service`, `firewall`) still work, but any profile step that lists `firewall_template` as its plugin will fail.

### Profile Signing Key (Optional)

If you author your own profiles, keep the private signing key in the same root-owned directory — not in your home folder:

```bash
sudo profiletool keygen \
    --private-out /etc/hardline/profile_signing.key \
    --public-out  /etc/hardline/profile_signing_pub.pem

sudo chmod 0600 /etc/hardline/profile_signing.key
sudo chmod 0644 /etc/hardline/profile_signing_pub.pem
```

`/etc/hardline/profile_signing_pub.pem` is also where `hardline verify-profile --allow-local-key` looks for a locally-trusted public key, so keeping both halves here means verify and sign both just work.

### Download The Example Profile

The example Ubuntu 24.04 hardening profile is shipped as its own archive so you can try Hardline without cloning the repo:

```bash
VERSION=v0.1.0
curl -LO "https://github.com/karvashish/hardline/releases/download/${VERSION}/starter-secure-ubuntu-24.04-lts-${VERSION}.tar.gz"
curl -LO "https://github.com/karvashish/hardline/releases/download/${VERSION}/starter-secure-ubuntu-24.04-lts-${VERSION}.tar.gz.sha256"
sha256sum -c "starter-secure-ubuntu-24.04-lts-${VERSION}.tar.gz.sha256"
tar -xzf "starter-secure-ubuntu-24.04-lts-${VERSION}.tar.gz"

hardline verify-profile starter-secure-ubuntu-24.04-lts
```

## Windows

On Windows, pick the matching `.zip`:

```powershell
$Version = "v0.1.0"
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

**External plugins are not supported on Windows** — the Windows builds are statically linked with CGO disabled, and Go's plugin system only works on Linux, FreeBSD, and macOS. Built-in plugins (`packages`, `template`, `service`, `firewall`) are compiled into the binary and work normally. Hardline on Windows is intended as a workstation CLI for managing remote Linux hosts over SSH — not for applying profiles to a Windows host. See the [Platform Support](../../README.md#platform-support) table for the full matrix.

## Verify The Install

Once `hardline` is on your `PATH`, confirm it works:

```bash
hardline version
hardline --help
```

If `hardline version` prints a build that matches the tag you downloaded, you're ready. Continue to [Getting Started](getting-started.md) for the verify → plan → apply → rollback flow.

## Build From Source

If you want to build from a checkout instead of downloading a release, see the [Build From Source](getting-started.md#build-from-source) section of Getting Started. You'll need Go 1.26.1 or newer.
