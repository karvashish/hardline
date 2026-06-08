# Hardline Release Archive

This archive contains the runnable Hardline command-line tools for one platform.
It is meant to be installed as-is; the full project documentation lives in the
repository and on the GitHub release page.

## Contents

Linux archives contain:

- `hardline` - main CLI
- `profiletool` - profile signing and manifest helper
- `plugins/firewall_template.so` - external firewall-template plugin
- `README.md` - this file
- `LICENSE`

Windows archives contain:

- `hardline.exe` - main CLI
- `profiletool.exe` - profile signing and manifest helper
- `README.md` - this file
- `LICENSE`

Windows builds do not include external plugins. Go's plugin system is not
available there, but the built-in plugins still work.

## Verify The Download

Each release file has a companion `.sha256` file. Verify the archive before
extracting it:

```bash
sha256sum -c hardline-<version>-linux-<arch>.tar.gz.sha256
```

On Windows, compare the hash from the `.sha256` file with:

```powershell
Get-FileHash hardline-<version>-windows-<arch>.zip -Algorithm SHA256
```

## Install On Linux

Install the Linux archive under `/etc/hardline` so the binary and its sibling
`plugins/` directory stay together:

```bash
sudo mkdir -p /etc/hardline
sudo tar -xzf hardline-<version>-linux-<arch>.tar.gz \
  -C /etc/hardline --strip-components=1

sudo chown -R root:root /etc/hardline
sudo chmod 0755 /etc/hardline /etc/hardline/plugins
sudo chmod 0755 /etc/hardline/hardline /etc/hardline/profiletool
sudo chmod 0644 /etc/hardline/plugins/*.so

sudo ln -sf /etc/hardline/hardline /usr/local/bin/hardline
sudo ln -sf /etc/hardline/profiletool /usr/local/bin/profiletool
hardline version
```

External plugins are loaded from `plugins/` next to the resolved `hardline`
binary. If you move `hardline`, move `plugins/` with it.

## Use On Windows

Extract the `.zip` file and run:

```powershell
.\hardline.exe version
```

Add the extracted directory to `PATH` if you want `hardline.exe` and
`profiletool.exe` available from any shell.

## Example Profile

The starter Ubuntu profile is published as a separate archive named:

```text
starter-secure-ubuntu-24.04-lts-<version>.tar.gz
```

Download and verify that file separately if you want a ready-to-run example
profile.

## Basic Flow

```bash
hardline verify-profile starter-secure-ubuntu-24.04-lts
hardline plan starter-secure-ubuntu-24.04-lts --host example.com --user ubuntu --keypath ~/.ssh/id_ed25519
hardline apply starter-secure-ubuntu-24.04-lts --host example.com --user ubuntu --keypath ~/.ssh/id_ed25519
hardline rollback starter-secure-ubuntu-24.04-lts --host example.com --user ubuntu --keypath ~/.ssh/id_ed25519
```

The target user must be able to run `sudo -n`, and the target host must already
exist in your `known_hosts` file.
