# Hardline

Hardline is a signed-profile runner for applying opinionated system configuration to remote Linux hosts over SSH. It verifies profile contents locally, checks the target host before changes, produces a plan, applies steps with non-interactive `sudo`, and stores rollback journals so the last successful run can be reverted.

A signed profile can only ask the runtime to do things the runtime already knows how to do. The vocabulary is five typed plugin configs: `packages`, `template`, `service`, `firewall`, and `file_meta`. There is no `exec`, no `command`, no `script`. Signing the manifest signs the full set of instructions, not a wrapper around them.

## Documentation

- [User Guide](user-guide.md) - install, run, sign, recover.
- [Profile Authoring](profile-authoring.md) - write and sign your own profile.
- [Internals](internals.md) - architecture, execution flow, plugin system, rollback.
- [Example Run Artifacts](examples/README.md) - real plan, apply, rollback, and journal output.

## Quick Start

Download a release archive from [the releases page](https://github.com/karvashish/hardline/releases), then:

```bash
hardline verify-profile starter-secure-ubuntu-24.04-lts
hardline plan starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
hardline apply starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
hardline rollback starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

See the [Install Guide](users/install.md) for verification and PATH steps, and [Getting Started](users/getting-started.md) for what each command does.
