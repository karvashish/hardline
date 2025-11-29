# Hardline Profiles

Profiles are deterministic, data-only descriptions of system configuration and hardening.

## Layout

- `profile/profile.json`
  Defines profile identity, OS target, schema version, and the ordered list of action and template files.

- `profile/actions/*.json`
  Each file contains:
  {
    "steps": [
      { "...": "..." }
    ]
  }

  Allowed primitives:
  - packages
  - service
  - sysctl
  - template
  - file
  - firewall
  - user
  - wireguard

- `profile/templates/*.tmpl`
  Static templates with no logic.

## Execution Model

1. Load profile.json
2. Validate schema and min_hardline
3. Validate OS match
4. Validate all step types
5. Execute actions in order
6. Render templates
7. Write metadata

Deterministic and reproducible.
