# Hardline Profiles

Profiles are deterministic, data-only descriptions of system configuration and hardening.

## Layout

- `profile/profile.json`
  Defines profile identity, OS target, schema version, and the ordered list of action and template files.

- `profile/actions/*.json`
  Each file contains:
  {
    "steps": [
      {
        "id": "step-id",
        "plugin": "plugin-name",
        "config": {
          "... plugin-owned fields ...": "..."
        }
      }
    ]
  }
  The core only owns common step metadata such as `id`, `plugin`, `severity`,
  `risk_class`, `control_tags`, and `allow_unvalidated`.
  All plugin-specific fields live under `config` and are parsed and validated by the plugin that owns them.

- `profile/templates/*.tmpl`
  Static templates with no logic.

## Execution Model

1. Load profile.json
2. Validate schema and min_hardline
3. Validate OS match
4. Validate each step through its plugin
5. Execute actions in order
6. Render templates
7. Write metadata

Deterministic and reproducible.
