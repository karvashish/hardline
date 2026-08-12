# Coverage Ledger

A profile that claims to cover a set of controls has to say so in content that
is signed with it. `coverage_ledger` in `profile.json` names a signed file
listing every control the profile makes a claim about: what state it wants,
where that state came from, which steps produce it, and how the claim was
tested.

It is optional. A profile that makes no coverage claim omits the field and
nothing changes.

```json
{
  "id": "example-profile",
  "actions": ["actions/10-packages.json"],
  "templates": [],
  "coverage_ledger": "coverage.json"
}
```

## Shape

```json
{
  "controls": [
    {
      "hardline_id": "HL-0001",
      "desired_state": "the SSH drop-in is present at mode 0600",
      "source_title": "sshd_config(5)",
      "source_url": "https://man.openbsd.org/sshd_config",
      "source_version_or_commit": "OpenSSH 9.6",
      "retrieved_at": "2026-08-12",
      "implementation_actions": ["deploy-ssh-config"],
      "status": "implemented",
      "tests": ["itest: ssh-reload-rollback"],
      "copied_code": false
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `hardline_id` | The profile's own control identifier. It is independent: it does not encode, and does not claim to correspond to, any benchmark's numbering |
| `desired_state` | What the control wants, in a sentence |
| `source_title`, `source_url`, `source_version_or_commit`, `retrieved_at` | The engineering reference the desired state was derived from, pinned to a version and a date. All four are required |
| `implementation_actions` | The step IDs that produce the state. Required when `status` is `implemented`, and forbidden otherwise |
| `status` | One of the six values below |
| `tests` | How the claim is checked, free text |
| `copied_code` | Must be `false`. No benchmark text, script or rule content is copied into the profile |

## Status values

| Status | Meaning |
| --- | --- |
| `implemented` | The profile produces this state, through the named steps |
| `asserted_prerequisite` | The profile checks the state but does not create it |
| `site_required` | The decision belongs to the operator: allowed ports, account exclusions, log destinations |
| `provisioning` | It belongs to image building or infrastructure: partitions, disk encryption, the admin account |
| `deferred` | In scope, not done yet, stated rather than omitted |
| `not_applicable` | Does not apply to this target |

## What verify enforces

`verify-profile` reads the ledger from the signed snapshot, like any other
profile reference, and refuses the profile when:

- the ledger is not covered by the signed manifest
- a control repeats a `hardline_id`, or leaves `desired_state` or any source
  field empty
- `retrieved_at` is not a `YYYY-MM-DD` date
- `status` is outside the six values
- `copied_code` is true
- an `implemented` control names no step, or names a step the profile does not
  declare
- two controls claim the same step
- a control that is not `implemented` names steps anyway
- **any step in the profile is left unaccounted for**

That last rule is what makes the ledger a coverage claim rather than a
selective list: a step nobody claims fails verification, so the ledger cannot
quietly omit what a profile actually does.

## What it does not do

The ledger records a citation; nothing checks that the cited document says what
the control claims. It is a statement by the profile's author, signed so it
cannot be edited afterwards without re-signing, and readable before the profile
is ever run against a host.
