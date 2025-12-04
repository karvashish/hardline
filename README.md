# hardline

***Always have rollback, and don’t lock yourself out.***

Declarative, deterministic security profiles using a strict JSON-only schema and template system for reproducible hardening.


### Why JSON?

1. **Determinism / safety**

   * JSON has no type coercion, no anchors, no merges, no indentation magic.
   * For security policy, “boring and strict” beats “convenient and ambiguous”.

2. **Separation of concerns**

   * Structure in JSON (`profile.json`, `actions/*.json`)
   * Actual config in native formats (`templates/*.tmpl`: sshd, nftables, journald, …)
   * We’re not trying to shove everything into YAML; configs stay as the service expects them.

3. **Tooling + UX**

   * Profiles are validated by `hardline verify-profile` with strict schema.
   * Nobody is expected to hand-write huge JSON; they edit small, well-defined step files and templates.
   * JSON’s constraints are a feature, not a bug.

*YAML is for human-facing infra manifests. Hardline profiles are machine-validated security policy; JSON’s strictness is intentional.*

### Design philosophy

- Keep behavior explicit and visible.
- Prefer concrete code over abstraction layers.
- Prefer small, focused functions over generic frameworks.
- Limit helpers to mechanical concerns (SSH, file I/O, logging).
- Do not use generics in domain logic.

Code should make operational intent obvious at the call site. Local duplication is acceptable when it preserves clarity. Shared abstractions are introduced only when proven stable and beneficial over time.
