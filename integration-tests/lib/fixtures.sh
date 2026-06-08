#!/usr/bin/env bash
# =============================================================================
# fixtures.sh — dynamic profile generators + signing infrastructure
# =============================================================================
# Sourced by itest.sh. Do not run directly.
# Requires: DYNAMIC_PROFILES_DIR, ROOT_DIR.
# Each generator prints the profile dir on stdout and signs the manifest.

# ─── Signing ─────────────────────────────────────────────────────────────────
init_signing() {
  SIGNING_KEY="${ROOT_DIR}/tmp/profile_signing.key"
  PROFILETOOL_BIN="${ROOT_DIR}/tmp/profiletool"

  if [[ ! -f "${SIGNING_KEY}" ]]; then
    echo "WARNING: signing key not found at ${SIGNING_KEY}" >&2
    CAN_SIGN=false
    return
  fi
  if [[ ! -x "${PROFILETOOL_BIN}" ]]; then
    echo "WARNING: profiletool not found at ${PROFILETOOL_BIN}" >&2
    CAN_SIGN=false
    return
  fi
  CAN_SIGN=true
}

sign_profile() {
  local profile_dir="$1"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    echo "WARNING: cannot sign profile — profiletool or key missing" >&2
    return 1
  fi
  "${PROFILETOOL_BIN}" sign \
    --profile-dir "${profile_dir}" \
    --private-key "${SIGNING_KEY}"
}

# ─── Packages ────────────────────────────────────────────────────────────────
make_profile_packages_install() {
  local name="$1" pkg="$2"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-packages.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-packages.json" <<EOJSON
{ "steps": [{ "id": "install-${pkg}", "plugin": "packages",
  "config": { "update": "once", "install": ["${pkg}"] } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

make_profile_packages_purge() {
  local name="$1" pkg="$2"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-packages.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-packages.json" <<EOJSON
{ "steps": [{ "id": "purge-${pkg}", "plugin": "packages",
  "config": { "purge": ["${pkg}"] } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

make_profile_packages_update_always() {
  local name="$1" pkg="$2"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-packages.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-packages.json" <<EOJSON
{ "steps": [{ "id": "install-${pkg}", "plugin": "packages",
  "config": { "update": "always", "install": ["${pkg}"] } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# ─── Template ────────────────────────────────────────────────────────────────
make_profile_template() {
  local name="$1" dest="$2" content="$3" mode="${4:-0644}"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions" "${dir}/templates"
  printf '%b' "${content}" > "${dir}/templates/config.tmpl"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-template.json"], "templates": ["templates/config.tmpl"]
}
EOJSON
  cat > "${dir}/actions/00-template.json" <<EOJSON
{ "steps": [{ "id": "deploy-config", "plugin": "template",
  "config": { "src": "templates/config.tmpl", "dest": "${dest}", "mode": "${mode}" } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# ─── Firewall (basic — input chain only) ─────────────────────────────────────
make_profile_firewall() {
  local name="$1" table="$2" dest="$3"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-firewall.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-firewall.json" <<EOJSON
{
  "steps": [
    { "id": "configure-fw", "plugin": "firewall", "config": {
        "backend": "nftables", "family": "inet", "table": "${table}",
        "managed_dest": "${dest}",
        "policies": [{ "chain": "input", "policy": "drop" }],
        "rules": [
          { "chain": "input", "in_interface": "lo", "action": "accept" },
          { "chain": "input", "ct_states": ["established", "related"], "action": "accept" },
          { "chain": "input", "proto": "tcp", "port": 22, "action": "accept" },
          { "chain": "input", "proto": "icmp", "action": "accept" }
        ] } },
    { "id": "reload-nftables", "plugin": "service",
      "config": { "name": "nftables", "enabled": true, "state": "restarted" } }
  ]
}
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# Firewall with advanced rules (forward chain, source CIDR, multi-port, non-lo).
make_profile_firewall_advanced() {
  local name="$1" table="$2" dest="$3" iface="${4:-lo}"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-firewall.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-firewall.json" <<EOJSON
{
  "steps": [
    { "id": "configure-fw-advanced", "plugin": "firewall", "config": {
        "backend": "nftables", "family": "inet", "table": "${table}",
        "managed_dest": "${dest}",
        "policies": [
          { "chain": "input", "policy": "drop" },
          { "chain": "forward", "policy": "drop" }
        ],
        "rules": [
          { "chain": "input", "in_interface": "lo", "action": "accept" },
          { "chain": "input", "ct_states": ["established", "related"], "action": "accept" },
          { "chain": "input", "proto": "tcp", "port": 22, "action": "accept" },
          { "chain": "input", "proto": "tcp", "ports": [80, 443], "action": "accept" },
          { "chain": "input", "proto": "tcp", "port": 8080, "source": "10.0.0.0/8", "action": "accept" },
          { "chain": "input", "proto": "icmp", "action": "accept" },
          { "chain": "forward", "in_interface": "${iface}", "proto": "tcp", "port": 8443, "action": "accept" }
        ] } },
    { "id": "reload-nftables", "plugin": "service",
      "config": { "name": "nftables", "enabled": true, "state": "restarted" } }
  ]
}
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# Firewall profile declaring allowed_overrides so a runtime overrides file can
# append accept rules (allow_tcp_ports / allow_udp_ports). Used to prove that an
# override value changes real applied nftables state.
make_profile_firewall_overridable() {
  local name="$1" table="$2" dest="$3"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-firewall.json"], "templates": [],
  "allowed_overrides": ["allow_tcp_ports", "allow_udp_ports"]
}
EOJSON
  cat > "${dir}/actions/00-firewall.json" <<EOJSON
{
  "steps": [
    { "id": "configure-fw", "plugin": "firewall", "config": {
        "backend": "nftables", "family": "inet", "table": "${table}",
        "managed_dest": "${dest}",
        "policies": [{ "chain": "input", "policy": "drop" }],
        "rules": [
          { "chain": "input", "in_interface": "lo", "action": "accept" },
          { "chain": "input", "ct_states": ["established", "related"], "action": "accept" },
          { "chain": "input", "proto": "tcp", "port": 22, "action": "accept" },
          { "chain": "input", "proto": "icmp", "action": "accept" }
        ] } },
    { "id": "reload-nftables", "plugin": "service",
      "config": { "name": "nftables", "enabled": true, "state": "restarted" } }
  ]
}
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# ─── Template + service (restart_policy on_change | always) ──────────────────
make_profile_template_service() {
  local name="$1" template_dest="$2" content="$3" svc_name="$4" policy="${5:-on_change}"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  local restart_policy='{ "type": "on_change", "steps": ["deploy-config"] }'
  if [[ "${policy}" == "always" ]]; then
    restart_policy='{ "type": "always" }'
  fi
  mkdir -p "${dir}/actions" "${dir}/templates"
  printf '%b' "${content}" > "${dir}/templates/config.tmpl"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-config.json"], "templates": ["templates/config.tmpl"]
}
EOJSON
  cat > "${dir}/actions/00-config.json" <<EOJSON
{
  "steps": [
    { "id": "deploy-config", "plugin": "template", "config": {
        "src": "templates/config.tmpl", "dest": "${template_dest}", "mode": "0600" } },
    { "id": "reload-service", "plugin": "service", "config": {
        "name": "${svc_name}", "enabled": true, "state": "reloaded",
        "restart_policy": ${restart_policy} } }
  ]
}
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# ─── Service only (various states) ───────────────────────────────────────────
make_profile_service() {
  local name="$1" svc_name="$2" state="$3" enabled="$4"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-service.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-service.json" <<EOJSON
{ "steps": [{ "id": "manage-service", "plugin": "service",
  "config": { "name": "${svc_name}", "enabled": ${enabled}, "state": "${state}" } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# Package install + restart of the unit that package provides, in one profile.
# On rollback the package step purges the package (its 'before' has it absent),
# removing the unit file before the deferred service-restore runs.
make_profile_package_service() {
  local name="$1" pkg="$2" unit="$3"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-pkg-svc.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-pkg-svc.json" <<EOJSON
{
  "steps": [
    { "id": "install-${pkg}", "plugin": "packages",
      "config": { "update": "once", "install": ["${pkg}"] } },
    { "id": "restart-${unit}", "plugin": "service",
      "config": { "name": "${unit}", "enabled": true, "state": "restarted" } }
  ]
}
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# Profile with a failing service step (triggers auto-rollback of the good step).
make_profile_with_failing_step() {
  local name="$1" good_dest="$2" content="$3"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions" "${dir}/templates"
  printf '%b' "${content}" > "${dir}/templates/config.tmpl"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-steps.json"], "templates": ["templates/config.tmpl"]
}
EOJSON
  cat > "${dir}/actions/00-steps.json" <<EOJSON
{
  "steps": [
    { "id": "good-step", "plugin": "template", "config": {
        "src": "templates/config.tmpl", "dest": "${good_dest}", "mode": "0644" } },
    { "id": "bad-step", "plugin": "service", "config": {
        "name": "nonexistent-service-hardline-test-xyzzy", "state": "restarted" } }
  ]
}
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# Template profile with allowed_overrides (for overrides verify-path scenarios).
# After calling, the caller may write "${dir}/profile.overrides.json" and it does
# NOT invalidate the signature (it is excluded from the signed manifest).
make_profile_with_allowed_overrides() {
  local name="$1" dest="$2" content="$3" allowed_csv="$4"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions" "${dir}/templates"
  printf '%b' "${content}" > "${dir}/templates/config.tmpl"

  local allowed_json="[" first=true name_i
  for name_i in ${allowed_csv}; do
    if [[ "${first}" == "true" ]]; then first=false; else allowed_json+=", "; fi
    allowed_json+="\"${name_i}\""
  done
  allowed_json+="]"

  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-template.json"], "templates": ["templates/config.tmpl"],
  "allowed_overrides": ${allowed_json}
}
EOJSON
  cat > "${dir}/actions/00-template.json" <<EOJSON
{ "steps": [{ "id": "deploy-config", "plugin": "template",
  "config": { "src": "templates/config.tmpl", "dest": "${dest}", "mode": "0644" } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# Profile with a high min_hardline version gate.
make_profile_min_version() {
  local name="$1" min_ver="$2"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "${min_ver}",
  "actions": ["actions/00-pkg.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-pkg.json" <<EOJSON
{ "steps": [{ "id": "s1", "plugin": "packages", "config": { "install": ["tree"] } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# File meta: stamp metadata on an existing path.
# $1=name $2=path $3=mode $4=owner $5=group $6=immutable $7=append_only
# Empty fields are omitted; $6/$7 are JSON booleans ("true"/"false"/"").
make_profile_file_meta() {
  local name="$1" path="$2" mode="${3:-}" owner="${4:-}" group="${5:-}" immutable="${6:-}" append_only="${7:-}"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"

  local cfg="\"path\": \"${path}\""
  [[ -n "${mode}" ]]        && cfg+=", \"mode\": \"${mode}\""
  [[ -n "${owner}" ]]       && cfg+=", \"owner\": \"${owner}\""
  [[ -n "${group}" ]]       && cfg+=", \"group\": \"${group}\""
  [[ -n "${immutable}" ]]   && cfg+=", \"immutable\": ${immutable}"
  [[ -n "${append_only}" ]] && cfg+=", \"append_only\": ${append_only}"

  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-file-meta.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-file-meta.json" <<EOJSON
{ "steps": [{ "id": "stamp-meta", "plugin": "file_meta", "config": { ${cfg} } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# File meta with a verbatim path value injected into the JSON, for path-rejection
# tests (relative/traversal/control-char/non-ASCII). $2 is inserted as-is.
make_profile_file_meta_badpath() {
  local name="$1" json_path="$2"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-file-meta.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-file-meta.json" <<EOJSON
{ "steps": [{ "id": "stamp-meta", "plugin": "file_meta",
  "config": { "path": "${json_path}", "mode": "0600" } }] }
EOJSON
  sign_profile "${dir}"
  echo "${dir}"
}

# Unsigned/static raw-profile helpers for verify-rejection cases.
# Writes a profile.json + a single packages action; does NOT sign.
make_raw_profile() {
  local name="$1" os_family="${2:-ubuntu}" os_version="${3:-24.04}" min_hl="${4:-0.0.1}"
  local dir="${DYNAMIC_PROFILES_DIR}/${name}"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<EOJSON
{
  "id": "${name}", "display_name": "Test: ${name}", "version": "1.0.0",
  "os": { "family": "${os_family}", "version": "${os_version}", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "${min_hl}",
  "actions": ["actions/00-pkg.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-pkg.json" <<EOJSON
{ "steps": [{ "id": "s1", "plugin": "packages", "config": { "install": ["tree"] } }] }
EOJSON
  echo "${dir}"
}
