package profile

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// bundleProfile builds a profile straight from the byte snapshot a passed
// integrity check would have produced, which is the only way a profile is
// constructed at runtime.
func bundleProfile(t *testing.T, files map[string]string) *Profile {
	t.Helper()
	snapshot := make(map[string][]byte, len(files))
	for rel, content := range files {
		snapshot[rel] = []byte(content)
	}
	p, err := LoadFromBundle("/srv/profile", snapshot)
	if err != nil {
		t.Fatalf("LoadFromBundle failed: %v", err)
	}
	return p
}

func TestAffirm_RequiresLoadedProfilePath(t *testing.T) {
	p := &Profile{}
	err := p.Affirm()
	if err == nil {
		t.Fatal("expected Affirm to fail when profile path is empty")
	}
	if !strings.Contains(err.Error(), "load profile before validation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAffirm_UsesLoadedProfileBytes(t *testing.T) {
	p := bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "broken-profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": [],
  "allowed_overrides": []
}`,
	})

	err := p.Affirm()
	if err == nil {
		t.Fatal("expected Affirm to fail for invalid loaded profile")
	}
	if !strings.Contains(err.Error(), "profile validation failed") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestAffirm_SucceedsForValidLoadedProfile(t *testing.T) {
	p := bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/ok.json"],
  "templates": [],
  "allowed_overrides": []
}`,
		"actions/ok.json": `{
  "steps": [
    {
      "id": "pkg",
      "plugin": "packages_apt",
      "config": {"install": ["curl"]}
    }
  ]
}`,
	})

	if err := p.Affirm(); err != nil {
		t.Fatalf("expected Affirm success, got %v", err)
	}
}

func TestAffirm_ValidatesOSDeclaration(t *testing.T) {
	cases := []struct {
		name    string
		family  string
		version string
		wantErr bool
	}{
		{name: "major-only version", family: "rocky", version: "9"},
		{name: "point version", family: "ubuntu", version: "24.04"},
		{name: "empty family", family: "", version: "9", wantErr: true},
		{name: "malformed family", family: "rocky linux", version: "9", wantErr: true},
		{name: "empty version", family: "rocky", version: "", wantErr: true},
		{name: "malformed version", family: "rocky", version: "9.x", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := bundleProfile(t, map[string]string{
				"profile.json": fmt.Sprintf(`{
  "id": "os-validation",
  "display_name": "OS Validation",
  "version": "1.0.0",
  "os": {"family": %q, "version": %q, "variant": "server"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": [],
  "allowed_overrides": []
}`, tc.family, tc.version),
			})

			err := p.Affirm()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "profile validation failed") {
					t.Fatalf("expected OS schema validation error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected valid OS declaration, got %v", err)
			}
		})
	}
}

func TestAffirm_ProfileReadAndDecodeErrors(t *testing.T) {
	missing := &Profile{profilePath: "/srv/profile"}
	if err := missing.Affirm(); err == nil || !strings.Contains(err.Error(), "read profile json") {
		t.Fatalf("expected read profile json error, got %v", err)
	}

	invalid := &Profile{profilePath: "/srv/profile", files: map[string][]byte{"profile.json": []byte("{bad-json")}}
	if err := invalid.Affirm(); err == nil || !strings.Contains(err.Error(), "decode profile json") {
		t.Fatalf("expected decode profile json error, got %v", err)
	}
}

func TestAffirm_SchemaReadAndParseErrors(t *testing.T) {
	p := bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": [],
  "allowed_overrides": []
}`,
	})

	setSchemaFSForTest(t, fstest.MapFS{})
	if err := p.Affirm(); err == nil {
		t.Fatal("expected schema read failure")
	}

	setSchemaFSForTest(t, fstest.MapFS{
		"profile.schema.json": &fstest.MapFile{Data: []byte("{not-json")},
	})
	if err := p.Affirm(); err == nil {
		t.Fatal("expected invalid schema parse failure")
	}
}

func TestAffirm_ActionFileErrors(t *testing.T) {
	t.Run("action file outside the signed set", func(t *testing.T) {
		// LoadFromBundle already refuses this, so Affirm is exercised against a
		// hand-built profile: the check has to hold on its own.
		p := &Profile{
			profilePath: "/srv/profile",
			Actions:     []string{"actions/missing.json"},
			files: map[string][]byte{"profile.json": []byte(`{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/missing.json"],
  "templates": [],
  "allowed_overrides": []
}`)},
		}
		if err := p.Affirm(); err == nil || !strings.Contains(err.Error(), "not covered by the signed manifest") {
			t.Fatalf("expected uncovered action file error, got %v", err)
		}
	})

	t.Run("invalid action file", func(t *testing.T) {
		p := &Profile{
			profilePath: "/srv/profile",
			Actions:     []string{"actions/invalid.json"},
			files: map[string][]byte{
				"profile.json": []byte(`{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/invalid.json"],
  "templates": [],
  "allowed_overrides": []
}`),
				"actions/invalid.json": []byte("{bad-json"),
			},
		}
		if err := p.Affirm(); err == nil || !strings.Contains(err.Error(), "decode action file") {
			t.Fatalf("expected action file decode error, got %v", err)
		}
	})
}

// TestSchemasLoadFromEmbeddedFS makes no assumption about a source tree on
// disk: a release archive ships the binary alone, so this is what proves a
// released hardline can still validate a profile.
func TestSchemasLoadFromEmbeddedFS(t *testing.T) {
	for _, name := range []string{profileSchemaName, actionFileSchemaName} {
		if _, err := loadResolvedSchema(name); err != nil {
			t.Fatalf("load embedded schema %q: %v", name, err)
		}
	}
}

func TestAffirm_ValidatesActionFiles(t *testing.T) {
	p := bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/invalid.json"],
  "templates": [],
  "allowed_overrides": []
}`,
		"actions/invalid.json": `{
  "steps": [
    {
      "id": "svc",
      "plugin": "service",
      "name": "ssh"
    }
  ]
}`,
	})

	err := p.Affirm()
	if err == nil || !strings.Contains(err.Error(), "action file validation failed") {
		t.Fatalf("expected action schema validation error, got %v", err)
	}
}

func TestAffirm_ValidatesDeclaredOverrides(t *testing.T) {
	p := bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": [],
  "allowed_overrides": ["ssh_port", "ssh_port"]
}`,
	})

	err := p.Affirm()
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate allowed_overrides error, got %v", err)
	}
}

func setSchemaFSForTest(t *testing.T, fsys fs.FS) {
	t.Helper()
	prev := schemaFS
	schemaFS = fsys
	t.Cleanup(func() {
		schemaFS = prev
	})
}

// TestAffirm_RejectsPluginConfigInjection pins the schema layer of the
// injection defence: a hostile value must fail at verify, before hardline
// connects to any host, not later when the plugin builds a root command.
func TestAffirm_RejectsPluginConfigInjection(t *testing.T) {
	cases := map[string]string{
		"service": `{"id":"s","plugin":"service","config":{"name":"ssh$(touch /tmp/hardline-pwn)"}}`,
		"file_meta path": `{"id":"s","plugin":"file_meta",
			"config":{"path":"/etc/99-hardline$(id).conf","mode":"0600"}}`,
		"file_meta owner": `{"id":"s","plugin":"file_meta",
			"config":{"path":"/etc/shadow","owner":"root;id"}}`,
		"template dest": `{"id":"s","plugin":"template",
			"config":{"src":"templates/c.tmpl","dest":"/etc/99-hardline` + "`id`" + `.conf"}}`,
		"template src": `{"id":"s","plugin":"template",
			"config":{"src":"../shared/c.tmpl","dest":"/etc/99-hardline.conf"}}`,
		"firewall dest": `{"id":"s","plugin":"firewall",
			"config":{"managed_dest":"/etc/nftables.d/99-hardline$(id).nft"}}`,
		"firewall table carrying grammar": `{"id":"s","plugin":"firewall",
			"config":{"main_config":"/etc/nftables.conf","table":"filter { }; include \"/tmp/evil.nft\""}}`,
		"firewall interface closing its quote": `{"id":"s","plugin":"firewall",
			"config":{"main_config":"/etc/nftables.conf",
				"rules":[{"chain":"input","action":"accept","in_interface":"lo\" accept; iif \"eth0"}]}}`,
		"firewall source as a second statement": `{"id":"s","plugin":"firewall",
			"config":{"main_config":"/etc/nftables.conf",
				"rules":[{"chain":"input","action":"accept","source":"10.0.0.1; drop"}]}}`,
		"firewall reject as a chain policy": `{"id":"s","plugin":"firewall",
			"config":{"main_config":"/etc/nftables.conf",
				"policies":[{"chain":"input","policy":"reject"}]}}`,
		"firewall unknown config key": `{"id":"s","plugin":"firewall",
			"config":{"main_config":"/etc/nftables.conf","flush_ruleset":true}}`,
		"packages_apt install":  `{"id":"s","plugin":"packages_apt","config":{"install":["curl;id"]}}`,
		"packages_dnf4 install": `{"id":"s","plugin":"packages_dnf4","config":{"install":["curl;id"]}}`,
	}

	for name, step := range cases {
		t.Run(name, func(t *testing.T) {
			p := bundleProfile(t, map[string]string{
				"profile.json": `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/a.json"],
  "templates": []
}`,
				"actions/a.json": `{"steps":[` + step + `]}`,
			})

			if err := p.Affirm(); err == nil {
				t.Fatal("expected the hostile step to be rejected at verify")
			}
		})
	}
}

// TestAffirm_AcceptsOrdinaryPluginConfig guards the same patterns against
// being so tight that a real profile stops validating.
func TestAffirm_AcceptsOrdinaryPluginConfig(t *testing.T) {
	p := bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/a.json"],
  "templates": []
}`,
		"actions/a.json": `{"steps":[
  {"id":"svc","plugin":"service","config":{"name":"getty@tty1.service","state":"started"}},
  {"id":"fm","plugin":"file_meta","config":{"path":"/etc/shadow","owner":"root","group":"shadow","mode":"0640"}},
  {"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/ssh/sshd_config.d/99-hardline.conf","mode":"0600"}},
  {"id":"fw","plugin":"firewall","config":{"main_config":"/etc/nftables.conf","managed_dest":"/etc/nftables.d/99-hardline.nft"}},
  {"id":"pkg","plugin":"packages_dnf4","config":{"install":["curl","libssl3"],"purge":["telnet"]}}
]}`,
	})

	if err := p.Affirm(); err != nil {
		t.Fatalf("expected an ordinary profile to validate, got %v", err)
	}
}

// graphProfile builds a two-action-file profile so the step graph is checked
// across files, which is the order a run executes them in.
func graphProfile(t *testing.T, first, second string) *Profile {
	t.Helper()
	return bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "graph-profile",
  "display_name": "Graph Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/a.json", "actions/b.json"],
  "templates": []
}`,
		"actions/a.json": `{"steps":[` + first + `]}`,
		"actions/b.json": `{"steps":[` + second + `]}`,
	})
}

func TestAffirm_RejectsBrokenStepGraph(t *testing.T) {
	const watcher = `{"id":"svc","plugin":"service","config":{"name":"sshd.service","state":"reloaded",
		"restart_policy":{"type":"on_change","steps":["tpl"]}}}`

	cases := []struct {
		name   string
		first  string
		second string
		want   string
	}{
		{
			name:   "duplicate id across action files",
			first:  `{"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/one.conf","mode":"0600"}}`,
			second: `{"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/two.conf","mode":"0600"}}`,
			want:   "already declared by an earlier step",
		},
		{
			name:   "empty id",
			first:  `{"id":"  ","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/one.conf","mode":"0600"}}`,
			second: `{"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/two.conf","mode":"0600"}}`,
			want:   "has an empty id",
		},
		{
			name:   "padded id",
			first:  `{"id":" tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/one.conf","mode":"0600"}}`,
			second: `{"id":"other","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/two.conf","mode":"0600"}}`,
			want:   "leading or trailing whitespace",
		},
		{
			name:   "watches unknown step",
			first:  `{"id":"other","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/one.conf","mode":"0600"}}`,
			second: watcher,
			want:   `watches unknown step "tpl"`,
		},
		{
			name:   "watches a later step",
			first:  watcher,
			second: `{"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/one.conf","mode":"0600"}}`,
			want:   "which runs after it",
		},
		{
			name:  "watches itself",
			first: `{"id":"svc","plugin":"service","config":{"name":"sshd.service","state":"reloaded","restart_policy":{"type":"on_change","steps":["svc"]}}}`,
			second: `{"id":"tpl","plugin":"template",
				"config":{"src":"templates/c.tmpl","dest":"/etc/one.conf","mode":"0600"}}`,
			want: "watches itself",
		},
		{
			name:  "empty watched id",
			first: `{"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/one.conf","mode":"0600"}}`,
			second: `{"id":"svc","plugin":"service","config":{"name":"sshd.service","state":"reloaded",
				"restart_policy":{"type":"on_change","steps":[" "]}}}`,
			want: "empty step id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := graphProfile(t, tc.first, tc.second).Affirm()
			if err == nil {
				t.Fatal("expected the broken step graph to be rejected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAffirm_AcceptsStepWatchingAnEarlierFile(t *testing.T) {
	p := graphProfile(t,
		`{"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/ssh/sshd_config.d/99-hardline.conf","mode":"0600"}}`,
		`{"id":"svc","plugin":"service","config":{"name":"sshd.service","state":"reloaded",
			"restart_policy":{"type":"on_change","steps":["tpl"]}}}`)

	if err := p.Affirm(); err != nil {
		t.Fatalf("expected a well-formed step graph to validate, got %v", err)
	}
}

// ledgerProfile builds a profile with two steps and whatever ledger the case
// wants to make claims with.
func ledgerProfile(t *testing.T, ledger string) *Profile {
	t.Helper()
	return bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "ledger-profile",
  "display_name": "Ledger Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/a.json"],
  "templates": [],
  "coverage_ledger": "coverage.json"
}`,
		"actions/a.json": `{"steps":[
  {"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/one.conf","mode":"0600"}},
  {"id":"svc","plugin":"service","config":{"name":"sshd.service","state":"started"}}
]}`,
		"coverage.json": ledger,
	})
}

const ledgerBoth = `{"controls":[
  {"hardline_id":"HL-0001","desired_state":"the drop-in is present at 0600",
   "source_title":"sshd_config(5)","source_url":"https://man.openbsd.org/sshd_config",
   "source_version_or_commit":"OpenSSH 9.6","retrieved_at":"2026-08-12",
   "implementation_actions":["tpl"],"status":"implemented","tests":["itest: ssh-reload-rollback"],"copied_code":false},
  {"hardline_id":"HL-0002","desired_state":"sshd is running",
   "source_title":"sshd(8)","source_url":"https://man.openbsd.org/sshd",
   "source_version_or_commit":"OpenSSH 9.6","retrieved_at":"2026-08-12",
   "implementation_actions":["svc"],"status":"implemented","tests":[],"copied_code":false}
]}`

func TestAffirm_AcceptsACompleteCoverageLedger(t *testing.T) {
	if err := ledgerProfile(t, ledgerBoth).Affirm(); err != nil {
		t.Fatalf("expected a complete ledger to validate, got %v", err)
	}
}

func TestAffirm_RejectsABrokenCoverageLedger(t *testing.T) {
	cases := []struct {
		name   string
		ledger string
		want   string
	}{
		{
			name:   "a step nobody claims",
			ledger: `{"controls":[{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","implementation_actions":["tpl"],"status":"implemented","copied_code":false}]}`,
			want:   `does not account for step(s): svc`,
		},
		{
			name:   "unsupported status",
			ledger: `{"controls":[{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","implementation_actions":["tpl","svc"],"status":"mostly","copied_code":false}]}`,
			want:   "unsupported status",
		},
		{
			name:   "copied code",
			ledger: `{"controls":[{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","implementation_actions":["tpl","svc"],"status":"implemented","copied_code":true}]}`,
			want:   "copied_code",
		},
		{
			name:   "missing source",
			ledger: `{"controls":[{"hardline_id":"HL-0001","desired_state":"a state","source_title":"","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","implementation_actions":["tpl","svc"],"status":"implemented","copied_code":false}]}`,
			want:   "empty source_title",
		},
		{
			name:   "retrieved_at is not a date",
			ledger: `{"controls":[{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"last tuesday","implementation_actions":["tpl","svc"],"status":"implemented","copied_code":false}]}`,
			want:   "not a 2006-01-02 date",
		},
		{
			name:   "a deferred control that still names steps",
			ledger: `{"controls":[{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","implementation_actions":["tpl","svc"],"status":"deferred","copied_code":false}]}`,
			want:   `is "deferred" but names implementation_actions`,
		},
		{
			name: "two controls claiming one step",
			ledger: `{"controls":[
				{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","implementation_actions":["tpl","svc"],"status":"implemented","copied_code":false},
				{"hardline_id":"HL-0002","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","implementation_actions":["svc"],"status":"implemented","copied_code":false}]}`,
			want: `claimed by both control "HL-0001" and control "HL-0002"`,
		},
		{
			name: "a control declared twice",
			ledger: `{"controls":[
				{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","implementation_actions":["tpl","svc"],"status":"implemented","copied_code":false},
				{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u","source_version_or_commit":"v","retrieved_at":"2026-08-12","status":"deferred","copied_code":false}]}`,
			want: `declares control "HL-0001" twice`,
		},
		{
			name:   "no controls at all",
			ledger: `{"controls":[]}`,
			want:   "declares no controls",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ledgerProfile(t, tc.ledger).Affirm()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAffirm_RejectsALedgerNamingAnUnknownStep(t *testing.T) {
	ledger := `{"controls":[{"hardline_id":"HL-0001","desired_state":"a state","source_title":"t","source_url":"u",
		"source_version_or_commit":"v","retrieved_at":"2026-08-12",
		"implementation_actions":["tpl","svc","ghost"],"status":"implemented","copied_code":false}]}`
	err := ledgerProfile(t, ledger).Affirm()
	if err == nil || !strings.Contains(err.Error(), `names step "ghost"`) {
		t.Fatalf("expected the unknown step to be refused, got %v", err)
	}
}

func TestAffirm_IgnoresAnAbsentCoverageLedger(t *testing.T) {
	p := bundleProfile(t, map[string]string{
		"profile.json": `{
  "id": "no-ledger",
  "display_name": "No Ledger",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": []
}`,
	})
	if err := p.Affirm(); err != nil {
		t.Fatalf("a profile that claims no coverage is still a valid profile, got %v", err)
	}
}
