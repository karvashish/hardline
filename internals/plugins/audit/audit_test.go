package audit

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

const sampleRules = `## hardline audit rules
-D
-b 8192
-w /etc/passwd -p wa -k identity
-a always,exit -F arch=b64 -S adjtimex -k time_change
-w /etc/audit/ -p wa -k audit_config
-e 1
`

type hostStub struct {
	cmds    *[]string
	loaded  string
	files   map[string]string
	runRoot func(string) error
	statErr bool
	outErr  error
	writes  map[string]string
}

func (s hostStub) record(cmd string) {
	if s.cmds != nil {
		*s.cmds = append(*s.cmds, cmd)
	}
}

func (s hostStub) RunRoot(cmd string) error {
	s.record(cmd)
	if s.runRoot != nil {
		return s.runRoot(cmd)
	}
	if strings.HasPrefix(cmd, "test -e ") {
		path := strings.Trim(strings.TrimPrefix(cmd, "test -e "), "'\"")
		if _, ok := s.files[path]; ok {
			return nil
		}
		return errors.New("missing")
	}
	return nil
}

func (s hostStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return "", s.RunRoot(cmd)
}

func (s hostStub) RunRootWithOutput(cmd string) (string, error) {
	s.record(cmd)
	if s.outErr != nil {
		return "", s.outErr
	}
	if strings.Contains(cmd, listCmd) {
		return s.loaded, nil
	}
	if strings.HasPrefix(cmd, "stat ") {
		return "640 10", nil
	}
	return "", nil
}

func (s hostStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("not found") }

func (s hostStub) ReadRootFile(path string) (string, error) {
	if s.statErr {
		return "", errors.New("boom")
	}
	return s.files[path], nil
}

func (s hostStub) WriteRootFile(path string, data []byte, _ os.FileMode) error {
	s.record("write " + path)
	if s.writes != nil {
		s.writes[path] = string(data)
	}
	return nil
}

const dest = "/etc/audit/rules.d/99-hardline.rules"

func testProfile(t *testing.T, rules string) *profile.Profile {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/templates", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/templates/audit.rules", []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/profile.json", []byte(`{
  "id": "audit-test", "display_name": "Audit Test", "version": "1.0.0",
  "os": {"family": "rocky", "version": "9", "variant": "server"},
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": [], "templates": ["templates/audit.rules"]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(dir)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

func spec() *Spec {
	return &Spec{Src: "templates/audit.rules", Dest: dest, Mode: "0640"}
}

func TestRuleKeys(t *testing.T) {
	got := RuleKeys([]byte(sampleRules))
	want := []string{"audit_config", "identity", "time_change"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (sorted, deduplicated)", got, want)
		}
	}
	if keys := RuleKeys([]byte("-w /etc/passwd -p wa\n")); len(keys) != 0 {
		t.Fatalf("a rules file with no keys has no keys, got %v", keys)
	}
	// auditctl prints the keys back in its own -k=value form.
	if keys := RuleKeys([]byte("-w /etc/passwd -p wa -k=identity\n")); len(keys) != 1 || keys[0] != "identity" {
		t.Fatalf("got %v", keys)
	}
}

func TestValidateSpec(t *testing.T) {
	cases := map[string]*Spec{
		"nil":            nil,
		"no src":         {Dest: dest},
		"no dest":        {Src: "templates/audit.rules"},
		"unmanaged dest": {Src: "templates/audit.rules", Dest: "/etc/audit/rules.d/audit.rules"},
		"wrong dir":      {Src: "templates/audit.rules", Dest: "/etc/hardline.d/99-hardline.rules"},
		"bad mode":       {Src: "templates/audit.rules", Dest: dest, Mode: "wide-open"},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateSpec(s); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if err := validateSpec(spec()); err != nil {
		t.Fatalf("expected a valid spec to pass, got %v", err)
	}
}

func TestApplyWritesAndLoads(t *testing.T) {
	var cmds []string
	writes := map[string]string{}
	host := hostStub{cmds: &cmds, writes: writes, files: map[string]string{},
		loaded: "-w /etc/passwd -p wa -k identity\n-a always,exit -k time_change\n-w /etc/audit/ -k audit_config\n"}

	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec())
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "write "+dest) {
		t.Fatalf("rules file was not written: %v", cmds)
	}
	if !strings.Contains(joined, loadCmd) {
		t.Fatalf("rules were written but never loaded: %v", cmds)
	}
	if writes[dest] != sampleRules {
		t.Fatalf("wrote unexpected content: %q", writes[dest])
	}
}

func TestApplyLoadsWhenTheFileIsAlreadyCorrectButUnloaded(t *testing.T) {
	// This is the failure the plugin exists to prevent: rules sitting on disk
	// that the running kernel has never been told about.
	var cmds []string
	host := hostStub{cmds: &cmds, files: map[string]string{dest: sampleRules}, loaded: ""}
	if err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec()); err == nil {
		t.Fatal("expected the unverifiable load to fail on this stub")
	}
	if !strings.Contains(strings.Join(cmds, "\n"), loadCmd) {
		t.Fatalf("expected a load attempt, got %v", cmds)
	}
}

func TestApplyIsANoOpWhenLoaded(t *testing.T) {
	var cmds []string
	host := hostStub{cmds: &cmds, files: map[string]string{dest: sampleRules},
		loaded: "-k identity\n-k time_change\n-k audit_config\n"}
	if err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec()); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	if strings.Contains(joined, loadCmd) {
		t.Fatalf("an aligned host must not be reloaded: %v", cmds)
	}
	if strings.Contains(joined, "write ") {
		t.Fatalf("an aligned host must not be rewritten: %v", cmds)
	}
}

func TestApplyRejectsRulesWithNoKeys(t *testing.T) {
	host := hostStub{files: map[string]string{}}
	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, "-w /etc/passwd -p wa\n")}, spec())
	if err == nil || !strings.Contains(err.Error(), "no -k keys") {
		t.Fatalf("expected keyless rules to be refused, got %v", err)
	}
}

func TestApplyReportsAnUnverifiedLoad(t *testing.T) {
	host := hostStub{files: map[string]string{}, loaded: "-k identity\n"}
	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec())
	if err == nil || !strings.Contains(err.Error(), "did not take effect") {
		t.Fatalf("expected the missing keys to be reported, got %v", err)
	}
	if !strings.Contains(err.Error(), "time_change") {
		t.Fatalf("the error must name what is missing, got %v", err)
	}
}

func TestApplyFailures(t *testing.T) {
	p := testProfile(t, sampleRules)
	if err := Apply(pluginapi.Context{Host: hostStub{}}, spec()); err == nil {
		t.Fatal("expected a profile-required error")
	}
	if err := Apply(pluginapi.Context{Profile: p}, spec()); err == nil {
		t.Fatal("expected a host-required error")
	}
	if err := Apply(pluginapi.Context{Host: hostStub{}, Profile: p}, &Spec{Src: "templates/audit.rules", Dest: "/etc/passwd"}); err == nil {
		t.Fatal("expected an unmanaged dest to be refused")
	}
	if err := Apply(pluginapi.Context{Host: hostStub{}, Profile: p}, &Spec{Src: "nope.rules", Dest: dest}); err == nil {
		t.Fatal("expected an undeclared src to be refused")
	}
	if err := Apply(pluginapi.Context{Host: hostStub{}, Profile: p}, &Spec{Src: "templates/audit.rules", Dest: dest, Mode: "zzz"}); err == nil {
		t.Fatal("expected a bad mode to be refused")
	}

	t.Run("augenrules failure surfaces", func(t *testing.T) {
		host := hostStub{files: map[string]string{}, runRoot: func(cmd string) error {
			if strings.Contains(cmd, loadCmd) {
				return errors.New("boom")
			}
			return errors.New("missing")
		}}
		if err := Apply(pluginapi.Context{Host: host, Profile: p}, spec()); err == nil {
			t.Fatal("expected the load failure to surface")
		}
	})

	t.Run("auditctl failure surfaces", func(t *testing.T) {
		host := hostStub{files: map[string]string{}, outErr: errors.New("boom")}
		if err := Apply(pluginapi.Context{Host: host, Profile: p}, spec()); err == nil {
			t.Fatal("expected the policy read failure to surface")
		}
	})
}

func TestPlan(t *testing.T) {
	p := testProfile(t, sampleRules)

	t.Run("aligned", func(t *testing.T) {
		host := hostStub{files: map[string]string{dest: sampleRules},
			loaded: "-k identity\n-k time_change\n-k audit_config\n"}
		res, err := Plan(pluginapi.Context{Host: host, Profile: p}, spec())
		if err != nil {
			t.Fatalf("plan failed: %v", err)
		}
		if res.WillChange {
			t.Fatalf("an aligned host is no change: %+v", res)
		}
	})

	t.Run("file matches but policy is not loaded", func(t *testing.T) {
		host := hostStub{files: map[string]string{dest: sampleRules}, loaded: ""}
		res, err := Plan(pluginapi.Context{Host: host, Profile: p}, spec())
		if err != nil {
			t.Fatalf("plan failed: %v", err)
		}
		if !res.WillChange {
			t.Fatal("rules on disk that are not loaded are a change")
		}
		joined := strings.Join(res.Details, "\n")
		if !strings.Contains(joined, "already matches") || !strings.Contains(joined, "missing 3 rule key") {
			t.Fatalf("details do not explain the state: %s", joined)
		}
	})

	t.Run("file absent", func(t *testing.T) {
		host := hostStub{files: map[string]string{}}
		res, err := Plan(pluginapi.Context{Host: host, Profile: p}, spec())
		if err != nil {
			t.Fatalf("plan failed: %v", err)
		}
		if !res.WillChange || len(res.Diff) == 0 {
			t.Fatalf("expected a change with a diff, got %+v", res)
		}
		if !strings.Contains(strings.Join(res.Diff, "\n"), "created") {
			t.Fatalf("diff=%v", res.Diff)
		}
	})

	if _, err := Plan(pluginapi.Context{Host: hostStub{}}, spec()); err == nil {
		t.Fatal("expected a profile-required error")
	}
	if _, err := Plan(pluginapi.Context{Profile: p}, spec()); err == nil {
		t.Fatal("expected a host-required error")
	}
	if _, err := Plan(pluginapi.Context{Host: hostStub{}, Profile: p}, &Spec{Src: "templates/audit.rules", Dest: "/etc/passwd"}); err == nil {
		t.Fatal("expected an unmanaged dest to be refused")
	}
	if _, err := Plan(pluginapi.Context{Host: hostStub{}, Profile: p}, &Spec{Src: "nope", Dest: dest}); err == nil {
		t.Fatal("expected an undeclared src to be refused")
	}
	if _, err := Plan(pluginapi.Context{Host: hostStub{outErr: errors.New("boom")}, Profile: p}, spec()); err == nil {
		t.Fatal("expected the policy read failure to surface")
	}
}

func TestCapture(t *testing.T) {
	host := hostStub{files: map[string]string{dest: sampleRules}}
	rec, err := Capture(pluginapi.Context{Host: host}, "audit", spec())
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	if rec.RollbackMode != pluginapi.ModeDeterministic {
		t.Fatalf("rollback mode is %q", rec.RollbackMode)
	}
	if len(rec.Objects) != 1 || rec.Objects[0].File == nil || rec.Objects[0].File.Path != dest {
		t.Fatalf("unexpected record: %+v", rec)
	}

	if _, err := Capture(pluginapi.Context{}, "audit", spec()); err == nil {
		t.Fatal("expected a host-required error")
	}
	if _, err := Capture(pluginapi.Context{Host: host}, "audit", &Spec{Src: "x", Dest: "/etc/passwd"}); err == nil {
		t.Fatal("expected an unmanaged dest to be refused")
	}
}

func TestRestoreReloadsAfterPuttingTheFileBack(t *testing.T) {
	var cmds []string
	host := hostStub{cmds: &cmds, files: map[string]string{}}
	snap := pluginapi.FileSnapshot{
		Path:       dest,
		Existed:    true,
		Mode:       "640",
		ContentB64: base64.StdEncoding.EncodeToString([]byte("-w /etc/passwd -p wa -k old\n")),
	}
	if err := Restore(host, snap); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	writeAt := strings.Index(joined, "write "+dest)
	loadAt := strings.Index(joined, loadCmd)
	if writeAt < 0 || loadAt < 0 {
		t.Fatalf("expected both a restore and a reload, got %v", cmds)
	}
	// The reload has to follow the restore, or the kernel keeps running the
	// rules that were just taken off disk.
	if loadAt < writeAt {
		t.Fatalf("reload ran before the restore: %v", cmds)
	}

	if err := Restore(nil, snap); err == nil {
		t.Fatal("expected a host-required error")
	}

	failing := hostStub{files: map[string]string{}, runRoot: func(cmd string) error {
		if strings.Contains(cmd, loadCmd) {
			return errors.New("boom")
		}
		return nil
	}}
	if err := Restore(failing, snap); err == nil {
		t.Fatal("expected the reload failure to surface")
	}
}

func TestPluginWiring(t *testing.T) {
	p := Plugin()
	if p.Name != "audit" || !p.InternalValidation {
		t.Fatalf("unexpected plugin identity: %q internal=%v", p.Name, p.InternalValidation)
	}

	bad := profile.Step{ID: "a", Plugin: "audit", Config: map[string]any{"src": "x"}}
	if err := p.Apply(pluginapi.Context{}, bad); err == nil {
		t.Fatal("Apply must reject an invalid config")
	}
	if _, err := p.Plan(pluginapi.Context{}, bad); err == nil {
		t.Fatal("Plan must reject an invalid config")
	}
	if _, err := p.Capture(pluginapi.Context{}, bad); err == nil {
		t.Fatal("Capture must reject an invalid config")
	}

	if err := p.Rollback(hostStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectValidate}); err != nil {
		t.Fatalf("a validate record rolls back to nothing: %v", err)
	}
	if err := p.Rollback(hostStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); err == nil {
		t.Fatal("a file record with no snapshot must fail")
	}
	if err := p.Rollback(hostStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage}); err == nil {
		t.Fatal("this plugin cannot roll back a package")
	}
	if got := p.DetectConflict(hostStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage}); got != nil {
		t.Fatalf("expected no conflicts for a foreign kind, got %v", got)
	}
}
