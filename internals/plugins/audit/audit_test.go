package audit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

const sampleRules = `## hardline audit rules
-b 8192
-w /etc/passwd -p wa -k identity
-a always,exit -F arch=b64 -S adjtimex -F auid>=1000 -F auid!=4294967295 -k time_change
-w /etc/audit/ -p wa -k audit_config
-e 1
`

const loadedSample = `-w /etc/passwd -p wa -k identity
-a always,exit -F arch=b64 -S adjtimex -F auid>=1000 -F auid!=unset -F key=time_change
-w /etc/audit -p wa -k audit_config
`

type hostStub struct {
	absent  map[string]bool
	status  string
	cmds    *[]string
	loaded  string
	files   map[string]string
	mode    string
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
		if s.absent[path] {
			return errors.New("missing")
		}
		return nil
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
	if strings.Contains(cmd, statusCmd) {
		return s.status, nil
	}
	if strings.Contains(cmd, listCmd) {
		return s.loaded, nil
	}
	if strings.Contains(cmd, "stat -c ") {
		path := statPathFromCmd(cmd)
		content, ok := s.files[path]
		if !ok {
			return "stat: cannot stat '" + path + "': No such file or directory\nHL-RC:1\n", nil
		}
		mode := s.mode
		if mode == "" {
			mode = "640"
		}
		return fmt.Sprintf("HL-STAT:regular file|%s|root|root|%d\nHL-RC:0\n", mode, len(content)), nil
	}
	return "", nil
}

func statPathFromCmd(cmd string) string {
	end := strings.LastIndex(cmd, "'")
	if end < 0 {
		return ""
	}
	start := strings.LastIndex(cmd[:end], "'")
	if start < 0 {
		return ""
	}
	return cmd[start+1 : end]
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
	p, err := profile.LoadFromBundle(t.TempDir(), map[string][]byte{
		"profile.json": []byte(`{
  "id": "audit-test", "display_name": "Audit Test", "version": "1.0.0",
  "os": {"family": "rocky", "version": "9", "variant": "server"},
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": [], "templates": ["templates/audit.rules"]
}`),
		"templates/audit.rules": []byte(rules),
	})
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

func spec() *Spec {
	return &Spec{Src: "templates/audit.rules", Dest: dest, Mode: "0640"}
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
		loaded: loadedSample}

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
		loaded: loadedSample}
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

func TestApplyRewritesCorrectContentAtTheWrongMode(t *testing.T) {
	var cmds []string
	host := hostStub{cmds: &cmds, files: map[string]string{dest: sampleRules}, mode: "666",
		loaded: loadedSample}
	if err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec()); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "write "+dest) {
		t.Fatalf("a world-writable rules file must be rewritten: %v", cmds)
	}

	res, err := Plan(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec())
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if !res.WillChange {
		t.Fatalf("plan must report the mode drift: %+v", res)
	}
}

func TestApplyRejectsAFileWithNoRules(t *testing.T) {
	host := hostStub{files: map[string]string{}}
	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, "## nothing but comments\n-b 8192\n")}, spec())
	if err == nil || !strings.Contains(err.Error(), "declare no rules") {
		t.Fatalf("expected a ruleless file to be refused, got %v", err)
	}
}

func TestApplyReportsAnUnverifiedLoad(t *testing.T) {
	host := hostStub{files: map[string]string{}, loaded: "-w /etc/passwd -p wa -k identity\n"}
	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec())
	if err == nil || !strings.Contains(err.Error(), "did not take effect") {
		t.Fatalf("expected the missing rules to be reported, got %v", err)
	}
	if !strings.Contains(err.Error(), "time_change") {
		t.Fatalf("the error must name what is missing, got %v", err)
	}
}

func TestApplyRefusesARuleThatOnlySharesTheKey(t *testing.T) {
	host := hostStub{files: map[string]string{}, loaded: `-w /etc/shadow -p wa -k identity
-a always,exit -F arch=b64 -S adjtimex -F key=time_change
-w /etc/audit/ -p wa -k audit_config
`}
	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec())
	if err == nil || !strings.Contains(err.Error(), "did not take effect") {
		t.Fatalf("expected a same-key different-body rule to be caught, got %v", err)
	}
	if !strings.Contains(err.Error(), "/etc/passwd") {
		t.Fatalf("the error must name the rule that is really missing, got %v", err)
	}
}

func TestApplyRefusesADestructiveOrLockingPolicy(t *testing.T) {
	host := hostStub{files: map[string]string{}, loaded: loadedSample}

	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, "-D\n"+sampleRules)}, spec())
	if err == nil || !strings.Contains(err.Error(), "deletes every rule on the host") {
		t.Fatalf("expected -D to be refused, got %v", err)
	}

	err = Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules+"-e 2\n")}, spec())
	if err == nil || !strings.Contains(err.Error(), "locks the policy") {
		t.Fatalf("expected -e 2 to be refused, got %v", err)
	}
}

func TestApplyRefusesAnAbsentWatchPath(t *testing.T) {
	host := hostStub{files: map[string]string{}, loaded: loadedSample,
		absent: map[string]bool{"/etc/audit": true}}
	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec())
	if err == nil || !strings.Contains(err.Error(), "do not exist on this host") {
		t.Fatalf("expected the absent watch path to be named, got %v", err)
	}
	if !strings.Contains(err.Error(), "/etc/audit") {
		t.Fatalf("the error must name the path, got %v", err)
	}
}

func TestApplyRefusesALockedPolicy(t *testing.T) {
	host := hostStub{files: map[string]string{}, loaded: loadedSample, status: "enabled 2 failure 1 pid 900"}
	err := Apply(pluginapi.Context{Host: host, Profile: testProfile(t, sampleRules)}, spec())
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("expected a locked policy to be refused, got %v", err)
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
			loaded: loadedSample}
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
		if !strings.Contains(joined, "already matches") || !strings.Contains(joined, "missing 3 rule(s)") {
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
	if len(rec.Objects) != 2 || rec.Objects[0].File == nil || rec.Objects[0].File.Path != dest {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec.Objects[1].Kind != pluginapi.ObjectRuntimePolicy || rec.Objects[1].RuntimePolicy == nil {
		t.Fatalf("the loaded policy was not journalled: %+v", rec.Objects[1])
	}

	if _, err := Capture(pluginapi.Context{}, "audit", spec()); err == nil {
		t.Fatal("expected a host-required error")
	}
	if _, err := Capture(pluginapi.Context{Host: hostStub{outErr: errors.New("boom")}}, "audit", spec()); err == nil {
		t.Fatal("expected a failed policy read to refuse the capture")
	}
	if _, err := Capture(pluginapi.Context{Host: host}, "audit", &Spec{Src: "x", Dest: "/etc/passwd"}); err == nil {
		t.Fatal("expected an unmanaged dest to be refused")
	}
}

func TestCaptureSeesALoadThatLeavesTheFileAlone(t *testing.T) {
	host := hostStub{files: map[string]string{dest: sampleRules}}
	before, err := Capture(pluginapi.Context{Host: host}, "audit", spec())
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}

	after, err := Capture(pluginapi.Context{Host: hostStub{
		files:  map[string]string{dest: sampleRules},
		loaded: "-w /etc/passwd -p wa -k identity\n",
	}}, "audit", spec())
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}

	if !pluginapi.CapturesDiffer(before, after) {
		t.Fatal("a load that changed the kernel policy without touching the file was not journalled as a change")
	}
}

func TestRestoreReloadsAfterPuttingTheFileBack(t *testing.T) {
	var cmds []string
	host := hostStub{cmds: &cmds, files: map[string]string{}}
	snap := pluginapi.FileSnapshot{
		Path:       dest,
		Existed:    true,
		Mode:       "640",
		Owner:      "root",
		Group:      "root",
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
	if p.Name != "audit" {
		t.Fatalf("unexpected plugin identity: %q", p.Name)
	}

	bad := profile.Step{ID: "a", Plugin: "audit", Config: map[string]any{"src": "x"}}
	if err := p.Validate(bad, nil); err == nil {
		t.Fatal("Validate must reject an invalid config with no host in sight")
	}
	good := profile.Step{ID: "a", Plugin: "audit", Config: map[string]any{
		"src": "rules/hardline.rules", "dest": "/etc/audit/rules.d/99-hardline.rules", "mode": "0640"}}
	if err := p.Validate(good, nil); err != nil {
		t.Fatalf("Validate must accept a well-formed step: %v", err)
	}
	if err := p.Apply(pluginapi.Context{}, bad); err == nil {
		t.Fatal("Apply must reject an invalid config")
	}
	if _, err := p.Plan(pluginapi.Context{}, bad); err == nil {
		t.Fatal("Plan must reject an invalid config")
	}
	if _, err := p.Capture(pluginapi.Context{}, bad); err == nil {
		t.Fatal("Capture must reject an invalid config")
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

func TestParseRulesReconcilesBothSpellings(t *testing.T) {
	fileForm, err := ParseRules([]byte("-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time_change\n"))
	if err != nil {
		t.Fatalf("parse file form: %v", err)
	}
	listForm, err := ParseRules([]byte("-a always,exit -F arch=b64 -S adjtimex -S settimeofday -F key=time_change\n"))
	if err != nil {
		t.Fatalf("parse auditctl form: %v", err)
	}
	if fileForm[0].Canonical() != listForm[0].Canonical() {
		t.Fatalf("the same rule must compare equal:\n file: %s\n list: %s", fileForm[0].Canonical(), listForm[0].Canonical())
	}

	a, err := ParseRules([]byte("-w /etc/passwd -p wa -k identity\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	b, err := ParseRules([]byte("-w /etc/passwd -p aw -k identity\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a[0].Canonical() != b[0].Canonical() {
		t.Fatalf("permission order must not matter: %s vs %s", a[0].Canonical(), b[0].Canonical())
	}
}

func TestParseRulesReconcilesAuditctlRewrites(t *testing.T) {
	cases := []struct {
		name       string
		file, list string
	}{
		{
			name: "the unset login id sentinel",
			file: "-a always,exit -F arch=b64 -S adjtimex -F auid>=1000 -F auid!=4294967295 -k time_change\n",
			list: "-a always,exit -F arch=b64 -S adjtimex -F auid>=1000 -F auid!=unset -F key=time_change\n",
		},
		{
			name: "the unset login id sentinel printed as -1",
			file: "-a always,exit -F arch=b64 -S adjtimex -F auid!=4294967295 -k time_change\n",
			list: "-a always,exit -F arch=b64 -S adjtimex -F auid!=-1 -F key=time_change\n",
		},
		{
			name: "a directory watch's trailing separator",
			file: "-w /etc/audit/ -p wa -k audit_config\n",
			list: "-w /etc/audit -p wa -k audit_config\n",
		},
		{
			name: "a watch expanded into its syscall-rule form",
			file: "-w /etc/passwd -p wa -k identity\n",
			list: "-a always,exit -F path=/etc/passwd -F perm=wa -F key=identity\n",
		},
		{
			name: "a watch left at auditctl's default permissions",
			file: "-w /etc/passwd -k identity\n",
			list: "-w /etc/passwd -p rwxa -k identity\n",
		},
		{
			name: "the list and action written list-first",
			file: "-a exit,always -F arch=b64 -S adjtimex -k time_change\n",
			list: "-a always,exit -F arch=b64 -S adjtimex -F key=time_change\n",
		},
		{
			name: "a list-first watch expanded into its syscall-rule form",
			file: "-w /etc/passwd -p wa -k identity\n",
			list: "-a exit,always -F path=/etc/passwd -F perm=wa -F key=identity\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fileForm, err := ParseRules([]byte(tc.file))
			if err != nil {
				t.Fatalf("parse file form: %v", err)
			}
			listForm, err := ParseRules([]byte(tc.list))
			if err != nil {
				t.Fatalf("parse auditctl form: %v", err)
			}
			if fileForm[0].Canonical() != listForm[0].Canonical() {
				t.Fatalf("the same rule must compare equal:\n file: %s\n list: %s",
					fileForm[0].Canonical(), listForm[0].Canonical())
			}
		})
	}
}

func TestParseRulesKeepsANarrowedPathRuleASyscallRule(t *testing.T) {
	rules, err := ParseRules([]byte("-a always,exit -F path=/etc/passwd -F perm=wa -F auid>=1000 -F key=identity\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rules[0].Watch != "" {
		t.Fatalf("expected a syscall rule, got a watch on %q", rules[0].Watch)
	}

	watch, err := ParseRules([]byte("-w /etc/passwd -p wa -k identity\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rules[0].Canonical() == watch[0].Canonical() {
		t.Fatalf("a narrowed rule must not compare equal to a plain watch: %s", rules[0].Canonical())
	}
}

func TestParseRulesDistinguishesDifferentBodies(t *testing.T) {
	rules, err := ParseRules([]byte(`-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-a always,exit -F arch=b64 -S adjtimex -k time_change
-a always,exit -F arch=b32 -S adjtimex -k time_change
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	seen := map[string]struct{}{}
	for _, rule := range rules {
		seen[rule.Canonical()] = struct{}{}
	}
	if len(seen) != 4 {
		t.Fatalf("four different rules must not collapse, got %d: %v", len(seen), seen)
	}
}

func TestParseRulesSkipsControlLinesAndComments(t *testing.T) {
	rules, err := ParseRules([]byte("# a comment\n\n-D\n-b 8192\n-f 1\n-e 1\n-w /etc/passwd -p wa -k identity\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rules) != 1 || rules[0].Watch != "/etc/passwd" {
		t.Fatalf("expected only the watch rule, got %+v", rules)
	}
}

func TestParseRulesRefusesWhatItCannotRead(t *testing.T) {
	for _, line := range []string{
		"-w",
		"-p wa -k identity",
		"-a always,exit -S",
		"-z something",
		"-k orphan",
	} {
		if _, err := ParseRules([]byte(line + "\n")); err == nil {
			t.Fatalf("expected %q to be refused rather than silently skipped", line)
		}
	}
}

func TestParseRulesRefusesAnUnreadableListAndAction(t *testing.T) {
	for _, line := range []string{
		"-a always -S adjtimex -k t",
		"-a always,never -S adjtimex -k t",
		"-a exit,entry -S adjtimex -k t",
		"-a always,bogus -S adjtimex -k t",
		"-a always,exit,extra -S adjtimex -k t",
	} {
		if _, err := ParseRules([]byte(line + "\n")); err == nil {
			t.Fatalf("expected %q to be refused", line)
		}
	}
}

func TestMissingRulesIgnoresRulesThisProfileDoesNotOwn(t *testing.T) {
	want, err := ParseRules([]byte("-w /etc/passwd -p wa -k identity\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	loaded, err := ParseRules([]byte("-w /var/log/sudo.log -p wa -k sudo_log\n-w /etc/passwd -p wa -k identity\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if missing := MissingRules(loaded, want); len(missing) != 0 {
		t.Fatalf("another owner's extra rules are not drift, got %v", missing)
	}
}

func TestAuditEnabledLockedReadsTheStatusLine(t *testing.T) {
	cases := map[string]bool{
		"enabled 2 failure 1 pid 900 rate_limit 0": true,
		"enabled 1 failure 1 pid 900":              false,
		"enabled 0":                                false,
		"":                                         false,
		"enabled":                                  false,
		"AUDIT_STATUS: enabled=2 flag=1 pid=900":   true,
		"AUDIT_STATUS: enabled=1 flag=1 pid=900":   false,
		"AUDIT_STATUS: enabled=0 flag=1 rate_limit=0": false,
	}
	for status, want := range cases {
		if got := auditEnabledLocked(status); got != want {
			t.Fatalf("auditEnabledLocked(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestLoadedRulesTreatsNoRulesAsEmpty(t *testing.T) {
	host := hostStub{loaded: "No rules\n"}
	rules, err := loadedRules(host)
	if err != nil {
		t.Fatalf("loadedRules failed: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected an empty policy, got %v", rules)
	}
}

func TestRuleStringRendersBothKinds(t *testing.T) {
	rules, err := ParseRules([]byte("-w /etc/passwd -p wa -k identity\n-a always,exit -F arch=b64 -S adjtimex -k time_change\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := rules[0].String(); got != "-w /etc/passwd -p aw -k identity" {
		t.Fatalf("unexpected watch rendering: %q", got)
	}
	if got := rules[1].String(); got != "-a always,exit -F arch=b64 -S adjtimex -k time_change" {
		t.Fatalf("unexpected syscall rendering: %q", got)
	}
}

func TestLoadedRulesSkipsRulesItCannotModel(t *testing.T) {
	host := hostStub{loaded: "-z nonsense\n" + loadedSample}
	rules, err := loadedRules(host)
	if err != nil {
		t.Fatalf("a foreign rule must not fail the read: %v", err)
	}

	want, err := ParseRules([]byte(sampleRules))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if missing := MissingRules(rules, want); len(missing) > 0 {
		t.Fatalf("the modelled rules around it must still count, missing %v", missing)
	}

	failing := hostStub{outErr: errors.New("auditctl boom")}
	if _, err := loadedRules(failing); err == nil {
		t.Fatal("expected the read failure to surface")
	}
}

func TestLoadReportsAFailedAugenrules(t *testing.T) {
	want, err := ParseRules([]byte(sampleRules))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	host := hostStub{runRoot: func(cmd string) error {
		if cmd == loadCmd {
			return errors.New("augenrules exited 1")
		}
		return nil
	}}
	if err := load(host, want); err == nil || !strings.Contains(err.Error(), loadCmd) {
		t.Fatalf("expected the load failure to name the command, got %v", err)
	}
}

func TestPlanSurfacesThePreflightRefusals(t *testing.T) {
	host := hostStub{files: map[string]string{}, loaded: loadedSample,
		status: "enabled 2 failure 1", absent: map[string]bool{"/etc/audit": true}}
	res, err := Plan(pluginapi.Context{Host: host, Profile: testProfile(t, "-D\n"+sampleRules)}, spec())
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	joined := strings.Join(res.Highlights, "\n")
	for _, want := range []string{"deletes every rule", "locked", "do not exist on this host"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("plan must warn about %q before apply refuses it, got %v", want, res.Highlights)
		}
	}
}

func TestControlLineCoversTheSubsystemSettings(t *testing.T) {
	for _, line := range []string{"-D", "-e 1", "-b 8192", "-f 1", "-r 60", "--loginuid-immutable"} {
		if !ControlLine(strings.Fields(line)) {
			t.Fatalf("%q is a control line", line)
		}
	}
	for _, line := range []string{"-w /etc/passwd -p wa -k identity", ""} {
		if ControlLine(strings.Fields(line)) {
			t.Fatalf("%q is not a control line", line)
		}
	}
}
