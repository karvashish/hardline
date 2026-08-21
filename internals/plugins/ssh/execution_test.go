package ssh

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

const testBin = "/usr/sbin/sshd"

type sshHostStub struct {
	noSSHD       bool
	user         string
	groups       string
	userErr      error
	candidateErr string
	mainErr      string
	effective    string
	matchOutput  map[string]string
	effectiveErr bool
	reloadErr    error

	fileExists  bool
	fileMode    string
	fileContent string

	writes  map[string]string
	modes   map[string]os.FileMode
	removed []string
	renames []string
	reloads []string
}

func newHostStub() *sshHostStub {
	return &sshHostStub{
		user:   "admin",
		groups: "admin sudo",
		writes: map[string]string{},
		modes:  map[string]os.FileMode{},
	}
}

func (s *sshHostStub) RunRoot(cmd string) error {
	switch {
	case strings.HasPrefix(cmd, "systemctl reload "):
		s.reloads = append(s.reloads, cmd)
		return s.reloadErr
	case strings.HasPrefix(cmd, "rm -f "):
		s.removed = append(s.removed, cmd)
		return nil
	case strings.HasPrefix(cmd, "mv -f "):
		s.renames = append(s.renames, cmd)
		return nil
	default:
		return nil
	}
}

func (s *sshHostStub) RunRootWithOutput(cmd string) (string, error) {
	switch {
	case strings.HasPrefix(cmd, "command -v sshd"):
		if s.noSSHD {
			return "", nil
		}
		return testBin + "\n", nil

	case strings.Contains(cmd, `printf '%s' "${SUDO_USER`):
		return s.user, s.userErr

	case strings.HasPrefix(cmd, "id -nG "):
		return s.groups, nil

	case strings.Contains(cmd, " -t -f "):
		if s.candidateErr != "" {
			return s.candidateErr, errors.New("exit 255")
		}
		return "", nil

	case strings.HasSuffix(cmd, " -t 2>&1"):
		if s.mainErr != "" {
			return s.mainErr, errors.New("exit 255")
		}
		return "", nil

	case strings.Contains(cmd, " -T -C "):
		if s.effectiveErr {
			return "bad connection spec", errors.New("exit 255")
		}
		spec := cmd[strings.Index(cmd, "-C ")+4:]
		spec = spec[:strings.Index(spec, "'")]
		if out, ok := s.matchOutput[spec]; ok {
			return out, nil
		}
		return s.effective, nil

	case strings.HasSuffix(cmd, " -T 2>&1"):
		if s.effectiveErr {
			return "sshd: no hostkeys available", errors.New("exit 255")
		}
		return s.effective, nil

	case strings.HasPrefix(cmd, "stat -L -c "):
		if !s.fileExists {
			return "", nil
		}
		return fmt.Sprintf("regular file|%s|root|root|%d", s.fileMode, len(s.fileContent)), nil

	default:
		return "", nil
	}
}

func (s *sshHostStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return s.RunRootWithOutput(cmd)
}

func (s *sshHostStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("not used") }

func (s *sshHostStub) ReadRootFile(string) (string, error) { return s.fileContent, nil }

func (s *sshHostStub) WriteRootFile(path string, data []byte, mode os.FileMode) error {
	s.writes[path] = string(data)
	s.modes[path] = mode
	return nil
}

func testSpec() *Spec {
	return &Spec{
		Path:    "/etc/ssh/sshd_config.d/00-hardline-ssh.conf",
		Mode:    "600",
		Service: "sshd",
		Settings: map[string]any{
			"PasswordAuthentication": "no",
			"PermitRootLogin":        "no",
		},
	}
}

func effectiveFor(extra ...string) string {
	lines := []string{
		"passwordauthentication no",
		"permitrootlogin no",
		"pubkeyauthentication yes",
	}
	return strings.Join(append(lines, extra...), "\n") + "\n"
}

func TestApplyWritesChecksAndReloads(t *testing.T) {
	host := newHostStub()
	host.effective = effectiveFor()

	if err := Apply(pluginapi.Context{Host: host}, testSpec()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	staged := candidatePath("/etc/ssh/sshd_config.d/00-hardline-ssh.conf")
	written, ok := host.writes[staged]
	if !ok {
		t.Fatalf("nothing was staged at %s; writes=%v", staged, host.writes)
	}
	if !strings.Contains(written, "PasswordAuthentication no\n") || !strings.Contains(written, "PermitRootLogin no\n") {
		t.Fatalf("staged content is not the rendered policy: %q", written)
	}
	if got := host.modes[staged]; got != 0o600 {
		t.Fatalf("staged mode = %o, want 600", got)
	}
	if len(host.renames) != 1 || !strings.Contains(host.renames[0], "00-hardline-ssh.conf") {
		t.Fatalf("candidate was not installed: %v", host.renames)
	}
	if len(host.reloads) != 1 || !strings.Contains(host.reloads[0], "'sshd'") {
		t.Fatalf("sshd was not reloaded: %v", host.reloads)
	}
}

func TestApplySkipsReloadWhenAlreadyActive(t *testing.T) {
	spec := testSpec()
	settings, err := ParseSettings(spec.Settings)
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}

	host := newHostStub()
	host.effective = effectiveFor()
	host.fileExists = true
	host.fileMode = "600"
	host.fileContent = string(Render(settings))

	if err := Apply(pluginapi.Context{Host: host}, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(host.reloads) != 0 {
		t.Fatalf("expected no reload, got %v", host.reloads)
	}
	if len(host.writes) != 0 {
		t.Fatalf("expected no write, got %v", host.writes)
	}
}

func TestApplyReloadsWhenFileMatchesButPolicyDoesNot(t *testing.T) {
	spec := testSpec()
	settings, _ := ParseSettings(spec.Settings)

	host := newHostStub()
	host.fileExists = true
	host.fileMode = "600"
	host.fileContent = string(Render(settings))
	host.effective = "passwordauthentication yes\npermitrootlogin no\npubkeyauthentication yes\n"

	err := Apply(pluginapi.Context{Host: host}, spec)
	if err == nil {
		t.Fatalf("expected the post-reload verification to fail")
	}
	if !strings.Contains(err.Error(), "not what the profile declares") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(host.reloads) != 2 {
		t.Fatalf("expected the refused policy to be reloaded back out, got %v", host.reloads)
	}
	if _, ok := host.writes["/etc/ssh/sshd_config.d/00-hardline-ssh.conf"]; !ok {
		t.Fatalf("expected the previous drop-in to be restored")
	}
}

func TestApplyRefusesCandidateThatDoesNotParse(t *testing.T) {
	host := newHostStub()
	host.effective = effectiveFor()
	host.candidateErr = "/etc/ssh/x.conf: line 2: Bad configuration option: nonsense"

	err := Apply(pluginapi.Context{Host: host}, testSpec())
	if err == nil || !strings.Contains(err.Error(), "sshd rejected the rendered configuration") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(host.renames) != 0 {
		t.Fatalf("a candidate that does not parse must not be installed: %v", host.renames)
	}
	if len(host.reloads) != 0 {
		t.Fatalf("sshd must not be reloaded: %v", host.reloads)
	}
}

func TestApplyRestoresWhenMainConfigDoesNotParse(t *testing.T) {
	host := newHostStub()
	host.effective = effectiveFor()
	host.fileExists = true
	host.fileMode = "600"
	host.fileContent = "PasswordAuthentication yes\n"
	host.mainErr = "/etc/ssh/sshd_config: line 12: Directive 'PermitRootLogin' is not allowed within a Match block"

	err := Apply(pluginapi.Context{Host: host}, testSpec())
	if err == nil || !strings.Contains(err.Error(), "does not parse with this drop-in in place") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(host.reloads) != 0 {
		t.Fatalf("sshd must not be reloaded: %v", host.reloads)
	}
	restored := host.writes["/etc/ssh/sshd_config.d/00-hardline-ssh.conf"]
	if restored != "PasswordAuthentication yes\n" {
		t.Fatalf("previous drop-in was not restored, got %q", restored)
	}
}

func TestApplyRefusesLockout(t *testing.T) {
	host := newHostStub()
	host.user = "root"
	host.groups = "root"
	host.effective = effectiveFor()

	err := Apply(pluginapi.Context{Host: host}, testSpec())
	if err == nil || !strings.Contains(err.Error(), "connected as root") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(host.reloads) != 0 {
		t.Fatalf("sshd must not be reloaded: %v", host.reloads)
	}
	if len(host.removed) == 0 {
		t.Fatalf("the installed drop-in was not removed on refusal")
	}
}

func TestApplyRefusesWhenMatchBlockOverrides(t *testing.T) {
	spec := testSpec()
	spec.VerifyContexts = []MatchContext{{User: "deploy", Host: "host.example", Address: "10.0.0.5"}}

	host := newHostStub()
	host.effective = effectiveFor()
	host.matchOutput = map[string]string{
		"user=deploy,host=host.example,addr=10.0.0.5": "passwordauthentication yes\npermitrootlogin no\npubkeyauthentication yes\n",
	}

	err := Apply(pluginapi.Context{Host: host}, spec)
	if err == nil || !strings.Contains(err.Error(), "a Match block overrides it") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyErrors(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*sshHostStub)
		spec     func(*Spec)
		contains string
	}{
		{"no sshd", func(h *sshHostStub) { h.noSSHD = true }, nil, "sshd is not installed"},
		{"no connecting user", func(h *sshHostStub) { h.user = "  " }, nil, "could not determine the connecting user"},
		{"user probe fails", func(h *sshHostStub) { h.userErr = errors.New("boom") }, nil, "determine the connecting user"},
		{"effective probe fails", func(h *sshHostStub) { h.effectiveErr = true }, nil, "read the effective sshd configuration"},
		{"reload fails", func(h *sshHostStub) { h.reloadErr = errors.New("job failed") }, nil, "reload sshd"},
		{"unmanaged path", nil, func(s *Spec) { s.Path = "/tmp/ssh.conf" }, "outside /etc managed scope"},
		{"bad keyword", nil, func(s *Spec) { s.Settings = map[string]any{"Nope": "no"} }, "not one this plugin can verify"},
		{"bad mode", nil, func(s *Spec) { s.Mode = "9999" }, "invalid file mode"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := newHostStub()
			host.effective = effectiveFor()
			if tc.mutate != nil {
				tc.mutate(host)
			}
			spec := testSpec()
			if tc.spec != nil {
				tc.spec(spec)
			}
			err := Apply(pluginapi.Context{Host: host}, spec)
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error %q does not contain %q", err, tc.contains)
			}
		})
	}
}

func TestApplyRequiresHost(t *testing.T) {
	if err := Apply(pluginapi.Context{}, testSpec()); err == nil {
		t.Fatalf("expected an error without a host")
	}
}

func TestAssertManagementAccess(t *testing.T) {
	cases := []struct {
		name      string
		effective map[string][]string
		user      string
		groups    []string
		contains  string
	}{
		{
			name:      "root denied by policy",
			effective: map[string][]string{"permitrootlogin": {"no"}},
			user:      "root",
			contains:  "connected as root",
		},
		{
			name:      "root with forced commands only",
			effective: map[string][]string{"permitrootlogin": {"forced-commands-only"}},
			user:      "root",
			contains:  "forced-commands-only",
		},
		{
			name:      "root with prohibit-password is fine",
			effective: map[string][]string{"permitrootlogin": {"prohibit-password"}, "pubkeyauthentication": {"yes"}},
			user:      "root",
		},
		{
			name:      "pubkey disabled",
			effective: map[string][]string{"pubkeyauthentication": {"no"}},
			user:      "admin",
			contains:  "PubkeyAuthentication no",
		},
		{
			name:      "user denied",
			effective: map[string][]string{"denyusers": {"admin backup"}},
			user:      "admin",
			contains:  "denyusers admin backup",
		},
		{
			name:      "user not allowed",
			effective: map[string][]string{"allowusers": {"deploy"}},
			user:      "admin",
			contains:  "does not cover this run's identity",
		},
		{
			name:      "user allowed by glob",
			effective: map[string][]string{"allowusers": {"adm*"}},
			user:      "admin",
		},
		{
			name:      "group denied",
			effective: map[string][]string{"denygroups": {"sudo"}},
			user:      "admin",
			groups:    []string{"admin", "sudo"},
			contains:  "denygroups sudo",
		},
		{
			name:      "group not allowed",
			effective: map[string][]string{"allowgroups": {"wheel"}},
			user:      "admin",
			groups:    []string{"admin", "sudo"},
			contains:  "allowgroups wheel",
		},
		{
			name:      "group allowed",
			effective: map[string][]string{"allowgroups": {"sudo wheel"}},
			user:      "admin",
			groups:    []string{"admin", "sudo"},
		},
		{
			name:      "negated pattern is refused rather than guessed",
			effective: map[string][]string{"allowusers": {"!backup admin"}},
			user:      "admin",
			contains:  "cannot evaluate",
		},
		{
			name:      "character-class deny pattern is refused rather than skipped",
			effective: map[string][]string{"denyusers": {"bad[ deploy"}},
			user:      "admin",
			contains:  "cannot evaluate",
		},
		{
			name:      "character-class allow pattern is refused rather than skipped",
			effective: map[string][]string{"allowusers": {"adm[in"}},
			user:      "admin",
			contains:  "cannot evaluate",
		},
		{
			name:      "deny pattern is checked even with an empty name list",
			effective: map[string][]string{"denygroups": {"adm[in"}},
			user:      "admin",
			groups:    nil,
			contains:  "cannot evaluate",
		},
		{
			name:      "user@host pattern is refused rather than guessed",
			effective: map[string][]string{"allowusers": {"admin@10.0.0.0/8"}},
			user:      "admin",
			contains:  "cannot evaluate",
		},
		{
			name:      "no restrictions",
			effective: map[string][]string{"pubkeyauthentication": {"yes"}},
			user:      "admin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := assertManagementAccess(tc.effective, tc.user, tc.groups)
			if tc.contains == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error %q does not contain %q", err, tc.contains)
			}
		})
	}
}

func TestPlanReportsChangeAndAlignment(t *testing.T) {
	host := newHostStub()
	host.effective = "passwordauthentication yes\npermitrootlogin no\npubkeyauthentication yes\n"

	result, err := Plan(pluginapi.Context{Host: host}, testSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !result.WillChange {
		t.Fatalf("expected WillChange")
	}
	if result.RollbackFidelity != pluginapi.ModeDeterministic {
		t.Fatalf("fidelity = %q", result.RollbackFidelity)
	}
	if !strings.Contains(strings.Join(result.Details, "\n"), "PasswordAuthentication") {
		t.Fatalf("details do not name the divergent keyword: %v", result.Details)
	}
}

func TestPlanAlignedHostWillNotChange(t *testing.T) {
	spec := testSpec()
	settings, _ := ParseSettings(spec.Settings)

	host := newHostStub()
	host.effective = effectiveFor()
	host.fileExists = true
	host.fileMode = "600"
	host.fileContent = string(Render(settings))

	result, err := Plan(pluginapi.Context{Host: host}, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if result.WillChange {
		t.Fatalf("expected no change: %v", result.Details)
	}
	if len(result.Highlights) != 0 {
		t.Fatalf("unexpected highlights: %v", result.Highlights)
	}
}

func TestPlanHighlightsLockout(t *testing.T) {
	host := newHostStub()
	host.user = "root"
	host.groups = "root"
	host.effective = effectiveFor()

	result, err := Plan(pluginapi.Context{Host: host}, testSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(result.Highlights) == 0 || !strings.Contains(result.Highlights[0], "connected as root") {
		t.Fatalf("expected a lockout highlight, got %v", result.Highlights)
	}
}

func TestPlanErrors(t *testing.T) {
	if _, err := Plan(pluginapi.Context{}, testSpec()); err == nil {
		t.Fatalf("expected an error without a host")
	}

	spec := testSpec()
	spec.Path = "/tmp/nope.conf"
	if _, err := Plan(pluginapi.Context{Host: newHostStub()}, spec); err == nil {
		t.Fatalf("expected an error for an unmanaged path")
	}

	spec = testSpec()
	spec.Mode = "zzz"
	if _, err := Plan(pluginapi.Context{Host: newHostStub()}, spec); err == nil {
		t.Fatalf("expected an error for a bad mode")
	}

	spec = testSpec()
	spec.Settings = map[string]any{"Nope": "x"}
	if _, err := Plan(pluginapi.Context{Host: newHostStub()}, spec); err == nil {
		t.Fatalf("expected an error for a bad keyword")
	}

	host := newHostStub()
	host.noSSHD = true
	if _, err := Plan(pluginapi.Context{Host: host}, testSpec()); err == nil {
		t.Fatalf("expected an error without sshd")
	}

	host = newHostStub()
	host.effectiveErr = true
	if _, err := Plan(pluginapi.Context{Host: host}, testSpec()); err == nil {
		t.Fatalf("expected an error when the effective probe fails")
	}

	host = newHostStub()
	host.effective = effectiveFor()
	host.userErr = errors.New("boom")
	if _, err := Plan(pluginapi.Context{Host: host}, testSpec()); err == nil {
		t.Fatalf("expected an error when the user probe fails")
	}
}

func TestCaptureRecordsFileAndUnit(t *testing.T) {
	host := newHostStub()
	host.fileExists = true
	host.fileMode = "600"
	host.fileContent = "PasswordAuthentication no\n"

	record, err := Capture(pluginapi.Context{Host: host}, "ssh-policy", testSpec())
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if record.RollbackMode != pluginapi.ModeDeterministic {
		t.Fatalf("rollback mode = %q", record.RollbackMode)
	}
	if len(record.Objects) != 1 || record.Objects[0].Kind != pluginapi.ObjectFile {
		t.Fatalf("objects = %+v", record.Objects)
	}
	if record.Objects[0].Message != "sshd" {
		t.Fatalf("unit was not journalled: %q", record.Objects[0].Message)
	}
	want := base64.StdEncoding.EncodeToString([]byte("PasswordAuthentication no\n"))
	if record.Objects[0].File.ContentB64 != want {
		t.Fatalf("content was not captured")
	}
}

func TestCaptureErrors(t *testing.T) {
	if _, err := Capture(pluginapi.Context{}, "ssh-policy", testSpec()); err == nil {
		t.Fatalf("expected an error without a host")
	}
	spec := testSpec()
	spec.Path = "/tmp/x.conf"
	if _, err := Capture(pluginapi.Context{Host: newHostStub()}, "ssh-policy", spec); err == nil {
		t.Fatalf("expected an error for an unmanaged path")
	}
}

func TestServiceUnit(t *testing.T) {
	snap := &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/00-hardline-ssh.conf"}

	if unit, err := ServiceUnit(pluginapi.ObjectRecord{File: snap, Message: " ssh "}); err != nil || unit != "ssh" {
		t.Fatalf("ServiceUnit = %q, %v", unit, err)
	}
	if _, err := ServiceUnit(pluginapi.ObjectRecord{File: snap}); err == nil {
		t.Fatalf("expected an error for an empty unit")
	}
	if _, err := ServiceUnit(pluginapi.ObjectRecord{File: snap, Message: "sshd; rm -rf /"}); err == nil {
		t.Fatalf("expected an error for an unsupported unit")
	}
}

func TestRestoreReloadsAfterParsing(t *testing.T) {
	host := newHostStub()
	snap := pluginapi.FileSnapshot{
		Path:       "/etc/ssh/sshd_config.d/00-hardline-ssh.conf",
		Existed:    true,
		Mode:       "600",
		Owner:      "root",
		Group:      "root",
		ContentB64: base64.StdEncoding.EncodeToString([]byte("PasswordAuthentication yes\n")),
	}

	if err := Restore(host, snap, "ssh"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if host.writes[snap.Path] != "PasswordAuthentication yes\n" {
		t.Fatalf("file was not restored: %q", host.writes[snap.Path])
	}
	if len(host.reloads) != 1 || !strings.Contains(host.reloads[0], "'ssh'") {
		t.Fatalf("unit was not reloaded: %v", host.reloads)
	}
}

func TestRestoreRefusesConfigThatDoesNotParse(t *testing.T) {
	host := newHostStub()
	host.mainErr = "line 3: Bad configuration option"
	snap := pluginapi.FileSnapshot{
		Path:       "/etc/ssh/sshd_config.d/00-hardline-ssh.conf",
		Existed:    true,
		Mode:       "600",
		Owner:      "root",
		Group:      "root",
		ContentB64: base64.StdEncoding.EncodeToString([]byte("PasswordAuthentication yes\n")),
	}

	err := Restore(host, snap, "ssh")
	if err == nil || !strings.Contains(err.Error(), "after restoring") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(host.reloads) != 0 {
		t.Fatalf("sshd must not be reloaded: %v", host.reloads)
	}
}

func TestRestoreRequiresHost(t *testing.T) {
	if err := Restore(nil, pluginapi.FileSnapshot{}, "ssh"); err == nil {
		t.Fatalf("expected an error without a host")
	}
}

func TestRestoreDeletesAFileThatDidNotExist(t *testing.T) {
	host := newHostStub()
	snap := pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/00-hardline-ssh.conf"}
	if err := Restore(host, snap, "sshd"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(host.removed) == 0 {
		t.Fatalf("expected the file to be removed")
	}
}

func TestSshdBinaryRejectsOddOutput(t *testing.T) {
	stub := &multiPathStub{sshHostStub: newHostStub()}
	if _, err := sshdBinary(stub); err == nil {
		t.Fatalf("expected an error for multi-line output")
	}
}

type multiPathStub struct{ *sshHostStub }

func (s *multiPathStub) RunRootWithOutput(cmd string) (string, error) {
	if strings.HasPrefix(cmd, "command -v sshd") {
		return "/usr/sbin/sshd\n/usr/local/sbin/sshd\n", nil
	}
	return s.sshHostStub.RunRootWithOutput(cmd)
}
