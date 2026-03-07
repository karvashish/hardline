package apply

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func TestEnforceManagedPath(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		if err := enforceManagedPath("/etc/ssh/sshd_config.d/99-hardline-ssh.conf"); err != nil {
			t.Fatalf("expected valid path, got %v", err)
		}
		if err := enforceManagedPath("/etc/nftables.d/99-hardline-firewall.nft"); err != nil {
			t.Fatalf("expected valid path, got %v", err)
		}
		if err := enforceManagedPath("/etc/audit/rules.d/99-hardline.rules"); err != nil {
			t.Fatalf("expected valid path, got %v", err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		cases := []string{
			"",
			"/tmp/99-hardline.conf",
			"/etc/ssh/sshd_config.d/10-ssh.conf",
			"/etc/ssh/sshd_config.d/99-hardline-ssh.txt",
			"/etc/ssh/sshd_config.d/../99-hardline-ssh.conf",
		}
		for _, in := range cases {
			if err := enforceManagedPath(in); err == nil {
				t.Fatalf("expected path %q to be rejected", in)
			}
		}
	})
}

func TestCaptureStepRecord_TemplateAndFirewall(t *testing.T) {
	t.Run("template existing file", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.HasPrefix(cmd, "test -e ") {
				return nil
			}
			return nil
		}
		runRootCmdWithOutput = func(_ *ssh.Client, cmd string) (string, error) {
			if strings.HasPrefix(cmd, "stat -c %a ") {
				return "0644\n", nil
			}
			t.Fatalf("unexpected command: %s", cmd)
			return "", nil
		}
		readRootFile = func(_ *ssh.Client, remotePath string) (string, error) {
			if remotePath != "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" {
				t.Fatalf("unexpected read path %q", remotePath)
			}
			return "abc", nil
		}

		step := profile.Step{
			ID:   "s1",
			Type: "template",
			Template: &profile.TemplateSpec{
				Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
			},
		}
		record, err := captureStepRecord(nil, step)
		if err != nil {
			t.Fatalf("captureStepRecord failed: %v", err)
		}
		if record.RollbackMode != rollback.ModeDeterministic {
			t.Fatalf("unexpected rollback mode: %s", record.RollbackMode)
		}
		if len(record.Objects) != 1 || record.Objects[0].File == nil {
			t.Fatalf("expected one file object, got %+v", record.Objects)
		}
		fileSnap := record.Objects[0].File
		if !fileSnap.Existed || fileSnap.Mode != "0644" {
			t.Fatalf("unexpected file snapshot: %+v", fileSnap)
		}
		if got := string(mustDecodeB64(t, fileSnap.ContentB64)); got != "abc" {
			t.Fatalf("unexpected file snapshot content: %q", got)
		}
	})

	t.Run("firewall managed path absent", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.HasPrefix(cmd, "test -e ") {
				return errors.New("not found")
			}
			return nil
		}
		runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) {
			t.Fatal("did not expect stat for absent file")
			return "", nil
		}
		readRootFile = func(_ *ssh.Client, _ string) (string, error) {
			t.Fatal("did not expect file read for absent file")
			return "", nil
		}

		step := profile.Step{
			ID:   "f1",
			Type: "firewall",
			Firewall: &profile.FirewallSpec{
				Backend:     "nftables",
				ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
			},
		}
		record, err := captureStepRecord(nil, step)
		if err != nil {
			t.Fatalf("captureStepRecord failed: %v", err)
		}
		if len(record.Objects) != 1 || record.Objects[0].File == nil {
			t.Fatalf("expected one file object, got %+v", record.Objects)
		}
		fileSnap := record.Objects[0].File
		if fileSnap.Path != "/etc/nftables.d/99-hardline-firewall.nft" || fileSnap.Existed {
			t.Fatalf("unexpected firewall snapshot: %+v", fileSnap)
		}
	})

	t.Run("firewall_template managed path absent", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.HasPrefix(cmd, "test -e ") {
				return errors.New("not found")
			}
			return nil
		}
		runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) {
			t.Fatal("did not expect stat for absent file")
			return "", nil
		}
		readRootFile = func(_ *ssh.Client, _ string) (string, error) {
			t.Fatal("did not expect file read for absent file")
			return "", nil
		}

		step := profile.Step{
			ID:   "ft1",
			Type: "firewall_template",
			FirewallTemplate: &profile.FirewallTemplateSpec{
				Backend:      "nftables",
				TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft",
			},
		}
		record, err := captureStepRecord(nil, step)
		if err != nil {
			t.Fatalf("captureStepRecord failed: %v", err)
		}
		if len(record.Objects) != 1 || record.Objects[0].File == nil {
			t.Fatalf("expected one file object, got %+v", record.Objects)
		}
		fileSnap := record.Objects[0].File
		if fileSnap.Path != "/etc/nftables.d/99-hardline-firewall.nft" || fileSnap.Existed {
			t.Fatalf("unexpected firewall_template snapshot: %+v", fileSnap)
		}
	})

	t.Run("template missing spec", func(t *testing.T) {
		_, err := captureStepRecord(nil, profile.Step{ID: "t", Type: "template"})
		if err == nil || !strings.Contains(err.Error(), "template spec missing") {
			t.Fatalf("expected template missing error, got %v", err)
		}
	})

	t.Run("firewall missing spec", func(t *testing.T) {
		_, err := captureStepRecord(nil, profile.Step{ID: "f", Type: "firewall"})
		if err == nil || !strings.Contains(err.Error(), "firewall spec missing") {
			t.Fatalf("expected firewall missing error, got %v", err)
		}
	})

	t.Run("template unmanaged destination", func(t *testing.T) {
		step := profile.Step{
			ID:   "t2",
			Type: "template",
			Template: &profile.TemplateSpec{
				Dest: "/tmp/99-hardline.conf",
			},
		}
		_, err := captureStepRecord(nil, step)
		if err == nil || !strings.Contains(err.Error(), "outside /etc managed scope") {
			t.Fatalf("expected managed path error, got %v", err)
		}
	})

	t.Run("template stat error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) { return "", errors.New("stat boom") }
		readRootFile = func(_ *ssh.Client, _ string) (string, error) { return "abc", nil }

		step := profile.Step{
			ID:   "t3",
			Type: "template",
			Template: &profile.TemplateSpec{
				Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
			},
		}
		_, err := captureStepRecord(nil, step)
		if err == nil || !strings.Contains(err.Error(), "capture template snapshot") {
			t.Fatalf("expected snapshot error, got %v", err)
		}
	})

	t.Run("firewall read error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) { return "0644", nil }
		readRootFile = func(_ *ssh.Client, _ string) (string, error) { return "", errors.New("read boom") }

		step := profile.Step{
			ID:   "f2",
			Type: "firewall",
			Firewall: &profile.FirewallSpec{
				ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
			},
		}
		_, err := captureStepRecord(nil, step)
		if err == nil || !strings.Contains(err.Error(), "capture firewall snapshot") {
			t.Fatalf("expected firewall snapshot error, got %v", err)
		}
	})
}

func TestCaptureStepRecord_ServicePackagesValidate(t *testing.T) {
	t.Run("service snapshot", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmdWithOutput = func(_ *ssh.Client, cmd string) (string, error) {
			switch {
			case strings.Contains(cmd, "is-enabled"):
				return "enabled\n", nil
			case strings.Contains(cmd, "is-active"):
				return "inactive\n", nil
			default:
				t.Fatalf("unexpected command: %s", cmd)
				return "", nil
			}
		}

		step := profile.Step{
			ID:   "svc",
			Type: "service",
			Service: &profile.ServiceSpec{
				Name: "sshd",
			},
		}
		record, err := captureStepRecord(nil, step)
		if err != nil {
			t.Fatalf("captureStepRecord failed: %v", err)
		}
		if len(record.Objects) != 1 || record.Objects[0].Service == nil {
			t.Fatalf("expected one service object, got %+v", record.Objects)
		}
		svc := record.Objects[0].Service
		if svc.Unit != "ssh" || !svc.Enabled || svc.Active {
			t.Fatalf("unexpected service snapshot: %+v", svc)
		}
	})

	t.Run("service missing spec", func(t *testing.T) {
		_, err := captureStepRecord(nil, profile.Step{ID: "svc", Type: "service"})
		if err == nil || !strings.Contains(err.Error(), "service spec missing") {
			t.Fatalf("expected service missing error, got %v", err)
		}
	})

	t.Run("service snapshot error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) { return "", errors.New("boom") }
		_, err := captureStepRecord(nil, profile.Step{
			ID:      "svc2",
			Type:    "service",
			Service: &profile.ServiceSpec{Name: "ssh"},
		})
		if err == nil || !strings.Contains(err.Error(), "capture service snapshot") {
			t.Fatalf("expected service snapshot error, got %v", err)
		}
	})

	t.Run("service known false when outputs empty", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) { return " \n", nil }
		state, err := snapshotServiceState(nil, "ssh")
		if err != nil {
			t.Fatalf("snapshotServiceState failed: %v", err)
		}
		if state.Known {
			t.Fatalf("expected unknown state from empty outputs, got %+v", state)
		}
	})

	t.Run("packages snapshot", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmdWithOutput = func(_ *ssh.Client, cmd string) (string, error) {
			switch {
			case strings.Contains(cmd, `"fail2ban"`):
				return "install ok installed\t1.0\n", nil
			case strings.Contains(cmd, `"telnet"`):
				return "", nil
			default:
				t.Fatalf("unexpected command: %s", cmd)
				return "", nil
			}
		}

		step := profile.Step{
			ID:   "pk",
			Type: "packages",
			Packages: &profile.PackageSpec{
				Install: []string{"fail2ban"},
				Purge:   []string{"telnet"},
				Update:  true,
			},
		}
		record, err := captureStepRecord(nil, step)
		if err != nil {
			t.Fatalf("captureStepRecord failed: %v", err)
		}
		if record.RollbackMode != rollback.ModeBestEffort {
			t.Fatalf("unexpected rollback mode: %s", record.RollbackMode)
		}
		if len(record.Objects) != 2 {
			t.Fatalf("expected 2 package objects, got %d", len(record.Objects))
		}
		var seenInstall, seenPurge bool
		for _, obj := range record.Objects {
			if obj.Package == nil {
				t.Fatalf("expected package payload in %+v", obj)
			}
			switch obj.Package.Name {
			case "fail2ban":
				seenInstall = true
				if !obj.Package.WasInstalled || !obj.Package.RequestedInstall {
					t.Fatalf("unexpected fail2ban snapshot: %+v", obj.Package)
				}
			case "telnet":
				seenPurge = true
				if obj.Package.WasInstalled || !obj.Package.RequestedPurge {
					t.Fatalf("unexpected telnet snapshot: %+v", obj.Package)
				}
			}
		}
		if !seenInstall || !seenPurge {
			t.Fatalf("missing package snapshots, got %+v", record.Objects)
		}
	})

	t.Run("packages missing spec", func(t *testing.T) {
		_, err := captureStepRecord(nil, profile.Step{ID: "p", Type: "packages"})
		if err == nil || !strings.Contains(err.Error(), "packages spec missing") {
			t.Fatalf("expected packages missing error, got %v", err)
		}
	})

	t.Run("packages snapshot query error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) { return "", errors.New("query boom") }
		_, err := captureStepRecord(nil, profile.Step{
			ID:   "pk2",
			Type: "packages",
			Packages: &profile.PackageSpec{
				Install: []string{"pkg"},
			},
		})
		if err == nil || !strings.Contains(err.Error(), "capture package state") {
			t.Fatalf("expected package snapshot error, got %v", err)
		}
	})

	t.Run("packages include notes and installed-without-version", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmdWithOutput = func(_ *ssh.Client, cmd string) (string, error) {
			if strings.Contains(cmd, `"pkg"`) {
				return "install ok installed\n", nil
			}
			t.Fatalf("unexpected command: %s", cmd)
			return "", nil
		}

		record, err := captureStepRecord(nil, profile.Step{
			ID:   "pk3",
			Type: "packages",
			Packages: &profile.PackageSpec{
				Install:    []string{"pkg"},
				Update:     true,
				Upgrade:    true,
				Autoremove: true,
			},
		})
		if err != nil {
			t.Fatalf("captureStepRecord failed: %v", err)
		}
		if len(record.Notes) != 3 {
			t.Fatalf("expected 3 notes, got %+v", record.Notes)
		}
		if len(record.Objects) != 1 || record.Objects[0].Package == nil || !record.Objects[0].Package.WasInstalled {
			t.Fatalf("expected installed package snapshot, got %+v", record.Objects)
		}
	})

	t.Run("validate noop", func(t *testing.T) {
		record, err := captureStepRecord(nil, profile.Step{ID: "v", Type: "validate"})
		if err != nil {
			t.Fatalf("captureStepRecord failed: %v", err)
		}
		if record.RollbackMode != rollback.ModeNoop {
			t.Fatalf("expected noop rollback mode, got %s", record.RollbackMode)
		}
	})

	t.Run("unknown type noop", func(t *testing.T) {
		record, err := captureStepRecord(nil, profile.Step{ID: "u", Type: "mystery"})
		if err != nil {
			t.Fatalf("captureStepRecord failed: %v", err)
		}
		if record.RollbackMode != rollback.ModeNoop || len(record.Objects) != 1 {
			t.Fatalf("expected unknown type noop record, got %+v", record)
		}
	})

	t.Run("canonicalServiceUnit passthrough", func(t *testing.T) {
		if got := canonicalServiceUnit("cron"); got != "cron" {
			t.Fatalf("unexpected canonical unit: %q", got)
		}
	})
}

func mustDecodeB64(t *testing.T, in string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return b
}
