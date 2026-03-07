package apply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestHandleStep_MissingSpecsAndUnknown(t *testing.T) {
	p := mustLoadProfileForTests(t, map[string]string{
		"templates/t.tmpl": "hello",
	})

	cases := []struct {
		name    string
		step    profile.Step
		wantSub string
	}{
		{
			name:    "packages missing",
			step:    profile.Step{ID: "p", Type: "packages"},
			wantSub: "packages spec missing",
		},
		{
			name:    "template missing",
			step:    profile.Step{ID: "t", Type: "template"},
			wantSub: "template spec missing",
		},
		{
			name:    "service missing",
			step:    profile.Step{ID: "s", Type: "service"},
			wantSub: "service spec missing",
		},
		{
			name:    "firewall missing",
			step:    profile.Step{ID: "f", Type: "firewall"},
			wantSub: "firewall spec missing",
		},
		{
			name:    "validate missing",
			step:    profile.Step{ID: "v", Type: "validate"},
			wantSub: "validate spec missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handleStep(nil, p, tc.step)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected %q error, got %v", tc.wantSub, err)
			}
		})
	}

	if err := handleStep(nil, p, profile.Step{ID: "u", Type: "unknown"}); err != nil {
		t.Fatalf("expected unknown type to no-op, got %v", err)
	}

	t.Run("dispatch success paths", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error { return nil }

		successCases := []profile.Step{
			{ID: "p-ok", Type: "packages", Packages: &profile.PackageSpec{}},
			{ID: "t-ok", Type: "template", Template: &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/tmp/t"}},
			{ID: "s-ok", Type: "service", Service: &profile.ServiceSpec{Name: "cron"}},
			{ID: "f-ok", Type: "firewall", Firewall: &profile.FirewallSpec{Backend: "nftables", TemplateSrc: "templates/nftables_base.tmpl"}},
			{ID: "v-ok", Type: "validate", Validate: "sshd"},
		}

		// add firewall default template for firewall success case
		p2 := mustLoadProfileForTests(t, map[string]string{
			"templates/t.tmpl":             "hello",
			"templates/nftables_base.tmpl": "{{allow_rules}}",
		})

		for _, step := range successCases {
			if err := handleStep(nil, p2, step); err != nil {
				t.Fatalf("expected success for step %q: %v", step.ID, err)
			}
		}
	})
}

func TestHandlePackages(t *testing.T) {
	t.Run("success runs commands in order", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		var cmds []string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}

		err := handlePackages(nil, &profile.PackageSpec{
			Update:     true,
			Upgrade:    true,
			Install:    []string{"a", "b"},
			Purge:      []string{"c"},
			Autoremove: true,
		})
		if err != nil {
			t.Fatalf("handlePackages failed: %v", err)
		}

		want := []string{
			"apt-get update -y",
			"apt-get upgrade -y",
			"apt-get install -y a b",
			"apt-get purge -y c",
			"apt-get autoremove -y",
		}
		if strings.Join(cmds, "|") != strings.Join(want, "|") {
			t.Fatalf("unexpected command sequence: got %#v want %#v", cmds, want)
		}
	})

	t.Run("error wrapping", func(t *testing.T) {
		tests := []struct {
			name    string
			spec    profile.PackageSpec
			failCmd string
			wantSub string
		}{
			{
				name:    "update error",
				spec:    profile.PackageSpec{Update: true},
				failCmd: "apt-get update -y",
				wantSub: "apt-get update failed",
			},
			{
				name:    "upgrade error",
				spec:    profile.PackageSpec{Upgrade: true},
				failCmd: "apt-get upgrade -y",
				wantSub: "apt-get upgrade failed",
			},
			{
				name:    "install error",
				spec:    profile.PackageSpec{Install: []string{"x"}},
				failCmd: "apt-get install -y x",
				wantSub: "apt-get install failed",
			},
			{
				name:    "purge error",
				spec:    profile.PackageSpec{Purge: []string{"x"}},
				failCmd: "apt-get purge -y x",
				wantSub: "apt-get purge failed",
			},
			{
				name:    "autoremove error",
				spec:    profile.PackageSpec{Autoremove: true},
				failCmd: "apt-get autoremove -y",
				wantSub: "apt-get autoremove failed",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				restore := stubStepDeps()
				defer restore()
				runRootCmd = func(_ *ssh.Client, cmd string) error {
					if cmd == tc.failCmd {
						return errors.New("boom")
					}
					return nil
				}
				err := handlePackages(nil, &tc.spec)
				if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("expected %q error, got %v", tc.wantSub, err)
				}
			})
		}
	})
}

func TestHandleService(t *testing.T) {
	t.Run("missing name", func(t *testing.T) {
		if err := handleService(nil, &profile.ServiceSpec{}); err == nil || !strings.Contains(err.Error(), "service name is required") {
			t.Fatalf("expected service name required error, got %v", err)
		}
	})

	t.Run("success with enable and restart", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		var cmds []string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}

		enabled := true
		err := handleService(nil, &profile.ServiceSpec{Name: "sshd", Enabled: &enabled, State: "restart"})
		if err != nil {
			t.Fatalf("handleService failed: %v", err)
		}
		want := []string{"systemctl enable ssh", "systemctl restart ssh"}
		if strings.Join(cmds, "|") != strings.Join(want, "|") {
			t.Fatalf("unexpected command sequence: got %#v want %#v", cmds, want)
		}
	})

	t.Run("disable and stop", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		var cmds []string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}
		enabled := false
		err := handleService(nil, &profile.ServiceSpec{Name: "cron", Enabled: &enabled, State: "stop"})
		if err != nil {
			t.Fatalf("handleService failed: %v", err)
		}
		want := []string{"systemctl disable cron", "systemctl stop cron"}
		if strings.Join(cmds, "|") != strings.Join(want, "|") {
			t.Fatalf("unexpected command sequence: got %#v want %#v", cmds, want)
		}
	})

	t.Run("unsupported state", func(t *testing.T) {
		err := handleService(nil, &profile.ServiceSpec{Name: "cron", State: "invalid"})
		if err == nil || !strings.Contains(err.Error(), "unsupported service state") {
			t.Fatalf("expected unsupported state error, got %v", err)
		}
	})

	t.Run("enable command error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		enabled := true
		runRootCmd = func(_ *ssh.Client, _ string) error { return errors.New("boom") }
		err := handleService(nil, &profile.ServiceSpec{Name: "cron", Enabled: &enabled})
		if err == nil || !strings.Contains(err.Error(), "systemctl enable/disable") {
			t.Fatalf("expected enable/disable error, got %v", err)
		}
	})

	t.Run("state command error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		runRootCmd = func(_ *ssh.Client, _ string) error { return errors.New("boom") }
		err := handleService(nil, &profile.ServiceSpec{Name: "cron", State: "start"})
		if err == nil || !strings.Contains(err.Error(), "systemctl start") {
			t.Fatalf("expected state command error, got %v", err)
		}
	})
}

func TestHandleTemplate(t *testing.T) {
	t.Run("success with explicit mode", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		p := mustLoadProfileForTests(t, map[string]string{"templates/t.tmpl": "hello"})
		var mkdirCmd string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			mkdirCmd = cmd
			return nil
		}
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, dest string, data []byte, mode os.FileMode) error {
			if dest != "/etc/example.conf" {
				t.Fatalf("unexpected destination: %q", dest)
			}
			if string(data) != "hello" {
				t.Fatalf("unexpected data: %q", string(data))
			}
			if mode != 0o644 {
				t.Fatalf("unexpected mode: %#o", mode)
			}
			return nil
		}

		err := handleTemplate(nil, p, &profile.TemplateSpec{
			Src:  "templates/t.tmpl",
			Dest: "/etc/example.conf",
			Mode: "0644",
		})
		if err != nil {
			t.Fatalf("handleTemplate failed: %v", err)
		}
		if mkdirCmd == "" || !strings.Contains(mkdirCmd, "mkdir -p") {
			t.Fatalf("expected mkdir command, got %q", mkdirCmd)
		}
	})

	t.Run("default mode on parse failure", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()

		p := mustLoadProfileForTests(t, map[string]string{"templates/t.tmpl": "hello"})
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, mode os.FileMode) error {
			if mode != 0o600 {
				t.Fatalf("expected default mode 0600, got %#o", mode)
			}
			return nil
		}

		err := handleTemplate(nil, p, &profile.TemplateSpec{
			Src:  "templates/t.tmpl",
			Dest: "/tmp/example.conf",
			Mode: "bad",
		})
		if err != nil {
			t.Fatalf("handleTemplate failed: %v", err)
		}
	})

	t.Run("load template error", func(t *testing.T) {
		p := mustLoadProfileForTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := handleTemplate(nil, p, &profile.TemplateSpec{
			Src:  "templates/missing.tmpl",
			Dest: "/tmp/example.conf",
		})
		if err == nil || !strings.Contains(err.Error(), "load template") {
			t.Fatalf("expected load template error, got %v", err)
		}
	})

	t.Run("new sftp error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		p := mustLoadProfileForTests(t, map[string]string{"templates/t.tmpl": "hello"})
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, errors.New("boom") }
		err := handleTemplate(nil, p, &profile.TemplateSpec{
			Src:  "templates/t.tmpl",
			Dest: "/tmp/example.conf",
		})
		if err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp client error, got %v", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		p := mustLoadProfileForTests(t, map[string]string{"templates/t.tmpl": "hello"})
		runRootCmd = func(_ *ssh.Client, _ string) error { return errors.New("boom") }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		err := handleTemplate(nil, p, &profile.TemplateSpec{
			Src:  "templates/t.tmpl",
			Dest: "/etc/example.conf",
		})
		if err == nil || !strings.Contains(err.Error(), "mkdir -p") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("write root file error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		p := mustLoadProfileForTests(t, map[string]string{"templates/t.tmpl": "hello"})
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error {
			return errors.New("boom")
		}
		err := handleTemplate(nil, p, &profile.TemplateSpec{
			Src:  "templates/t.tmpl",
			Dest: "/etc/example.conf",
		})
		if err == nil || !strings.Contains(err.Error(), "remote.WriteRootFile") {
			t.Fatalf("expected write root file error, got %v", err)
		}
	})
}

func TestHandleFirewall(t *testing.T) {
	t.Run("unsupported backend", func(t *testing.T) {
		p := mustLoadProfileForTests(t, map[string]string{"templates/nftables_base.tmpl": "ok"})
		err := handleFirewall(nil, p, &profile.FirewallSpec{Backend: "ufw"})
		if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
			t.Fatalf("expected unsupported backend error, got %v", err)
		}
	})

	t.Run("template load error", func(t *testing.T) {
		p := mustLoadProfileForTests(t, map[string]string{"templates/other.tmpl": "ok"})
		err := handleFirewall(nil, p, &profile.FirewallSpec{
			Backend:     "nftables",
			TemplateSrc: "templates/nftables_base.tmpl",
		})
		if err == nil || !strings.Contains(err.Error(), "load nftables template") {
			t.Fatalf("expected template load error, got %v", err)
		}
	})

	t.Run("template parse error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		p := mustLoadProfileForTests(t, map[string]string{"templates/bad.tmpl": "{{"})
		err := handleFirewall(nil, p, &profile.FirewallSpec{
			Backend:     "nftables",
			TemplateSrc: "templates/bad.tmpl",
		})
		if err == nil || !strings.Contains(err.Error(), "parse nftables template") {
			t.Fatalf("expected parse template error, got %v", err)
		}
	})

	t.Run("template execute error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error { return nil }
		p := mustLoadProfileForTests(t, map[string]string{"templates/bad.tmpl": "{{index .Missing 0}}"})
		err := handleFirewall(nil, p, &profile.FirewallSpec{
			Backend:     "nftables",
			TemplateSrc: "templates/bad.tmpl",
		})
		if err == nil || !strings.Contains(err.Error(), "execute nftables template") {
			t.Fatalf("expected execute template error, got %v", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		p := mustLoadProfileForTests(t, map[string]string{"templates/nftables_base.tmpl": "{{allow_rules}}"})
		runRootCmd = func(_ *ssh.Client, _ string) error { return errors.New("boom") }
		err := handleFirewall(nil, p, &profile.FirewallSpec{
			Backend: "nftables",
		})
		if err == nil || !strings.Contains(err.Error(), "mkdir") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("new sftp error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		p := mustLoadProfileForTests(t, map[string]string{"templates/nftables_base.tmpl": "{{allow_rules}}"})
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, errors.New("boom") }
		err := handleFirewall(nil, p, &profile.FirewallSpec{
			Backend: "nftables",
		})
		if err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp error, got %v", err)
		}
	})

	t.Run("write root file error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		p := mustLoadProfileForTests(t, map[string]string{"templates/nftables_base.tmpl": "{{allow_rules}}"})
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error {
			return errors.New("boom")
		}
		err := handleFirewall(nil, p, &profile.FirewallSpec{
			Backend: "nftables",
		})
		if err == nil || !strings.Contains(err.Error(), "remote.WriteRootFile") {
			t.Fatalf("expected write root file error, got %v", err)
		}
	})

	t.Run("success default template and dest", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		p := mustLoadProfileForTests(t, map[string]string{
			"templates/nftables_base.tmpl": "table inet filter {\n{{allow_rules}}\n}",
		})
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, dest string, data []byte, mode os.FileMode) error {
			if dest != "/etc/nftables.d/10-hardline.nft" {
				t.Fatalf("unexpected destination: %q", dest)
			}
			if mode != 0o644 {
				t.Fatalf("unexpected mode: %#o", mode)
			}
			rendered := string(data)
			if !strings.Contains(rendered, "tcp dport 22 accept") {
				t.Fatalf("expected rendered allow rule, got %q", rendered)
			}
			return nil
		}
		err := handleFirewall(nil, p, &profile.FirewallSpec{
			Backend: "nftables",
			Allow: []profile.FirewallRule{
				{Port: 22, Proto: "tcp"},
			},
		})
		if err != nil {
			t.Fatalf("handleFirewall failed: %v", err)
		}
	})
}

func TestHandleValidate_NoMutationAndErrors(t *testing.T) {
	t.Run("sshd success no mutation", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		var cmds []string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}

		err := handleValidate(nil, "sshd")
		if err != nil {
			t.Fatalf("handleValidate sshd failed: %v", err)
		}
		if len(cmds) != 2 {
			t.Fatalf("expected 2 commands, got %#v", cmds)
		}
		joined := strings.Join(cmds, "\n")
		if strings.Contains(joined, ">>") || strings.Contains(joined, "|| echo") {
			t.Fatalf("validate command must not mutate config, got %#v", cmds)
		}
	})

	t.Run("firewall success no mutation", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		var cmds []string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}

		err := handleValidate(nil, "firewall")
		if err != nil {
			t.Fatalf("handleValidate firewall failed: %v", err)
		}
		if len(cmds) != 2 {
			t.Fatalf("expected 2 commands, got %#v", cmds)
		}
		joined := strings.Join(cmds, "\n")
		if strings.Contains(joined, ">>") || strings.Contains(joined, "|| echo") {
			t.Fatalf("validate command must not mutate config, got %#v", cmds)
		}
	})

	t.Run("sshd missing include", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		count := 0
		runRootCmd = func(_ *ssh.Client, _ string) error {
			count++
			if count == 1 {
				return errors.New("grep miss")
			}
			return nil
		}
		err := handleValidate(nil, "sshd")
		if err == nil || !strings.Contains(err.Error(), "missing Include") {
			t.Fatalf("expected missing include error, got %v", err)
		}
	})

	t.Run("sshd config test failure", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		count := 0
		runRootCmd = func(_ *ssh.Client, _ string) error {
			count++
			if count == 2 {
				return errors.New("sshd bad")
			}
			return nil
		}
		err := handleValidate(nil, "sshd")
		if err == nil || !strings.Contains(err.Error(), "sshd config test failed") {
			t.Fatalf("expected sshd test failure, got %v", err)
		}
	})

	t.Run("firewall missing include", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		count := 0
		runRootCmd = func(_ *ssh.Client, _ string) error {
			count++
			if count == 1 {
				return errors.New("grep miss")
			}
			return nil
		}
		err := handleValidate(nil, "firewall")
		if err == nil || !strings.Contains(err.Error(), "missing include") {
			t.Fatalf("expected missing include error, got %v", err)
		}
	})

	t.Run("firewall config test failure", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		count := 0
		runRootCmd = func(_ *ssh.Client, _ string) error {
			count++
			if count == 2 {
				return errors.New("nft bad")
			}
			return nil
		}
		err := handleValidate(nil, "firewall")
		if err == nil || !strings.Contains(err.Error(), "nftables config check failed") {
			t.Fatalf("expected nft check failure, got %v", err)
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		err := handleValidate(nil, "other")
		if err == nil || !strings.Contains(err.Error(), "unsupported validate kind") {
			t.Fatalf("expected unsupported kind error, got %v", err)
		}
	})
}

func stubStepDeps() func() {
	prevRunRoot := runRootCmd
	prevNewSFTP := newSFTPClient
	prevWriteRoot := writeRootFile

	return func() {
		runRootCmd = prevRunRoot
		newSFTPClient = prevNewSFTP
		writeRootFile = prevWriteRoot
	}
}

func mustLoadProfileForTests(t *testing.T, templates map[string]string) *profile.Profile {
	t.Helper()
	dir := t.TempDir()

	tplList := make([]string, 0, len(templates))
	for rel, content := range templates {
		tplList = append(tplList, rel)
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %q: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write template %q: %v", path, err)
		}
	}

	profileJSON := `{
  "id": "p",
  "display_name": "P",
  "version": "1.0.0",
  "os": {"family":"ubuntu","version":"24.04","variant":"lts"},
  "profile_schema": 1,
  "min_hardline": "1.0.0",
  "actions": [],
  "templates": ["` + strings.Join(tplList, `","`) + `"]
}`
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte(profileJSON), 0o644); err != nil {
		t.Fatalf("write profile.json: %v", err)
	}

	p, err := profile.Load(dir)
	if err != nil {
		t.Fatalf("profile.Load failed: %v", err)
	}
	return p
}
