package packages

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

type engineQueryResult struct {
	installed bool
	version   string
	pin       string
}

type engineFixture struct {
	events      []string
	queries     map[string]engineQueryResult
	queryErrors map[string]error
	previews    map[string][]string
	previewErrs map[string]error
	lockErr     error
}

func newEngineFixture() *engineFixture {
	return &engineFixture{
		queries:     map[string]engineQueryResult{},
		queryErrors: map[string]error{},
		previews:    map[string][]string{},
		previewErrs: map[string]error{},
	}
}

func (f *engineFixture) record(event string) {
	f.events = append(f.events, event)
}

func (f *engineFixture) preview(kind string, fallback []string) ([]string, error) {
	if err := f.previewErrs[kind]; err != nil {
		return nil, err
	}
	if result, ok := f.previews[kind]; ok {
		return slices.Clone(result), nil
	}
	return slices.Clone(fallback), nil
}

func (f *engineFixture) backend() Backend {
	return Backend{
		Name:        "packages_test",
		NamePattern: regexp.MustCompile(`^[a-z][a-z0-9-]*$`),
		PinPattern:  regexp.MustCompile(`^[a-z][a-z0-9-]*=[0-9.]+$`),
		CheckLock: func(pluginapi.Host) error {
			f.record("lock")
			return f.lockErr
		},
		Query: func(_ pluginapi.Host, name string) (bool, string, string, error) {
			f.record("query:" + name)
			if err := f.queryErrors[name]; err != nil {
				return false, "", "", err
			}
			result := f.queries[name]
			return result.installed, result.version, result.pin, nil
		},
		Commands: Commands{
			Update:     "update-cmd",
			Upgrade:    "upgrade-cmd",
			Install:    "install-cmd",
			Purge:      "purge-cmd",
			Autoremove: "autoremove-cmd",
		},
		Previews: Previews{
			Upgrade: func(pluginapi.Host) ([]string, error) {
				f.record("preview:upgrade")
				return f.preview("upgrade", nil)
			},
			Install: func(_ pluginapi.Host, names []string) ([]string, error) {
				f.record("preview:install:" + strings.Join(names, ","))
				return f.preview("install", names)
			},
			Purge: func(_ pluginapi.Host, names []string) ([]string, error) {
				f.record("preview:purge:" + strings.Join(names, ","))
				return f.preview("purge", names)
			},
			Autoremove: func(pluginapi.Host) ([]string, error) {
				f.record("preview:autoremove")
				return f.preview("autoremove", nil)
			},
		},
	}
}

type engineHost struct {
	fixture *engineFixture
	runErr  func(string) error
	stat    func(string) (os.FileInfo, error)
	write   func(string, []byte, os.FileMode) error
}

func (h *engineHost) run(prefix, cmd string) error {
	h.fixture.record(prefix + ":" + cmd)
	if h.runErr != nil {
		return h.runErr(cmd)
	}
	return nil
}

func (h *engineHost) RunRoot(cmd string) error {
	return h.run("root", cmd)
}

func (h *engineHost) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return "", h.run("run", cmd)
}

func (h *engineHost) RunRootWithOutput(cmd string) (string, error) {
	return "", h.run("output", cmd)
}

func (h *engineHost) Stat(path string) (os.FileInfo, error) {
	if h.stat != nil {
		return h.stat(path)
	}
	return nil, errors.New("not found")
}

func (h *engineHost) ReadRootFile(string) (string, error) { return "", nil }

func (h *engineHost) WriteRootFile(path string, data []byte, mode os.FileMode) error {
	h.fixture.record("write:" + path)
	if h.write != nil {
		return h.write(path, data, mode)
	}
	return nil
}

func (f *engineFixture) host() *engineHost {
	return &engineHost{fixture: f}
}

func engineStep(config map[string]any) profile.Step {
	return profile.Step{ID: "pkg", Plugin: "packages_test", Config: config}
}

func requireEngineError(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("got error %v, want one containing %q", err, contains)
	}
}

func requireEngineEvents(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("events differ\ngot:  %v\nwant: %v", got, want)
	}
}

func TestBackendPlugin(t *testing.T) {
	f := newEngineFixture()
	b := f.backend()
	p := b.Plugin()
	if p.Name != b.Name || !p.InternalValidation {
		t.Fatalf("plugin identity is wrong: name=%q internal_validation=%v", p.Name, p.InternalValidation)
	}
	for name, fn := range map[string]any{
		"Validate": p.Validate, "Apply": p.Apply, "Plan": p.Plan,
		"Capture": p.Capture, "Rollback": p.Rollback, "DetectConflict": p.DetectConflict,
	} {
		if fn == nil {
			t.Fatalf("%s callback is nil", name)
		}
	}

	good := engineStep(map[string]any{"install": []any{"pkg"}})
	bad := engineStep(map[string]any{"install": []any{"pkg;id"}})
	if err := p.Validate(good, nil); err != nil {
		t.Fatalf("valid config was rejected: %v", err)
	}
	if err := p.Validate(bad, nil); err == nil {
		t.Fatal("Validate accepted invalid config")
	}
	if err := p.Apply(pluginapi.Context{Host: f.host()}, bad); err == nil {
		t.Fatal("Apply accepted invalid config")
	}
	if _, err := p.Plan(pluginapi.Context{Host: f.host()}, bad); err == nil {
		t.Fatal("Plan accepted invalid config")
	}
	if _, err := p.Capture(pluginapi.Context{Host: f.host()}, bad); err == nil {
		t.Fatal("Capture accepted invalid config")
	}

	if err := p.Apply(pluginapi.Context{Host: f.host()}, good); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if _, err := p.Plan(pluginapi.Context{Host: f.host()}, good); err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if _, err := p.Capture(pluginapi.Context{Host: f.host()}, good); err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	if err := p.Rollback(f.host(), pluginapi.ObjectRecord{Kind: pluginapi.ObjectValidate}); err != nil {
		t.Fatalf("validate rollback failed: %v", err)
	}
	requireEngineError(t,
		p.Rollback(f.host(), pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage}),
		"missing package snapshot")
	requireEngineError(t,
		p.Rollback(f.host(), pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}),
		"cannot roll back")
	if err := p.Rollback(f.host(), pluginapi.ObjectRecord{
		Kind:    pluginapi.ObjectPackage,
		Package: &pluginapi.PackageState{Name: "pkg"},
	}); err != nil {
		t.Fatalf("package rollback failed: %v", err)
	}

	if got := p.DetectConflict(f.host(), pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); got != nil {
		t.Fatalf("foreign object produced conflicts: %v", got)
	}
	if got := p.DetectConflict(f.host(), pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage}); got != nil {
		t.Fatalf("nil package produced conflicts: %v", got)
	}
	if got := p.DetectConflict(f.host(), pluginapi.ObjectRecord{
		Kind:    pluginapi.ObjectPackage,
		Package: &pluginapi.PackageState{Name: "pkg"},
	}); got != nil {
		t.Fatalf("unchanged package produced conflicts: %v", got)
	}
}

func TestBackendPluginRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Backend)
	}{
		{"missing name", "name is required", func(b *Backend) { b.Name = " " }},
		{"missing name pattern", "package-name pattern is required", func(b *Backend) { b.NamePattern = nil }},
		{"missing pin pattern", "package-pin pattern is required", func(b *Backend) { b.PinPattern = nil }},
		{"missing lock check", "lock check is required", func(b *Backend) { b.CheckLock = nil }},
		{"missing query", "package query is required", func(b *Backend) { b.Query = nil }},
		{"missing update command", "update command is required", func(b *Backend) { b.Commands.Update = "" }},
		{"missing upgrade command", "upgrade command is required", func(b *Backend) { b.Commands.Upgrade = "" }},
		{"missing install command", "install command is required", func(b *Backend) { b.Commands.Install = "" }},
		{"missing purge command", "purge command is required", func(b *Backend) { b.Commands.Purge = "" }},
		{"missing autoremove command", "autoremove command is required", func(b *Backend) { b.Commands.Autoremove = "" }},
		{"missing upgrade preview", "upgrade preview is required", func(b *Backend) { b.Previews.Upgrade = nil }},
		{"missing install preview", "install preview is required", func(b *Backend) { b.Previews.Install = nil }},
		{"missing purge preview", "purge preview is required", func(b *Backend) { b.Previews.Purge = nil }},
		{"missing autoremove preview", "autoremove preview is required", func(b *Backend) { b.Previews.Autoremove = nil }},
		{
			"rollback command without preview",
			"rollback removal command and preview must be configured together",
			func(b *Backend) { b.Commands.RollbackRemove = "rollback-cmd" },
		},
		{
			"rollback preview without command",
			"rollback removal command and preview must be configured together",
			func(b *Backend) {
				b.Previews.RollbackRemove = func(pluginapi.Host, []string) ([]string, error) { return nil, nil }
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newEngineFixture().backend()
			tc.mutate(&b)
			defer func() {
				got, ok := recover().(string)
				if !ok || !strings.Contains(got, tc.want) {
					t.Fatalf("panic=%q, want one containing %q", got, tc.want)
				}
			}()
			_ = b.Plugin()
		})
	}
}

func TestBackendDecodeAndValidate(t *testing.T) {
	b := newEngineFixture().backend()

	if _, err := b.decode(engineStep(nil)); err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("empty config got %v", err)
	}
	if _, err := b.decode(engineStep(map[string]any{"install": make(chan int)})); err == nil {
		t.Fatal("expected an encoding failure")
	}

	for name, spec := range map[string]*Spec{
		"invalid update":       {Update: "sometimes"},
		"invalid upgrade":      {Upgrade: "sometimes"},
		"invalid autoremove":   {Autoremove: "sometimes"},
		"dead collateral":      {Install: []string{"pkg"}, PurgeAlsoRemoves: []string{"dep"}},
		"invalid collateral":   {Purge: []string{"pkg"}, PurgeAlsoRemoves: []string{"dep;id"}},
		"duplicate install":    {Install: []string{"pkg", "pkg"}},
		"install and purge":    {Install: []string{"pkg"}, Purge: []string{"pkg"}},
		"invalid package name": {Install: []string{"pkg;id"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := b.validate(spec); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}

	got, err := b.decode(engineStep(map[string]any{
		"update": "always", "install": []any{"pkg"}, "purge": []any{"old"},
		"purge_also_removes": []any{"old-dep"},
	}))
	if err != nil {
		t.Fatalf("valid config failed: %v", err)
	}
	if got.Update != "always" || !slices.Equal(got.Install, []string{"pkg"}) ||
		!slices.Equal(got.PurgeAlsoRemoves, []string{"old-dep"}) {
		t.Fatalf("decoded spec is wrong: %+v", got)
	}
}

func TestBackendApplyOrderingAndModes(t *testing.T) {
	t.Run("runs in lifecycle order", func(t *testing.T) {
		f := newEngineFixture()
		b := f.backend()
		host := f.host()
		f.previews["purge"] = []string{"old", "old-dep"}
		err := b.apply(pluginapi.Context{Host: host}, &Spec{
			Update: "always", Upgrade: "always", Autoremove: "always",
			Install: []string{"pkg"}, Purge: []string{"old"}, PurgeAlsoRemoves: []string{"old-dep"},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		requireEngineEvents(t, f.events, []string{
			"lock",
			"run:update-cmd",
			"run:upgrade-cmd",
			"run:install-cmd 'pkg'",
			"preview:purge:old",
			"run:purge-cmd 'old'",
			"run:autoremove-cmd",
		})
	})

	t.Run("once probes and skips aligned operations", func(t *testing.T) {
		f := newEngineFixture()
		f.queries["pkg"] = engineQueryResult{installed: true}
		b := f.backend()
		if err := b.apply(pluginapi.Context{Host: f.host()}, &Spec{
			Upgrade: "once", Autoremove: "once", Install: []string{"pkg"},
		}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		joined := strings.Join(f.events, "\n")
		if !strings.Contains(joined, "query:pkg") || strings.Contains(joined, "upgrade-cmd") ||
			strings.Contains(joined, "autoremove-cmd") {
			t.Fatalf("once decision was wrong: %v", f.events)
		}
	})

	t.Run("conditional operations mark successful runs", func(t *testing.T) {
		f := newEngineFixture()
		b := f.backend()
		if err := b.apply(pluginapi.Context{Host: f.host()}, &Spec{
			Update: "if_7d_since_last", Autoremove: "if_7d_since_last",
		}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		joined := strings.Join(f.events, "\n")
		for _, want := range []string{
			"run:update-cmd", "write:" + StateLastUpdate,
			"run:autoremove-cmd", "write:" + StateLastAutoremove,
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("events missing %q: %v", want, f.events)
			}
		}
	})
}

func TestBackendApplyFailures(t *testing.T) {
	b := newEngineFixture().backend()
	requireEngineError(t, b.apply(pluginapi.Context{}, &Spec{Update: "always"}), "host context is required")

	t.Run("lock", func(t *testing.T) {
		f := newEngineFixture()
		f.lockErr = errors.New("held")
		err := f.backend().apply(pluginapi.Context{Host: f.host()}, &Spec{Update: "always"})
		requireEngineError(t, err, "held")
		requireEngineEvents(t, f.events, []string{"lock"})
	})

	for _, tc := range []struct {
		name   string
		bad    string
		spec   *Spec
		prefix string
	}{
		{"update", "update-cmd", &Spec{Update: "always"}, "package index update failed"},
		{"upgrade", "upgrade-cmd", &Spec{Upgrade: "always"}, "package upgrade failed"},
		{"install", "install-cmd", &Spec{Install: []string{"pkg"}}, "package install failed"},
		{"purge", "purge-cmd", &Spec{Purge: []string{"pkg"}}, "package purge failed"},
		{"autoremove", "autoremove-cmd", &Spec{Autoremove: "always"}, "package autoremove failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEngineFixture()
			host := f.host()
			host.runErr = func(cmd string) error {
				if strings.Contains(cmd, tc.bad) {
					return errors.New("boom")
				}
				return nil
			}
			err := f.backend().apply(pluginapi.Context{Host: host}, tc.spec)
			requireEngineError(t, err, tc.prefix)
		})
	}

	t.Run("install query", func(t *testing.T) {
		f := newEngineFixture()
		f.queryErrors["pkg"] = errors.New("query failed")
		err := f.backend().apply(pluginapi.Context{Host: f.host()}, &Spec{
			Upgrade: "once", Install: []string{"pkg"},
		})
		requireEngineError(t, err, "query failed")
	})

	t.Run("purge query", func(t *testing.T) {
		f := newEngineFixture()
		f.queryErrors["old"] = errors.New("query failed")
		err := f.backend().apply(pluginapi.Context{Host: f.host()}, &Spec{
			Upgrade: "once", Purge: []string{"old"},
		})
		requireEngineError(t, err, "query failed")
	})

	for name, spec := range map[string]*Spec{
		"update mode":     {Update: "if_bad_since_last"},
		"upgrade mode":    {Upgrade: "if_bad_since_last"},
		"autoremove mode": {Autoremove: "if_bad_since_last"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEngineFixture()
			err := f.backend().apply(pluginapi.Context{Host: f.host()}, spec)
			requireEngineError(t, err, "if_bad_since_last")
		})
	}

	t.Run("purge preview", func(t *testing.T) {
		f := newEngineFixture()
		f.previewErrs["purge"] = errors.New("preview failed")
		err := f.backend().apply(pluginapi.Context{Host: f.host()}, &Spec{Purge: []string{"old"}})
		requireEngineError(t, err, "preview purge transaction")
	})

	t.Run("purge collateral", func(t *testing.T) {
		f := newEngineFixture()
		f.previews["purge"] = []string{"old", "dependency"}
		err := f.backend().apply(pluginapi.Context{Host: f.host()}, &Spec{Purge: []string{"old"}})
		requireEngineError(t, err, "dependency")
		if strings.Contains(strings.Join(f.events, "\n"), "run:purge-cmd") {
			t.Fatalf("purge ran after refusal: %v", f.events)
		}
	})
}

func TestBackendPlan(t *testing.T) {
	t.Run("collects state and every preview", func(t *testing.T) {
		f := newEngineFixture()
		f.queries["old"] = engineQueryResult{installed: true, version: "1", pin: "old=1"}
		f.previews["upgrade"] = []string{"base"}
		f.previews["install"] = []string{"pkg", "dependency"}
		f.previews["purge"] = []string{"old"}
		f.previews["autoremove"] = []string{"unused"}
		res, err := f.backend().plan(pluginapi.Context{Host: f.host()}, &Spec{
			Update: "always", Upgrade: "always", Autoremove: "always",
			Install: []string{"pkg"}, Purge: []string{"old"},
		})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !res.WillChange {
			t.Fatal("expected a changing plan")
		}
		joined := strings.Join(res.Diff, "\n")
		for _, want := range []string{"base", "pkg", "dependency", "old", "unused"} {
			if !strings.Contains(joined, want) {
				t.Errorf("diff missing %q: %v", want, res.Diff)
			}
		}
		requireEngineEvents(t, f.events, []string{
			"query:pkg", "query:old",
			"preview:upgrade", "preview:install:pkg", "preview:purge:old", "preview:autoremove",
		})
	})

	t.Run("preview failures are highlights", func(t *testing.T) {
		f := newEngineFixture()
		for _, kind := range []string{"upgrade", "install", "purge", "autoremove"} {
			f.previewErrs[kind] = errors.New(kind + " failed")
		}
		res, err := f.backend().plan(pluginapi.Context{Host: f.host()}, &Spec{
			Upgrade: "always", Autoremove: "always", Install: []string{"pkg"}, Purge: []string{"old"},
		})
		if err != nil {
			t.Fatalf("preview errors must not abandon plan: %v", err)
		}
		if len(res.Highlights) != 4 {
			t.Fatalf("got highlights %v", res.Highlights)
		}
	})

	t.Run("skipped operations do not preview", func(t *testing.T) {
		f := newEngineFixture()
		if _, err := f.backend().plan(pluginapi.Context{Host: f.host()}, &Spec{
			Upgrade: "never", Autoremove: "never",
		}); err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if strings.Contains(strings.Join(f.events, "\n"), "preview:") {
			t.Fatalf("a skipped operation was previewed: %v", f.events)
		}
	})
}

func TestBackendPlanFailures(t *testing.T) {
	b := newEngineFixture().backend()
	if _, err := b.plan(pluginapi.Context{}, &Spec{}); err == nil {
		t.Fatal("expected a host-required error")
	}

	for _, name := range []string{"install", "purge"} {
		t.Run(name+" query", func(t *testing.T) {
			f := newEngineFixture()
			f.queryErrors["bad"] = errors.New("query failed")
			spec := &Spec{}
			if name == "install" {
				spec.Install = []string{"bad"}
			} else {
				spec.Purge = []string{"bad"}
			}
			_, err := f.backend().plan(pluginapi.Context{Host: f.host()}, spec)
			requireEngineError(t, err, "query failed")
		})
	}

	for name, spec := range map[string]*Spec{
		"update":     {Update: "if_bad_since_last"},
		"upgrade":    {Upgrade: "if_bad_since_last"},
		"autoremove": {Autoremove: "if_bad_since_last"},
	} {
		t.Run(name+" mode", func(t *testing.T) {
			f := newEngineFixture()
			_, err := f.backend().plan(pluginapi.Context{Host: f.host()}, spec)
			requireEngineError(t, err, "invalid "+name+" mode")
		})
	}
}

func TestBackendCapture(t *testing.T) {
	f := newEngineFixture()
	f.queries["old"] = engineQueryResult{installed: true, version: "1.2", pin: "old=1.2"}
	b := f.backend()
	res, err := b.capture(pluginapi.Context{Host: f.host()}, "step-id", &Spec{
		Update: "always", Upgrade: "once", Autoremove: "always",
		Install: []string{"new"}, Purge: []string{"old"},
	})
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if res.RollbackMode != pluginapi.ModeBestEffort || len(res.Objects) != 2 || len(res.Notes) != 3 {
		t.Fatalf("capture metadata is wrong: %+v", res)
	}
	old := res.Objects[1].Package
	newPkg := res.Objects[0].Package
	if newPkg.Name != "new" || !newPkg.RequestedInstall || newPkg.WasInstalled {
		t.Fatalf("new package record is wrong: %+v", newPkg)
	}
	if old.Name != "old" || !old.RequestedPurge || !old.WasInstalled ||
		old.Version != "1.2" || old.PinSpec != "old=1.2" {
		t.Fatalf("old package record is wrong: %+v", old)
	}

	if _, err := b.capture(pluginapi.Context{}, "step-id", &Spec{}); err == nil {
		t.Fatal("expected a host-required error")
	}
	f.queryErrors["bad"] = errors.New("query failed")
	_, err = b.capture(pluginapi.Context{Host: f.host()}, "step-id", &Spec{Install: []string{"bad"}})
	requireEngineError(t, err, `step "step-id"`)
}

func TestBackendRestoreRemoval(t *testing.T) {
	t.Run("defaults to purge preview and command", func(t *testing.T) {
		f := newEngineFixture()
		host := f.host()
		if err := f.backend().restore(host, pluginapi.PackageState{
			Name: "pkg", RequestedInstall: true, WasInstalled: false,
		}); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}
		requireEngineEvents(t, f.events, []string{"preview:purge:pkg", "root:purge-cmd 'pkg'"})
	})

	t.Run("uses rollback overrides", func(t *testing.T) {
		f := newEngineFixture()
		b := f.backend()
		b.Commands.RollbackRemove = "rollback-remove-cmd"
		b.Previews.RollbackRemove = func(_ pluginapi.Host, names []string) ([]string, error) {
			f.record("preview:rollback:" + strings.Join(names, ","))
			return names, nil
		}
		if err := b.restore(f.host(), pluginapi.PackageState{Name: "pkg", RequestedInstall: true}); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}
		requireEngineEvents(t, f.events, []string{"preview:rollback:pkg", "root:rollback-remove-cmd 'pkg'"})
	})

	t.Run("preview failure", func(t *testing.T) {
		f := newEngineFixture()
		f.previewErrs["purge"] = errors.New("preview failed")
		err := f.backend().restore(f.host(), pluginapi.PackageState{Name: "pkg", RequestedInstall: true})
		requireEngineError(t, err, "preview removal")
	})

	t.Run("collateral refusal", func(t *testing.T) {
		f := newEngineFixture()
		f.previews["purge"] = []string{"pkg", "dependent"}
		err := f.backend().restore(f.host(), pluginapi.PackageState{Name: "pkg", RequestedInstall: true})
		requireEngineError(t, err, "dependent")
		if strings.Contains(strings.Join(f.events, "\n"), "root:purge-cmd") {
			t.Fatalf("remove ran after refusal: %v", f.events)
		}
	})

	t.Run("remove failure", func(t *testing.T) {
		f := newEngineFixture()
		host := f.host()
		host.runErr = func(string) error { return errors.New("remove failed") }
		err := f.backend().restore(host, pluginapi.PackageState{Name: "pkg", RequestedInstall: true})
		requireEngineError(t, err, "purge package")
	})
}

func TestBackendRestoreReinstall(t *testing.T) {
	t.Run("uses a valid pin", func(t *testing.T) {
		f := newEngineFixture()
		if err := f.backend().restore(f.host(), pluginapi.PackageState{
			Name: "pkg", WasInstalled: true, RequestedPurge: true, PinSpec: "pkg=1.2",
		}); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}
		requireEngineEvents(t, f.events, []string{"root:install-cmd 'pkg=1.2'"})
	})

	t.Run("falls back after a pinned install failure", func(t *testing.T) {
		f := newEngineFixture()
		host := f.host()
		host.runErr = func(cmd string) error {
			if strings.Contains(cmd, "=") {
				return errors.New("pin unavailable")
			}
			return nil
		}
		if err := f.backend().restore(host, pluginapi.PackageState{
			Name: "pkg", WasInstalled: true, RequestedPurge: true, PinSpec: "pkg=1.2",
		}); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}
		requireEngineEvents(t, f.events, []string{
			"root:install-cmd 'pkg=1.2'", "root:install-cmd 'pkg'",
		})
	})

	t.Run("rejects a malformed pin", func(t *testing.T) {
		f := newEngineFixture()
		if err := f.backend().restore(f.host(), pluginapi.PackageState{
			Name: "pkg", WasInstalled: true, RequestedPurge: true, PinSpec: "pkg=1.2 --force",
		}); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}
		requireEngineEvents(t, f.events, []string{"root:install-cmd 'pkg'"})
	})

	t.Run("fallback failure", func(t *testing.T) {
		f := newEngineFixture()
		host := f.host()
		host.runErr = func(string) error { return errors.New("install failed") }
		err := f.backend().restore(host, pluginapi.PackageState{
			Name: "pkg", WasInstalled: true, RequestedPurge: true,
		})
		requireEngineError(t, err, "reinstall package")
	})

	b := newEngineFixture().backend()
	requireEngineError(t, b.restore(newEngineFixture().host(), pluginapi.PackageState{Name: " "}), "name is empty")
	requireEngineError(t, b.restore(newEngineFixture().host(), pluginapi.PackageState{Name: "pkg;id"}), "invalid package name")
	if err := b.restore(newEngineFixture().host(), pluginapi.PackageState{Name: "pkg"}); err != nil {
		t.Fatalf("no-op restore failed: %v", err)
	}
}

func TestBackendConflict(t *testing.T) {
	t.Run("empty name", func(t *testing.T) {
		f := newEngineFixture()
		if got := f.backend().conflict(f.host(), pluginapi.PackageState{Name: " "}); got != nil {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("query failure", func(t *testing.T) {
		f := newEngineFixture()
		f.queryErrors["pkg"] = errors.New("query failed")
		got := f.backend().conflict(f.host(), pluginapi.PackageState{Name: "pkg", WasInstalled: true})
		if len(got) != 1 || !strings.Contains(got[0], "cannot read current state") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("installed state changed", func(t *testing.T) {
		f := newEngineFixture()
		got := f.backend().conflict(f.host(), pluginapi.PackageState{Name: "pkg", WasInstalled: true})
		if len(got) != 1 || !strings.Contains(got[0], "changed since apply") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("version changed", func(t *testing.T) {
		f := newEngineFixture()
		f.queries["pkg"] = engineQueryResult{installed: true, version: "2.0", pin: "pkg=2.0"}
		got := f.backend().conflict(f.host(), pluginapi.PackageState{
			Name: "pkg", WasInstalled: true, Version: "1.0",
		})
		if len(got) != 1 || !strings.Contains(got[0], "upgraded since apply") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("unchanged", func(t *testing.T) {
		f := newEngineFixture()
		f.queries["pkg"] = engineQueryResult{installed: true, version: "1.0", pin: "pkg=1.0"}
		if got := f.backend().conflict(f.host(), pluginapi.PackageState{
			Name: "pkg", WasInstalled: true, Version: "1.0",
		}); got != nil {
			t.Fatalf("got %v", got)
		}
	})
}
