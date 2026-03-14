package registry

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestSharedReturnsSingleton(t *testing.T) {
	if Shared() == nil {
		t.Fatal("expected shared registry")
	}
	if Shared() != sharedRegistry {
		t.Fatal("expected Shared to return package singleton")
	}
}

func TestNewDefaultRegistryIncludesBuiltins(t *testing.T) {
	reg := NewDefaultRegistry()
	if reg == nil {
		t.Fatal("expected default registry")
	}

	for _, name := range []string{"packages", "template", "service", "firewall"} {
		plugin, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("missing builtin plugin %q", name)
		}
		if !plugin.InternalValidation {
			t.Fatalf("expected builtin plugin %q to validate internally", name)
		}
	}
}

func TestNewRegistrySFTPClientPanicsOnNilClient(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	_, _ = newRegistrySFTPClient(nil)
}

func TestNewDefaultRegistryPanicsOnRegisterError(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		if !strings.Contains(r.(string), "register default plugin bundle") {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	_ = newDefaultRegistry(func(*pluginapi.Registry, pluginapi.PluginBundle) error {
		return errors.New("boom")
	})
}
