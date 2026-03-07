package apply

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/builtin"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

var applyActionRegistry = newDefaultApplyRegistry()
var applyRollbackRegistry = newDefaultRollbackRegistry()

func RegisterApplyAction(h pluginapi.ApplyHandler) error {
	return applyActionRegistry.Register(h)
}

func RegisterRollbackAction(h pluginapi.RollbackHandler) error {
	return applyRollbackRegistry.Register(h)
}

func newDefaultApplyRegistry() *pluginapi.ApplyRegistry {
	r := pluginapi.NewApplyRegistry()

	for _, h := range builtin.DefaultApplyHandlers(builtin.ApplyDeps{
		RunRoot:           runRootCmd,
		NewSFTPClient:     newSFTPClient,
		WriteRootFile:     writeRootFile,
		MarkServiceDirty:  markServiceDirty,
		IsServiceDirty:    isServiceDirty,
		ClearServiceDirty: clearServiceDirty,
	}) {
		if err := r.Register(h); err != nil {
			panic(fmt.Sprintf("register default apply action %q: %v", h.Type, err))
		}
	}

	return r
}

func newDefaultRollbackRegistry() *pluginapi.RollbackRegistry {
	r := pluginapi.NewRollbackRegistry()

	for _, h := range builtin.DefaultRollbackHandlers(builtin.RollbackDeps{
		RunRoot:           runRootCmd,
		RunRootWithOutput: runRootCmdWithOutput,
		ReadRootFile:      readRootFile,
	}) {
		if err := r.Register(h); err != nil {
			panic(fmt.Sprintf("register default rollback action %q: %v", h.Type, err))
		}
	}

	return r
}

func applyActionContext(client *ssh.Client, p *profile.Profile) pluginapi.ApplyContext {
	return pluginapi.ApplyContext{
		Client:  client,
		Profile: p,
	}
}

func applyRollbackContext(client *ssh.Client, p *profile.Profile) pluginapi.RollbackContext {
	return pluginapi.RollbackContext{
		Client:  client,
		Profile: p,
	}
}

func applyValidateByKind(client *ssh.Client, p *profile.Profile, kind string) error {
	validateFn, ok := applyActionRegistry.LookupValidate(kind)
	if !ok {
		return fmt.Errorf("unsupported validate kind %q", strings.TrimSpace(kind))
	}
	return validateFn(applyActionContext(client, p))
}
