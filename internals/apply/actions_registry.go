package apply

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/builtin"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

var pluginRegistry = newDefaultPluginRegistry()

func PluginRegistry() *pluginapi.Registry {
	return pluginRegistry
}

func RegisterApplyAction(h pluginapi.ApplyHandler) error {
	return pluginRegistry.RegisterApply(h)
}

func RegisterPlanAction(h pluginapi.PlanHandler) error {
	return pluginRegistry.RegisterPlan(h)
}

func RegisterRollbackAction(h pluginapi.RollbackHandler) error {
	return pluginRegistry.RegisterRollback(h)
}

func RegisterPluginBundle(bundle pluginapi.PluginBundle) error {
	return pluginRegistry.RegisterBundle(bundle)
}

func newDefaultPluginRegistry() *pluginapi.Registry {
	r := pluginapi.NewRegistry()

	bundle := builtin.DefaultBundle(
		builtin.ApplyDeps{
			RunRoot:           runRootCmd,
			NewSFTPClient:     newSFTPClient,
			WriteRootFile:     writeRootFile,
			MarkServiceDirty:  markServiceDirty,
			IsServiceDirty:    isServiceDirty,
			ClearServiceDirty: clearServiceDirty,
		},
		builtin.RollbackDeps{
			RunRoot:           runRootCmd,
			RunRootWithOutput: runRootCmdWithOutput,
			ReadRootFile:      readRootFile,
		},
	)
	if err := r.RegisterBundle(bundle); err != nil {
		panic(fmt.Sprintf("register default plugin bundle %q: %v", bundle.Name, err))
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
	validateFn, ok := pluginRegistry.LookupApplyValidate(kind)
	if !ok {
		return fmt.Errorf("unsupported validate kind %q", strings.TrimSpace(kind))
	}
	return validateFn(applyActionContext(client, p))
}
