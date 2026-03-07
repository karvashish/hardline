package builtin

import (
	"os"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/firewall"
	"github.com/karvashish/hardline/internals/plugins/firewalltemplate"
	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/internals/plugins/service"
	"github.com/karvashish/hardline/internals/plugins/template"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type ApplyDeps struct {
	RunRoot           func(*ssh.Client, string) error
	NewSFTPClient     func(*ssh.Client) (*sftp.Client, error)
	WriteRootFile     func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error
	MarkServiceDirty  func(string)
	IsServiceDirty    func(string) bool
	ClearServiceDirty func(string)
}

type RollbackDeps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
}

func DefaultApplyHandlers(deps ApplyDeps) []pluginapi.ApplyHandler {
	return []pluginapi.ApplyHandler{
		packages.DefaultApplyHandler(packages.ApplyDeps{
			RunRoot: deps.RunRoot,
		}),
		template.DefaultApplyHandler(template.ApplyDeps{
			RunRoot:          deps.RunRoot,
			NewSFTPClient:    deps.NewSFTPClient,
			WriteRootFile:    deps.WriteRootFile,
			MarkServiceDirty: deps.MarkServiceDirty,
		}),
		service.DefaultApplyHandler(service.ApplyDeps{
			RunRoot:           deps.RunRoot,
			IsServiceDirty:    deps.IsServiceDirty,
			ClearServiceDirty: deps.ClearServiceDirty,
		}),
		firewall.DefaultApplyHandler(firewall.ApplyDeps{
			RunRoot:          deps.RunRoot,
			NewSFTPClient:    deps.NewSFTPClient,
			WriteRootFile:    deps.WriteRootFile,
			MarkServiceDirty: deps.MarkServiceDirty,
		}),
		firewalltemplate.DefaultApplyHandler(firewalltemplate.ApplyDeps{
			RunRoot:          deps.RunRoot,
			NewSFTPClient:    deps.NewSFTPClient,
			WriteRootFile:    deps.WriteRootFile,
			MarkServiceDirty: deps.MarkServiceDirty,
		}),
	}
}

func DefaultPlanHandlers() []pluginapi.PlanHandler {
	return []pluginapi.PlanHandler{
		packages.DefaultPlanHandler(),
		template.DefaultPlanHandler(),
		service.DefaultPlanHandler(),
		firewall.DefaultPlanHandler(),
		firewalltemplate.DefaultPlanHandler(),
	}
}

func DefaultRollbackHandlers(deps RollbackDeps) []pluginapi.RollbackHandler {
	return []pluginapi.RollbackHandler{
		{
			Type: "validate",
			Capture: func(_ pluginapi.RollbackContext, s profile.Step) (rollback.StepRecord, error) {
				return rollback.StepRecord{
					ID:           s.ID,
					Type:         strings.ToLower(strings.TrimSpace(s.Type)),
					RollbackMode: rollback.ModeNoop,
					Objects: []rollback.ObjectRecord{
						{
							Kind:    rollback.ObjectValidate,
							Message: "validate step has no rollback action",
						},
					},
				}, nil
			},
		},
		packages.DefaultRollbackHandler(packages.RollbackDeps{
			RunRootWithOutput: deps.RunRootWithOutput,
		}),
		template.DefaultRollbackHandler(template.RollbackDeps{
			RunRoot:           deps.RunRoot,
			RunRootWithOutput: deps.RunRootWithOutput,
			ReadRootFile:      deps.ReadRootFile,
		}),
		service.DefaultRollbackHandler(service.RollbackDeps{
			RunRootWithOutput: deps.RunRootWithOutput,
		}),
		firewall.DefaultRollbackHandler(firewall.RollbackDeps{
			RunRoot:           deps.RunRoot,
			RunRootWithOutput: deps.RunRootWithOutput,
			ReadRootFile:      deps.ReadRootFile,
		}),
		firewalltemplate.DefaultRollbackHandler(firewalltemplate.RollbackDeps{
			RunRoot:           deps.RunRoot,
			RunRootWithOutput: deps.RunRootWithOutput,
			ReadRootFile:      deps.ReadRootFile,
		}),
	}
}
