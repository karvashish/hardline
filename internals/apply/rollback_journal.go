package apply

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func captureStepRecord(client *ssh.Client, p *profile.Profile, s profile.Step) (rollback.StepRecord, error) {
	stepType := strings.ToLower(strings.TrimSpace(s.Type))
	record := rollback.StepRecord{
		ID:   s.ID,
		Type: stepType,
	}
	if stepType == "validate" {
		record.RollbackMode = rollback.ModeNoop
		record.Objects = []rollback.ObjectRecord{
			{
				Kind:    rollback.ObjectValidate,
				Message: "validate step has no rollback action",
			},
		}
		return record, nil
	}

	handler, ok := pluginRegistry.LookupRollbackType(stepType)
	if !ok {
		record.RollbackMode = rollback.ModeNoop
		record.Objects = []rollback.ObjectRecord{
			{
				Kind:    rollback.ObjectValidate,
				Message: fmt.Sprintf("unknown step type %q captured as noop", s.Type),
			},
		}
		return record, nil
	}

	return handler.Capture(applyRollbackContext(client, p), s)
}
