package apply

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	runRootCmd           = remote.RunRoot
	runRootCmdWithOutput = remote.RunRootWithOutput
	readRootFile         = remote.ReadRootFile
	newSFTPClient        = func(client *ssh.Client) (*sftp.Client, error) { return sftp.NewClient(client) }
	writeRootFile        = remote.WriteRootFile
	serviceDirty         = make(map[string]bool)
)

func resetApplyStepState() {
	serviceDirty = make(map[string]bool)
}

func normalizeServiceUnit(unit string) string {
	return strings.TrimSpace(unit)
}

func markServiceDirty(unit string) {
	u := normalizeServiceUnit(unit)
	if u == "" {
		return
	}
	serviceDirty[u] = true
}

func clearServiceDirty(unit string) {
	u := normalizeServiceUnit(unit)
	delete(serviceDirty, u)
}

func isServiceDirty(unit string) bool {
	u := normalizeServiceUnit(unit)
	return serviceDirty[u]
}

func handleStep(client *ssh.Client, p *profile.Profile, s profile.Step) error {
	stepType := strings.ToLower(strings.TrimSpace(s.Type))

	if stepType == "validate" {
		if strings.TrimSpace(s.Validate) == "" {
			return fmt.Errorf("step %q (type=%s): validate spec missing", s.ID, s.Type)
		}
		return handleValidate(client, p, s.Validate)
	}

	handler, ok := pluginRegistry.LookupApplyType(stepType)
	if !ok {
		logger.Warnf("warning: empty or unknown step type %q (id=%q)\n", s.Type, s.ID)
		return nil
	}

	return handler.Apply(applyActionContext(client, p), s)
}

func handleValidate(client *ssh.Client, p *profile.Profile, kind string) error {
	logger.Debugf("handleValidate: kind=%s\n", strings.ToLower(strings.TrimSpace(kind)))
	return applyValidateByKind(client, p, kind)
}
