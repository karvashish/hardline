package rollback

import (
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	newSSHClient       = connection.NewSSHClient
	runRootCmd         = remote.RunRoot
	writeRootFile      = remote.WriteRootFile
	newSFTPClient      = func(client *ssh.Client) (*sftp.Client, error) { return sftp.NewClient(client) }
	runRollbackCommand = rollbackCommand
	exitProcess        = os.Exit
)

func Rollback(c cli.Command) {
	if err := runRollbackCommand(c); err != nil {
		logger.Errorf("rollback failed: %v\n", err)
		exitProcess(1)
	}
}

func rollbackCommand(c cli.Command) error {
	target := strings.ToLower(strings.TrimSpace(c.Profile))
	if target == "" {
		target = "last"
	}
	if target != "last" {
		return fmt.Errorf("unsupported rollback target %q (only \"last\" is supported)", c.Profile)
	}

	if !c.Debug {
		logger.Infof("rollback %s\n", target)
	}

	journal, err := LoadLast(c.Host)
	if err != nil {
		return err
	}
	if journal.Status != "success" {
		return fmt.Errorf("last run is not marked successful (status=%q)", journal.Status)
	}

	cfg := connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}
	client, err := newSSHClient(cfg)
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	if client != nil {
		defer client.Close()
	}

	for i := len(journal.Steps) - 1; i >= 0; i-- {
		step := journal.Steps[i]
		if !c.Debug {
			logger.Infof("step: %s (%s) ", step.ID, step.Type)
		}
		if err := rollbackStep(client, step); err != nil {
			return fmt.Errorf("rollback step %q failed: %w", step.ID, err)
		}
		if !c.Debug {
			logger.Infof("✓\n")
		}
	}

	if !c.Debug {
		logger.Infof("ok\n")
	}
	return nil
}

func rollbackStep(client *ssh.Client, step StepRecord) error {
	if step.RollbackMode == ModeNoop {
		return nil
	}

	for i := len(step.Objects) - 1; i >= 0; i-- {
		obj := step.Objects[i]
		err := rollbackObject(client, obj)
		if err == nil {
			continue
		}
		if step.RollbackMode == ModeBestEffort {
			logger.Warnf("rollback warning (best-effort, step=%s): %v\n", step.ID, err)
			continue
		}
		return err
	}

	return nil
}

func rollbackObject(client *ssh.Client, obj ObjectRecord) error {
	switch obj.Kind {
	case ObjectFile:
		if obj.File == nil {
			return fmt.Errorf("file rollback object missing snapshot payload")
		}
		return restoreFile(client, *obj.File)
	case ObjectService:
		if obj.Service == nil {
			return fmt.Errorf("service rollback object missing snapshot payload")
		}
		return restoreService(client, *obj.Service)
	case ObjectPackage:
		if obj.Package == nil {
			return fmt.Errorf("package rollback object missing snapshot payload")
		}
		return rollbackPackageBestEffort(client, *obj.Package)
	case ObjectValidate:
		return nil
	default:
		return fmt.Errorf("unsupported rollback object kind %q", obj.Kind)
	}
}

func restoreFile(client *ssh.Client, snap FileSnapshot) error {
	if err := enforceManagedPath(snap.Path); err != nil {
		return err
	}

	if !snap.Existed {
		return runRootCmd(client, "rm -f "+strconv.Quote(snap.Path))
	}

	mode := os.FileMode(0o600)
	if strings.TrimSpace(snap.Mode) != "" {
		if parsed, err := strconv.ParseUint(strings.TrimSpace(snap.Mode), 8, 32); err == nil {
			mode = os.FileMode(parsed)
		}
	}

	content, err := base64.StdEncoding.DecodeString(snap.ContentB64)
	if err != nil {
		return fmt.Errorf("decode snapshot content for %q: %w", snap.Path, err)
	}

	dir := path.Dir(snap.Path)
	if dir != "" && dir != "." {
		if err := runRootCmd(client, "mkdir -p "+strconv.Quote(dir)); err != nil {
			return fmt.Errorf("ensure directory %q: %w", dir, err)
		}
	}

	sftpClient, err := newSFTPClient(client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	if sftpClient != nil {
		defer sftpClient.Close()
	}

	if err := writeRootFile(client, sftpClient, snap.Path, content, mode); err != nil {
		return fmt.Errorf("restore file %q: %w", snap.Path, err)
	}
	return nil
}

func restoreService(client *ssh.Client, state ServiceState) error {
	unit := strings.TrimSpace(state.Unit)
	if unit == "" {
		return fmt.Errorf("service unit is empty")
	}
	if !state.Known {
		return fmt.Errorf("service state for %q is unknown", unit)
	}

	enableCmd := "systemctl disable " + strconv.Quote(unit)
	if state.Enabled {
		enableCmd = "systemctl enable " + strconv.Quote(unit)
	}
	if err := runRootCmd(client, enableCmd); err != nil {
		return fmt.Errorf("restore service enabled state for %q: %w", unit, err)
	}

	activeCmd := "systemctl stop " + strconv.Quote(unit)
	if state.Active {
		activeCmd = "systemctl start " + strconv.Quote(unit)
	}
	if err := runRootCmd(client, activeCmd); err != nil {
		return fmt.Errorf("restore service active state for %q: %w", unit, err)
	}
	return nil
}

func rollbackPackageBestEffort(client *ssh.Client, p PackageState) error {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return fmt.Errorf("package name is empty")
	}

	// If this step installed a package that was previously absent, remove it.
	if p.RequestedInstall && !p.WasInstalled {
		if err := runRootCmd(client, "apt-get purge -y "+strconv.Quote(name)); err != nil {
			return fmt.Errorf("purge package %q: %w", name, err)
		}
	}

	// If this step purged a package that was previously present, try to bring it back.
	if p.RequestedPurge && p.WasInstalled {
		if p.Version != "" {
			withVersion := name + "=" + p.Version
			if err := runRootCmd(client, "DEBIAN_FRONTEND=noninteractive apt-get install -y "+strconv.Quote(withVersion)); err == nil {
				return nil
			}
		}
		if err := runRootCmd(client, "DEBIAN_FRONTEND=noninteractive apt-get install -y "+strconv.Quote(name)); err != nil {
			return fmt.Errorf("reinstall package %q: %w", name, err)
		}
	}

	return nil
}

func enforceManagedPath(dest string) error {
	p := strings.TrimSpace(dest)
	if p == "" {
		return fmt.Errorf("managed destination path is empty")
	}
	if !strings.HasPrefix(p, "/etc/") {
		return fmt.Errorf("destination %q is outside /etc managed scope", p)
	}
	cleaned := path.Clean(p)
	if cleaned != p {
		return fmt.Errorf("destination %q is not a normalized absolute path", p)
	}

	base := path.Base(p)
	if !strings.HasPrefix(base, "99-hardline") {
		return fmt.Errorf("destination %q must use high-priority hardline prefix 99-hardline*", p)
	}

	ext := strings.ToLower(path.Ext(base))
	switch ext {
	case ".conf", ".nft", ".rules":
		return nil
	default:
		return fmt.Errorf("destination %q has unsupported extension %q", p, ext)
	}
}
