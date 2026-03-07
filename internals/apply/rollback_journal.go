package apply

import (
	"encoding/base64"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func captureStepRecord(client *ssh.Client, s profile.Step) (rollback.StepRecord, error) {
	stepType := strings.ToLower(strings.TrimSpace(s.Type))
	record := rollback.StepRecord{
		ID:   s.ID,
		Type: stepType,
	}

	switch stepType {
	case "template":
		if s.Template == nil {
			return record, fmt.Errorf("step %q (type=%s): template spec missing", s.ID, s.Type)
		}
		dest := strings.TrimSpace(s.Template.Dest)
		if err := enforceManagedPath(dest); err != nil {
			return record, fmt.Errorf("step %q (type=%s): %w", s.ID, s.Type, err)
		}
		snap, err := snapshotRemoteFile(client, dest)
		if err != nil {
			return record, fmt.Errorf("capture template snapshot for %q: %w", dest, err)
		}
		record.RollbackMode = rollback.ModeDeterministic
		record.Objects = []rollback.ObjectRecord{
			{Kind: rollback.ObjectFile, File: &snap},
		}
		return record, nil

	case "firewall":
		if s.Firewall == nil {
			return record, fmt.Errorf("step %q (type=%s): firewall spec missing", s.ID, s.Type)
		}
		dest := strings.TrimSpace(s.Firewall.TemplateDest)
		if dest == "" {
			dest = defaultManagedFirewallDest
		}
		if err := enforceManagedPath(dest); err != nil {
			return record, fmt.Errorf("step %q (type=%s): %w", s.ID, s.Type, err)
		}
		snap, err := snapshotRemoteFile(client, dest)
		if err != nil {
			return record, fmt.Errorf("capture firewall snapshot for %q: %w", dest, err)
		}
		record.RollbackMode = rollback.ModeDeterministic
		record.Objects = []rollback.ObjectRecord{
			{Kind: rollback.ObjectFile, File: &snap},
		}
		return record, nil

	case "service":
		if s.Service == nil {
			return record, fmt.Errorf("step %q (type=%s): service spec missing", s.ID, s.Type)
		}
		unit := canonicalServiceUnit(s.Service.Name)
		state, err := snapshotServiceState(client, unit)
		if err != nil {
			return record, fmt.Errorf("capture service snapshot for %q: %w", unit, err)
		}
		record.RollbackMode = rollback.ModeDeterministic
		record.Objects = []rollback.ObjectRecord{
			{Kind: rollback.ObjectService, Service: &state},
		}
		return record, nil

	case "packages":
		if s.Packages == nil {
			return record, fmt.Errorf("step %q (type=%s): packages spec missing", s.ID, s.Type)
		}
		pkgs, err := snapshotPackageState(client, s.Packages)
		if err != nil {
			return record, err
		}
		record.RollbackMode = rollback.ModeBestEffort
		record.Objects = pkgs
		if s.Packages.Update {
			record.Notes = append(record.Notes, "apt update is not directly reversible")
		}
		if s.Packages.Upgrade {
			record.Notes = append(record.Notes, "apt upgrade rollback is best-effort")
		}
		if s.Packages.Autoremove {
			record.Notes = append(record.Notes, "apt autoremove rollback is best-effort")
		}
		return record, nil

	case "validate":
		record.RollbackMode = rollback.ModeNoop
		record.Objects = []rollback.ObjectRecord{
			{
				Kind:    rollback.ObjectValidate,
				Message: "validate step has no rollback action",
			},
		}
		return record, nil

	default:
		record.RollbackMode = rollback.ModeNoop
		record.Objects = []rollback.ObjectRecord{
			{
				Kind:    rollback.ObjectValidate,
				Message: fmt.Sprintf("unknown step type %q captured as noop", s.Type),
			},
		}
		return record, nil
	}
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

func snapshotRemoteFile(client *ssh.Client, remotePath string) (rollback.FileSnapshot, error) {
	snap := rollback.FileSnapshot{Path: remotePath}

	testCmd := "test -e " + strconv.Quote(remotePath)
	if err := runRootCmd(client, testCmd); err != nil {
		snap.Existed = false
		return snap, nil
	}
	snap.Existed = true

	modeCmd := "stat -c %a " + strconv.Quote(remotePath)
	modeOut, err := runRootCmdWithOutput(client, modeCmd)
	if err != nil {
		return snap, err
	}
	snap.Mode = strings.TrimSpace(modeOut)

	content, err := readRootFile(client, remotePath)
	if err != nil {
		return snap, err
	}
	snap.ContentB64 = base64.StdEncoding.EncodeToString([]byte(content))
	return snap, nil
}

func canonicalServiceUnit(name string) string {
	unit := strings.TrimSpace(name)
	if unit == "sshd" {
		return "ssh"
	}
	return unit
}

func snapshotServiceState(client *ssh.Client, unit string) (rollback.ServiceState, error) {
	enabledOut, err := runRootCmdWithOutput(client, "systemctl is-enabled "+strconv.Quote(unit)+" 2>/dev/null || true")
	if err != nil {
		return rollback.ServiceState{}, err
	}

	activeOut, err := runRootCmdWithOutput(client, "systemctl is-active "+strconv.Quote(unit)+" 2>/dev/null || true")
	if err != nil {
		return rollback.ServiceState{}, err
	}

	enabledVal := strings.TrimSpace(enabledOut)
	activeVal := strings.TrimSpace(activeOut)
	return rollback.ServiceState{
		Unit:    unit,
		Enabled: enabledVal == "enabled",
		Active:  activeVal == "active",
		Known:   enabledVal != "" || activeVal != "",
	}, nil
}

func snapshotPackageState(client *ssh.Client, pk *profile.PackageSpec) ([]rollback.ObjectRecord, error) {
	pkgSet := map[string]struct{}{}
	installSet := map[string]struct{}{}
	purgeSet := map[string]struct{}{}

	for _, name := range pk.Install {
		n := strings.TrimSpace(name)
		if n == "" {
			continue
		}
		pkgSet[n] = struct{}{}
		installSet[n] = struct{}{}
	}
	for _, name := range pk.Purge {
		n := strings.TrimSpace(name)
		if n == "" {
			continue
		}
		pkgSet[n] = struct{}{}
		purgeSet[n] = struct{}{}
	}

	names := make([]string, 0, len(pkgSet))
	for name := range pkgSet {
		names = append(names, name)
	}
	sort.Strings(names)

	records := make([]rollback.ObjectRecord, 0, len(names))
	for _, name := range names {
		cmd := "dpkg-query -W -f='${Status}\\t${Version}' " + strconv.Quote(name) + " 2>/dev/null || true"
		out, err := runRootCmdWithOutput(client, cmd)
		if err != nil {
			return nil, fmt.Errorf("capture package state for %q: %w", name, err)
		}

		raw := strings.TrimSpace(out)
		state := rollback.PackageState{
			Name:             name,
			RequestedInstall: inSet(installSet, name),
			RequestedPurge:   inSet(purgeSet, name),
		}

		if strings.HasPrefix(raw, "install ok installed\t") {
			state.WasInstalled = true
			state.Version = strings.TrimPrefix(raw, "install ok installed\t")
		} else if raw == "install ok installed" {
			state.WasInstalled = true
		}

		records = append(records, rollback.ObjectRecord{
			Kind:    rollback.ObjectPackage,
			Package: &state,
		})
	}
	return records, nil
}

func inSet(set map[string]struct{}, name string) bool {
	_, ok := set[name]
	return ok
}
