package pluginapi

import (
	"encoding/base64"
	"fmt"
	"path"
	"strconv"
	"strings"
)

func CapturesDiffer(before, after CaptureResult) bool {
	if len(before.Objects) != len(after.Objects) {
		return true
	}
	for i := range before.Objects {
		b, a := before.Objects[i], after.Objects[i]
		if b.Kind != a.Kind {
			return true
		}
		switch b.Kind {
		case ObjectFile:
			if b.File == nil || a.File == nil {
				return b.File != a.File
			}
			if b.File.Existed != a.File.Existed || b.File.ContentB64 != a.File.ContentB64 {
				return true
			}
		case ObjectService:
			if b.Service == nil || a.Service == nil {
				return b.Service != a.Service
			}
			if b.Service.Active != a.Service.Active || b.Service.Enabled != a.Service.Enabled {
				return true
			}
		case ObjectPackage:
			if b.Package == nil || a.Package == nil {
				return b.Package != a.Package
			}
			if b.Package.WasInstalled != a.Package.WasInstalled {
				return true
			}
		}
	}
	return false
}

func EnforceManagedPath(dest string) error {
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

func SnapshotRemoteFile(host Host, remotePath string) (FileSnapshot, error) {
	if host == nil {
		return FileSnapshot{}, fmt.Errorf("host is required")
	}

	snap := FileSnapshot{Path: remotePath}

	testCmd := "test -e " + strconv.Quote(remotePath)
	if err := host.RunRoot(testCmd); err != nil {
		snap.Existed = false
		return snap, nil
	}
	snap.Existed = true

	modeCmd := "stat -c %a " + strconv.Quote(remotePath)
	modeOut, err := host.RunRootWithOutput(modeCmd)
	if err != nil {
		return snap, err
	}
	snap.Mode = strings.TrimSpace(modeOut)

	content, err := host.ReadRootFile(remotePath)
	if err != nil {
		return snap, err
	}
	snap.ContentB64 = base64.StdEncoding.EncodeToString([]byte(content))
	return snap, nil
}

func SnapshotServiceState(host Host, unit string) (ServiceState, error) {
	if host == nil {
		return ServiceState{}, fmt.Errorf("host is required")
	}

	enabledOut, err := host.RunRootWithOutput("systemctl is-enabled " + strconv.Quote(unit) + " 2>/dev/null || true")
	if err != nil {
		return ServiceState{}, err
	}

	activeOut, err := host.RunRootWithOutput("systemctl is-active " + strconv.Quote(unit) + " 2>/dev/null || true")
	if err != nil {
		return ServiceState{}, err
	}

	enabledVal := strings.TrimSpace(enabledOut)
	activeVal := strings.TrimSpace(activeOut)
	return ServiceState{
		Unit:    unit,
		Enabled: enabledVal == "enabled",
		Active:  activeVal == "active",
		Known:   enabledVal != "" || activeVal != "",
	}, nil
}
