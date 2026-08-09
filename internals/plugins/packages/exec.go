package packages

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

// PkgTimeoutSeconds is the per-command deadline applied to every package
// manager invocation via the shell timeout(1) utility. This prevents wedged
// package operations from blocking automation indefinitely.
const PkgTimeoutSeconds = 1800 // 30 minutes

// sshTimeout is the SSH session deadline for package commands. It must exceed
// PkgTimeoutSeconds so the shell-level timeout fires first and returns a
// meaningful error; the SSH deadline is the outer safety net.
var sshTimeout = time.Duration(PkgTimeoutSeconds)*time.Second + 5*time.Minute

// RunRoot runs one package manager command under the outer SSH deadline.
func RunRoot(host pluginapi.Host, cmd string) error {
	_, err := host.RunRootWithTimeout(cmd, sshTimeout)
	return err
}

// TimeoutCmd applies the per-command deadline to a command tail.
func TimeoutCmd(tail string) string {
	return fmt.Sprintf("timeout %d %s", PkgTimeoutSeconds, tail)
}

// AppendPackages quotes and appends package names to a command.
func AppendPackages(cmd string, pkgs []string) string {
	quoted := make([]string, len(pkgs))
	for i, p := range pkgs {
		quoted[i] = pluginapi.ShellArg(p)
	}
	return cmd + " " + strings.Join(quoted, " ")
}

// Installed runs the caller's own "is this installed" probe.
func Installed(host pluginapi.Host, installedFmt, name string) bool {
	if host == nil {
		return false
	}
	return host.RunRoot(fmt.Sprintf(installedFmt, pluginapi.ShellArg(name))) == nil
}

// CheckLock reports the package manager's lock as held, using the caller's own
// lock paths. A failing probe is not an answer, so it is treated as unlocked.
func CheckLock(host pluginapi.Host, lockCheck, lockHint string) error {
	out, err := host.RunRootWithOutput(lockCheck)
	if err != nil {
		return nil
	}
	if pids := strings.TrimSpace(out); pids != "" {
		return fmt.Errorf("package manager lock is held by another process (PIDs: %s); wait for it to finish or %s", pids, lockHint)
	}
	return nil
}

// FirstLines trims a command's output down to something an error can carry.
func FirstLines(out string, n int) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}

// Targets is the sorted set of packages a step touches, with the two membership
// sets capture needs to record what was requested.
func Targets(installList, purgeList []string) (names []string, install, purge map[string]struct{}) {
	all := map[string]struct{}{}
	install = map[string]struct{}{}
	purge = map[string]struct{}{}

	for _, raw := range installList {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		all[name] = struct{}{}
		install[name] = struct{}{}
	}
	for _, raw := range purgeList {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		all[name] = struct{}{}
		purge[name] = struct{}{}
	}

	names = make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, install, purge
}

// CaptureNotes are the irreversibility notes every backend records for the
// operations that cannot be undone exactly.
func CaptureNotes(update, upgrade, autoremove string) []string {
	var notes []string
	if update != "" && update != "never" {
		notes = append(notes, "package index update is not directly reversible")
	}
	if upgrade != "" && upgrade != "never" {
		notes = append(notes, "package upgrade rollback is best-effort")
	}
	if autoremove != "" && autoremove != "never" {
		notes = append(notes, "autoremove rollback is best-effort")
	}
	return notes
}
