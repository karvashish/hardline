package packages

import (
	"fmt"
	"regexp"
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

// lockProbeMarker prefixes the probe's answer. The marker is what separates
// "fuser reported no holder" from "the probe never ran": the two look identical
// on stdout, and only one of them means the lock is free.
const lockProbeMarker = "HL-LOCK:"

// lockPathRe bounds what a lock path may look like. The paths go into the probe
// unquoted, because one backend's lock is a glob and quoting it would make fuser
// look for a file named "*". They are compile-time constants of this repository
// and never profile input, so the shape is asserted at init and a violation is a
// build bug rather than something to handle at runtime.
var lockPathRe = regexp.MustCompile(`^/[A-Za-z0-9._*/-]+$`)

// LockProbe builds the lock probe for a backend's own lock paths. fuser must be
// present: a host that cannot answer the question has not answered it, and
// package operations must not start on an unanswered lock check.
func LockProbe(paths ...string) string {
	if len(paths) == 0 {
		panic("packages.LockProbe: no lock paths")
	}
	for _, p := range paths {
		if !lockPathRe.MatchString(p) {
			panic("packages.LockProbe: unsupported lock path " + p)
		}
	}
	return "command -v fuser >/dev/null 2>&1 || { echo 'fuser is not installed (package psmisc)' >&2; exit 3; }; " +
		"printf '%s' " + pluginapi.ShellArg(lockProbeMarker) + "; " +
		"fuser " + strings.Join(paths, " ") + " 2>/dev/null; echo"
}

// CheckLock reports the package manager's lock as held, using a probe built by
// LockProbe. A probe that fails or returns no verdict is an error: treating it
// as "unlocked" starts a transaction against a package manager that is already
// running one.
func CheckLock(host pluginapi.Host, lockCheck, lockHint string) error {
	if host == nil {
		return fmt.Errorf("host context is required to check the package manager lock")
	}
	out, err := host.RunRootWithOutput(lockCheck)
	if err != nil {
		return fmt.Errorf("package manager lock check failed: %w", err)
	}
	pids, ok := strings.CutPrefix(strings.TrimSpace(out), lockProbeMarker)
	if !ok {
		return fmt.Errorf("package manager lock check returned no verdict: %s", FirstLines(out, 3))
	}
	if pids = strings.TrimSpace(pids); pids != "" {
		return fmt.Errorf("package manager lock is held by another process (PIDs: %s); wait for it to finish or %s", pids, lockHint)
	}
	return nil
}

// GuardPurgeTransaction refuses a purge whose real transaction reaches past
// what the step declared. A purge is resolved outwards by every backend here,
// so the names in the profile are a request, not the transaction: the only
// honest way to run one is to read the transaction back first and stop when it
// contains a package nobody signed off on.
func GuardPurgeTransaction(purge, alsoRemoves, preview []string) error {
	want := make([]string, 0, len(purge)+len(alsoRemoves))
	want = append(want, purge...)
	want = append(want, alsoRemoves...)

	extra := UnexpectedRemovals(want, preview)
	if len(extra) == 0 {
		return nil
	}
	return fmt.Errorf(
		"refusing to purge %s: the transaction would also remove %s; list them in purge_also_removes to accept this",
		strings.Join(purge, ", "), strings.Join(extra, ", "))
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
