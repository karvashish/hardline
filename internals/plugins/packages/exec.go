package packages

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

const PkgTimeoutSeconds = 1800

var sshTimeout = time.Duration(PkgTimeoutSeconds)*time.Second + 5*time.Minute

func RunRoot(host pluginapi.Host, cmd string) error {
	_, err := host.RunRootWithTimeout(cmd, sshTimeout)
	return err
}

func TimeoutCmd(tail string) string {
	return fmt.Sprintf("timeout %d %s", PkgTimeoutSeconds, tail)
}

func AppendPackages(cmd string, pkgs []string) string {
	quoted := make([]string, len(pkgs))
	for i, p := range pkgs {
		quoted[i] = pluginapi.ShellArg(p)
	}
	return cmd + " " + strings.Join(quoted, " ")
}

const lockProbeMarker = "HL-LOCK:"

var lockPathRe = regexp.MustCompile(`^/[A-Za-z0-9._*/-]+$`)

func LockProbe(paths ...string) string {
	if len(paths) == 0 {
		panic("packages.LockProbe: no lock paths")
	}
	for _, p := range paths {
		if !lockPathRe.MatchString(p) {
			panic("packages.LockProbe: unsupported lock path " + p)
		}
	}
	joined := strings.Join(paths, " ")
	return "printf '%s' " + pluginapi.ShellArg(lockProbeMarker) + "; " +
		"if command -v fuser >/dev/null 2>&1; then fuser " + joined + " 2>/dev/null; " +
		"else " + procLockHolders(joined) + "; fi; echo"
}

func procLockHolders(joined string) string {
	return "{ [ -d /proc/1/fd ] || { echo 'cannot read /proc to check the package manager lock, and fuser is not installed (package psmisc)' >&2; exit 3; }; " +
		"for fd in /proc/[0-9]*/fd/*; do " +
		`target=$(readlink "$fd" 2>/dev/null) || continue; ` +
		// A holder whose lock file was unlinked still holds it; /proc spells that target "<path> (deleted)".
		`target=${target%" (deleted)"}; ` +
		"for lock in " + joined + "; do " +
		`if [ "$target" = "$lock" ]; then ` +
		"pid=${fd#/proc/}; pid=${pid%%/*}; " +
		`printf '%s ' "$pid"; break; fi; ` +
		"done; done; }"
}

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
		return fmt.Errorf("package manager lock check returned no verdict: %s", pluginapi.FirstLines(out, 3))
	}
	if pids = strings.TrimSpace(pids); pids != "" {
		return fmt.Errorf("package manager lock is held by another process (PIDs: %s); wait for it to finish or %s", pids, lockHint)
	}
	return nil
}

func GuardPurgeTransaction(purge, alsoRemoves, preview []string) error {
	var want []string
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
