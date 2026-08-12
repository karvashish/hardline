package firewall

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

// The nftables service reads a different main config per distribution family:
// Debian-family ships /etc/nftables.conf, RHEL-family /etc/sysconfig/nftables.conf.
// The profile picks one of the two; anything else is rejected, because this path
// is appended to as root and restored from the journal on rollback.
const (
	MainConfigDebian = "/etc/nftables.conf"
	MainConfigRHEL   = "/etc/sysconfig/nftables.conf"
)

func ValidMainConfig(p string) bool {
	switch strings.TrimSpace(p) {
	case MainConfigDebian, MainConfigRHEL:
		return true
	default:
		return false
	}
}

// IncludeLine is the line apply appends to the main config. It names the exact
// file this step manages, not its directory: several profiles can own files in
// the same drop-in directory, and a glob would make each of them load the
// others' rules and make the evaluation order between them a function of their
// filenames.
func IncludeLine(dest string) string {
	return fmt.Sprintf(`include "%s"`, dest)
}

// includeCheckCmd matches this file's own include line and nothing else, with
// or without quotes, so a line already present is not duplicated and another
// profile's include is never mistaken for this one.
func includeCheckCmd(mainConfig, dest string) string {
	return fmt.Sprintf(`grep -E -q '^[[:space:]]*include[[:space:]]+"?%s"?[[:space:]]*$' %s 2>/dev/null`,
		escapeIncludeRegex(dest), pluginapi.ShellArg(mainConfig))
}

// legacyGlobCheckCmd finds the directory-wide include earlier hardline versions
// wrote. Leaving it in place next to an exact include would load this file
// twice in one transaction, so apply refuses rather than duplicating rules.
func legacyGlobCheckCmd(mainConfig, dest string) string {
	glob := escapeIncludeRegex(path.Dir(dest) + "/*.nft")
	return fmt.Sprintf(`grep -E -q '^[[:space:]]*include[[:space:]]+"?%s"?[[:space:]]*$' %s 2>/dev/null`,
		glob, pluginapi.ShellArg(mainConfig))
}

// escapeIncludeRegex quotes the characters EnforceManagedPath allows that mean
// something to a POSIX ERE.
func escapeIncludeRegex(p string) string {
	var b strings.Builder
	for _, r := range p {
		switch r {
		case '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

type NormalizedSpec struct {
	Family   string
	Table    string
	Policies map[string]string
	Rules    []NormalizedRule
}

type NormalizedRule struct {
	Chain        string
	Action       string
	Proto        string
	Port         int
	Source       string
	Destination  string
	InInterface  string
	OutInterface string
	CTStates     []string
}

type NormalizedDiff struct {
	PolicyChanges []string
	RulesToAdd    []NormalizedRule
	RulesToRemove []NormalizedRule
	// Reordered names the chains whose rules are all present but evaluated in a
	// different order than declared.
	Reordered []string
}

type firewallStatRuntime interface {
	RunRoot(cmd string) error
	RunRootWithOutput(cmd string) (string, error)
}

type firewallCompareRuntime interface {
	firewallStatRuntime
	ReadRootFile(path string) (string, error)
}

func Apply(ctx pluginapi.Context, fw *Spec) error {
	logger.Debugf("handleFirewall: backend=%q policies=%d rules=%d\n", fw.Backend, len(fw.Policies), len(fw.Rules))

	if fw.Backend != "nftables" {
		return fmt.Errorf("unsupported firewall backend %q", fw.Backend)
	}
	if ctx.Host == nil {
		return fmt.Errorf("firewall step: host context is required")
	}

	desired, err := NormalizeDesiredSpec(fw)
	if err != nil {
		return err
	}
	destPath := ManagedDestination(fw)
	if destPath == "" {
		return fmt.Errorf("firewall managed_dest is required")
	}

	dir := path.Dir(destPath)
	if dir != "" && dir != "." {
		if err := ctx.Host.RunRoot("mkdir -p " + pluginapi.ShellArg(dir)); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", dir, err)
		}
	}

	desiredRendered := RenderNormalized(desired)
	matches, err := firewallDestinationMatches(ctx.Host, destPath, desiredRendered, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("compare destination %s: %w", destPath, err)
	}
	if !matches {
		if err := installFirewallCandidate(ctx.Host, destPath, desiredRendered); err != nil {
			return err
		}
		logger.Debugf("handleFirewall: rendered deterministic firewall rules to %q\n", destPath)
	} else {
		logger.Debugf("handleFirewall: destination %q already matches, skipping write\n", destPath)
	}

	// The flush header comes first so a load produces exactly what the file
	// says, then the include, which goes in only after the file it names
	// exists: an include pointing at a missing file fails every nft load on the
	// host, including the one this step is about to ask for.
	if err := EnsureNftablesFlush(ctx.Host, fw.MainConfig); err != nil {
		return err
	}
	return EnsureNftablesInclude(ctx.Host, fw.MainConfig, destPath)
}

// ActivateFirewall loads the main config into the kernel and proves the running
// ruleset is the one that was asked for. Writing the file is not what protects
// a host: until something loads it, the kernel keeps whatever it had, so a
// profile that only wrote a file was hardened on disk and open in practice.
func ActivateFirewall(host pluginapi.Host, mainConfig string, desired NormalizedSpec) error {
	if host == nil {
		return fmt.Errorf("firewall step: host context is required")
	}
	if !ValidMainConfig(mainConfig) {
		return fmt.Errorf("unsupported firewall main_config %q", mainConfig)
	}

	if err := assertManagementAccess(host, desired); err != nil {
		return err
	}

	// One file, one transaction: the flush and every table in it commit
	// together, so there is no moment where the host has no rules. A service
	// restart would do this as stop-then-start, and its stop flushes the
	// ruleset on its own.
	if out, err := host.RunRootWithOutput("nft -f " + pluginapi.ShellArg(mainConfig) + " 2>&1"); err != nil {
		if detail := firstNftLines(out, 5); detail != "" {
			return fmt.Errorf("load %s: %s", mainConfig, detail)
		}
		return fmt.Errorf("load %s: %w", mainConfig, err)
	}

	live, err := currentFirewallState(host, desired.Family, desired.Table)
	if err != nil {
		return fmt.Errorf("read back the loaded ruleset: %w", err)
	}
	if drift := renderFirewallStateDiff(live, desired); len(drift) > 0 {
		return fmt.Errorf("the loaded ruleset is not what was applied:\n  %s", strings.Join(drift, "\n  "))
	}
	return nil
}

// assertManagementAccess refuses to load a ruleset that would not accept the
// port sshd is listening on. A drop policy with no rule for that port takes the
// host away from whoever applied it, and the run cannot undo what it can no
// longer reach.
func assertManagementAccess(host pluginapi.Host, desired NormalizedSpec) error {
	policy := desired.Policies["input"]
	if policy != "drop" && policy != "reject" {
		return nil
	}

	ports, err := sshdListeningPorts(host)
	if err != nil {
		return err
	}
	for _, port := range ports {
		if acceptsInputPort(desired, port) {
			return nil
		}
	}
	return fmt.Errorf(
		"refusing to load: the input chain policy is %q and no rule accepts tcp on the port sshd is listening on (%s); "+
			"add an accept rule for it, or hardline would lock itself out of this host",
		policy, joinPorts(ports))
}

// sshdListeningPorts reads the ports sshd is actually listening on. It fails
// closed: a probe that cannot answer is not evidence that a lockout is safe.
func sshdListeningPorts(host pluginapi.Host) ([]int, error) {
	out, err := host.RunRootWithOutput("ss -Hltnp 2>/dev/null")
	if err != nil {
		return nil, fmt.Errorf("probe the listening ssh ports: %w", err)
	}

	seen := make(map[int]struct{})
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "sshd") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		port, convErr := strconv.Atoi(local[idx+1:])
		if convErr != nil || port < 1 || port > 65535 {
			continue
		}
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("could not determine which port sshd is listening on; refusing to load a ruleset that may lock this host out")
	}
	sort.Ints(ports)
	return ports, nil
}

// acceptsInputPort reports whether the ruleset lets a new connection to port
// reach sshd. Only rules with no address or interface narrowing count: one that
// accepts a single source address does not keep the host reachable in general.
func acceptsInputPort(desired NormalizedSpec, port int) bool {
	for _, rule := range desired.Rules {
		if rule.Chain != "input" || rule.Action != "accept" || rule.Proto != "tcp" || rule.Port != port {
			continue
		}
		if rule.Source != "" || rule.Destination != "" || rule.InInterface != "" || rule.OutInterface != "" {
			continue
		}
		return true
	}
	return false
}

func joinPorts(ports []int) string {
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, strconv.Itoa(port))
	}
	return strings.Join(out, ", ")
}

// firstNftLines trims nft's complaint down to something an error can carry. nft
// prints the offending line and a caret ruler, which is the useful part.
func firstNftLines(out string, n int) string {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}

// candidateSuffix names the staging file. It sits beside the destination so the
// move into place is a rename on one filesystem, and it is not the file the
// main config includes, so nothing loads it while it is being checked.
const candidateSuffix = ".hardline-candidate"

// installFirewallCandidate writes the ruleset to a staging path, has nft parse
// it there, and only then moves it into place. Writing first and checking after
// leaves a file the host would fail to load sitting where the host will load
// it, which is exactly the state a firewall step must never produce.
func installFirewallCandidate(host pluginapi.Host, destPath, rendered string) error {
	candidate := destPath + candidateSuffix

	if err := host.WriteRootFile(candidate, []byte(rendered), os.FileMode(0644)); err != nil {
		return fmt.Errorf("write firewall candidate %s: %w", candidate, err)
	}

	out, checkErr := host.RunRootWithOutput("nft -c -f " + pluginapi.ShellArg(candidate) + " 2>&1")
	if checkErr != nil {
		if rmErr := host.RunRoot("rm -f " + pluginapi.ShellArg(candidate)); rmErr != nil {
			logger.Warnf("firewall: could not remove the rejected candidate %s: %v\n", candidate, rmErr)
		}
		if detail := firstNftLines(out, 5); detail != "" {
			return fmt.Errorf("firewall candidate rejected by nft: %s", detail)
		}
		return fmt.Errorf("firewall candidate rejected by nft: %w", checkErr)
	}

	if err := host.RunRoot("mv -f " + pluginapi.ShellArg(candidate) + " " + pluginapi.ShellArg(destPath)); err != nil {
		if rmErr := host.RunRoot("rm -f " + pluginapi.ShellArg(candidate)); rmErr != nil {
			logger.Warnf("firewall: could not remove the staged candidate %s: %v\n", candidate, rmErr)
		}
		return fmt.Errorf("install firewall candidate as %s: %w", destPath, err)
	}
	return nil
}

func firewallDestinationMatches(rt firewallCompareRuntime, dest string, rendered string, mode os.FileMode) (bool, error) {
	size, currentMode, err := statFirewallDestination(rt, dest)
	if err != nil {
		return false, err
	}
	if size < 0 || currentMode.Perm() != mode.Perm() {
		return false, nil
	}

	current, err := rt.ReadRootFile(dest)
	if err != nil {
		return false, err
	}
	return current == rendered, nil
}

func statFirewallDestination(rt firewallStatRuntime, dest string) (int64, os.FileMode, error) {
	if rt == nil {
		return 0, 0, fmt.Errorf("runtime is required")
	}
	if err := rt.RunRoot(fmt.Sprintf("test -e %s", pluginapi.ShellArg(dest))); err != nil {
		return -1, 0, nil
	}

	out, err := rt.RunRootWithOutput(fmt.Sprintf("stat -c '%%a %%s' -- %s", pluginapi.ShellArg(dest)))
	if err != nil {
		return 0, 0, err
	}

	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("parse stat output for %q: unexpected format %q", dest, strings.TrimSpace(out))
	}

	perm, err := strconv.ParseUint(fields[0], 8, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse stat mode for %q: %w", dest, err)
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse stat size for %q: %w", dest, err)
	}

	return size, os.FileMode(perm), nil
}

func Plan(ctx pluginapi.Context, fw *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("planFirewall: backend=%q family=%q table=%q policies=%d rules=%d\n", fw.Backend, fw.Family, fw.Table, len(fw.Policies), len(fw.Rules))
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: host context is required")
	}

	var details []string
	var diff []string
	var highlights []string

	if fw.Backend != "nftables" {
		summary := fmt.Sprintf("firewall step: unsupported backend %q (no-op)", fw.Backend)
		return pluginapi.PlanResult{
			Summary:          summary,
			Details:          []string{"only nftables backend is supported by executor"},
			Diff:             nil,
			WillChange:       true,
			OperatorSummary:  fmt.Sprintf("Unsupported firewall backend %q requested", fw.Backend),
			Highlights:       []string{fmt.Sprintf("only the nftables backend is supported; got %q", fw.Backend)},
			RollbackFidelity: pluginapi.ModeDeterministic,
		}, nil
	}
	if strings.TrimSpace(fw.Family) == "" {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: family is required")
	}
	if strings.TrimSpace(fw.Table) == "" {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: table is required")
	}
	if strings.TrimSpace(fw.ManagedDest) == "" {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: managed_dest is required")
	}
	if len(fw.Policies) == 0 {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: policies are required")
	}

	desired, err := NormalizeDesiredSpec(fw)
	if err != nil {
		return pluginapi.PlanResult{}, err
	}
	desiredRendered := RenderNormalized(desired)
	const desiredMode = os.FileMode(0o644)
	destinationMatches := false

	info, err := ctx.Host.Stat(fw.ManagedDest)
	if err != nil {
		details = append(details,
			logger.ColorBlue+fmt.Sprintf("managed destination %q: does not exist (file will be created)", fw.ManagedDest)+logger.ColorReset,
		)
		diff = append(diff, fmt.Sprintf("file %q: absent -> present (mode %#o)", fw.ManagedDest, desiredMode.Perm()))
		diff = append(diff, renderFirewallContentDiff(fw.ManagedDest, "", desiredRendered, false)...)
	} else {
		details = append(details,
			logger.ColorBlue+fmt.Sprintf("managed destination %q: exists (size=%d mode=%#o)", fw.ManagedDest, info.Size(), info.Mode().Perm())+logger.ColorReset,
		)
		if info.Mode().Perm() == desiredMode.Perm() {
			details = append(details,
				logger.ColorGreen+fmt.Sprintf("managed destination mode matches desired mode %#o", desiredMode.Perm())+logger.ColorReset,
			)
		} else {
			details = append(details,
				logger.ColorYellow+fmt.Sprintf("managed destination mode differs (current=%#o desired=%#o)", info.Mode().Perm(), desiredMode.Perm())+logger.ColorReset,
			)
			diff = append(diff,
				fmt.Sprintf("file mode %q: %#o -> %#o", fw.ManagedDest, info.Mode().Perm(), desiredMode.Perm()),
			)
		}

		currentContent, readErr := ctx.Host.ReadRootFile(fw.ManagedDest)
		if readErr != nil {
			highlights = append(highlights, fmt.Sprintf("cannot compare managed destination %q (%v)", fw.ManagedDest, readErr))
			details = append(details,
				logger.ColorRed+fmt.Sprintf("cannot compare managed destination %q (%v)", fw.ManagedDest, readErr)+logger.ColorReset,
			)
		} else if currentContent == desiredRendered {
			details = append(details,
				logger.ColorGreen+"managed destination content matches rendered firewall policy"+logger.ColorReset,
			)
			destinationMatches = info.Mode().Perm() == desiredMode.Perm()
		} else {
			details = append(details,
				logger.ColorYellow+"managed destination content differs from rendered firewall policy"+logger.ColorReset,
			)
			diff = append(diff, renderFirewallContentDiff(fw.ManagedDest, currentContent, desiredRendered, true)...)
		}
	}

	details = append(details, logger.ColorGreen+fmt.Sprintf("desired table: %s %s", desired.Family, desired.Table)+logger.ColorReset)
	details = append(details, logger.ColorGreen+fmt.Sprintf("desired chain policies: %d", len(desired.Policies))+logger.ColorReset)
	details = append(details, logger.ColorGreen+fmt.Sprintf("desired rules: %d", len(desired.Rules))+logger.ColorReset)

	current, err := currentFirewallState(ctx.Host, desired.Family, desired.Table)
	if err != nil {
		highlights = append(highlights,
			fmt.Sprintf("cannot inspect running nftables table %s %s (%v)", desired.Family, desired.Table, err),
		)
		details = append(details,
			logger.ColorRed+fmt.Sprintf("cannot inspect running nftables table %s %s (%v)", desired.Family, desired.Table, err)+logger.ColorReset,
		)
	} else {
		details = append(details,
			logger.ColorBlue+fmt.Sprintf("current running table: %d chain policies, %d managed rules", len(current.Policies), len(current.Rules))+logger.ColorReset,
		)
		runtimeDiff := renderFirewallStateDiff(current, desired)
		diff = append(diff, runtimeDiff...)
		if len(runtimeDiff) == 0 {
			details = append(details,
				logger.ColorGreen+fmt.Sprintf("running nftables table %s %s already matches desired final state", desired.Family, desired.Table)+logger.ColorReset,
			)
		}
	}

	planDest := ManagedDestination(fw)
	if !firewallIncludePresent(ctx.Host, fw.MainConfig, planDest) {
		diff = append(diff, fmt.Sprintf("file %q: add include %q (apply will patch)", fw.MainConfig, IncludeLine(planDest)))
		details = append(details,
			logger.ColorBlue+fmt.Sprintf("%q: include %q absent; apply will add it", fw.MainConfig, IncludeLine(planDest))+logger.ColorReset,
		)
	} else {
		validateRes, err := ValidatePlan(ctx.Host, fw.MainConfig, planDest)
		if err != nil {
			return pluginapi.PlanResult{}, err
		}
		details = append(details, validateRes.Details...)
		highlights = append(highlights, validateRes.Highlights...)
	}

	summary := fmt.Sprintf(
		"firewall step (deterministic): backend=nftables table=%s %s, managed_dest=%q, policies=%d, rules=%d",
		desired.Family, desired.Table, fw.ManagedDest, len(desired.Policies), len(desired.Rules),
	)
	willChange := true
	if destinationMatches && len(diff) == 0 && len(highlights) == 0 {
		willChange = false
	}
	return pluginapi.PlanResult{
		Summary:          summary,
		Details:          details,
		Diff:             diff,
		WillChange:       willChange,
		OperatorSummary:  fmt.Sprintf("Manage nftables table %s %s in %q (%d policy entries, %d rules)", desired.Family, desired.Table, fw.ManagedDest, len(desired.Policies), len(desired.Rules)),
		Highlights:       highlights,
		RollbackFidelity: pluginapi.ModeDeterministic,
	}, nil
}

func currentFirewallState(host pluginapi.Host, family string, table string) (NormalizedSpec, error) {
	if host == nil {
		return NormalizedSpec{}, fmt.Errorf("host is required")
	}

	out, err := host.RunRootWithOutput("nft -j list ruleset 2>/dev/null")
	if err != nil {
		return NormalizedSpec{}, fmt.Errorf("query nftables ruleset: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		return NormalizedSpec{
			Family:   family,
			Table:    table,
			Policies: make(map[string]string),
		}, nil
	}

	state, err := NormalizeCurrentState(out, family, table)
	if err != nil {
		return NormalizedSpec{}, err
	}
	return state, nil
}

func renderFirewallStateDiff(current NormalizedSpec, desired NormalizedSpec) []string {
	diff := DiffNormalized(current, desired)
	var lines []string
	for _, change := range diff.PolicyChanges {
		lines = append(lines, change)
	}
	for _, rule := range diff.RulesToRemove {
		lines = append(lines, "- "+RenderNormalizedRule(desired.Family, rule))
	}
	for _, rule := range diff.RulesToAdd {
		lines = append(lines, "+ "+RenderNormalizedRule(desired.Family, rule))
	}
	for _, chain := range diff.Reordered {
		lines = append(lines, fmt.Sprintf("chain %s: same rules, different evaluation order", chain))
	}
	return lines
}

func ValidateApply(host pluginapi.Host, mainConfig, dest string) error {
	if host == nil {
		return fmt.Errorf("firewall step: host context is required")
	}
	if err := host.RunRoot(includeCheckCmd(mainConfig, dest)); err != nil {
		return fmt.Errorf("%s missing %s: %w", mainConfig, IncludeLine(dest), err)
	}

	if err := host.RunRoot("nft -c -f " + pluginapi.ShellArg(mainConfig)); err != nil {
		return fmt.Errorf("nftables config check failed: %w", err)
	}
	return nil
}

func ValidatePlan(host pluginapi.Host, mainConfig, dest string) (pluginapi.PlanResult, error) {
	logger.Debugf("planValidate: kind=firewall main_config=%q\n", mainConfig)

	var details []string
	var highlights []string

	include := IncludeLine(dest)
	if firewallIncludePresent(host, mainConfig, dest) {
		details = append(details,
			logger.ColorGreen+fmt.Sprintf("%s: %s is present", mainConfig, include)+logger.ColorReset,
		)
	} else {
		highlights = append(highlights, fmt.Sprintf("%s %s is missing (validate would fail)", mainConfig, include))
		details = append(details,
			logger.ColorRed+fmt.Sprintf("%s: %s is missing (validate would fail)", mainConfig, include)+logger.ColorReset,
		)
	}

	testErr := firewallConfigTest(host, mainConfig)
	if testErr == nil {
		details = append(details,
			logger.ColorGreen+fmt.Sprintf("current nftables configuration: passes nft -c -f %s", mainConfig)+logger.ColorReset,
		)
	} else {
		highlights = append(highlights, fmt.Sprintf("current nftables configuration: nft -c reports errors (%v)", testErr))
		details = append(details,
			logger.ColorRed+fmt.Sprintf("current nftables configuration: nft -c reports errors (%v)", testErr)+logger.ColorReset,
		)
	}

	return pluginapi.PlanResult{
		Summary:          fmt.Sprintf("validate firewall: check %s and nft -c on %s", include, mainConfig),
		Details:          details,
		WillChange:       true,
		OperatorSummary:  "Validate nftables include wiring and current nftables syntax",
		Highlights:       highlights,
		RollbackFidelity: pluginapi.ModeDeterministic,
	}, nil
}

func Capture(ctx pluginapi.Context, stepID string, spec *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if spec == nil {
		return record, fmt.Errorf("step %q (type=firewall): firewall spec missing", stepID)
	}
	if ctx.Host == nil {
		return record, fmt.Errorf("firewall step: host context is required")
	}

	dest := ManagedDestination(spec)
	if err := pluginapi.EnforceManagedPath(dest); err != nil {
		return record, fmt.Errorf("step %q (type=firewall): %w", stepID, err)
	}

	snap, err := pluginapi.SnapshotRemoteFile(ctx.Host, dest)
	if err != nil {
		return record, fmt.Errorf("capture firewall snapshot for %q: %w", dest, err)
	}

	// Apply also appends the include line to the main config, so that mutation
	// has to be journalled too or rollback silently leaves it behind. Only the
	// line is recorded, not the file: another profile may add its own include to
	// the same config after this run, and restoring the whole file would delete
	// it along with ours.
	mainConfig := strings.TrimSpace(spec.MainConfig)
	if !ValidMainConfig(mainConfig) {
		return record, fmt.Errorf("step %q (type=firewall): unsupported main_config %q", stepID, spec.MainConfig)
	}
	mainSnap, err := pluginapi.SnapshotRemoteFile(ctx.Host, mainConfig)
	if err != nil {
		return record, fmt.Errorf("capture firewall snapshot for %q: %w", mainConfig, err)
	}
	include := pluginapi.ConfigLineSnapshot{
		Path:        mainConfig,
		Line:        IncludeLine(dest),
		FileExisted: mainSnap.Existed,
		Added:       !firewallIncludePresent(ctx.Host, mainConfig, dest),
	}
	flush := pluginapi.ConfigLineSnapshot{
		Path:        mainConfig,
		Line:        FlushLine,
		FileExisted: mainSnap.Existed,
		Added:       !flushPresent(ctx.Host, mainConfig),
	}

	record.RollbackMode = pluginapi.ModeDeterministic
	// Rollback walks Before in reverse, so the main-config lines are listed
	// last to be taken back first. An include naming a file that is no longer
	// there fails every nftables load, so the pointer has to go before what it
	// points at, and the flush header goes with it.
	record.Objects = []pluginapi.ObjectRecord{
		{Kind: pluginapi.ObjectFile, File: &snap},
		{Kind: pluginapi.ObjectConfigLine, ConfigLine: &flush},
		{Kind: pluginapi.ObjectConfigLine, ConfigLine: &include},
	}
	return record, nil
}

// includeLineConflict reports an include this run added that is no longer
// there. Rolling back would then be removing a line someone else already
// removed, and the managed file has been inert since.
func includeLineConflict(host pluginapi.Host, rec pluginapi.ConfigLineSnapshot) []string {
	if host == nil || !rec.Added {
		return nil
	}
	if strings.Join(strings.Fields(rec.Line), " ") == FlushLine {
		if flushPresent(host, rec.Path) {
			return nil
		}
		return []string{fmt.Sprintf("%s no longer contains %s", rec.Path, rec.Line)}
	}
	dest := normalizeIncludeLine(rec.Line)
	if dest == "" {
		return nil
	}
	if firewallIncludePresent(host, rec.Path, dest) {
		return nil
	}
	return []string{fmt.Sprintf("%s no longer contains %s", rec.Path, rec.Line)}
}

// RestoreNftablesInclude undoes what apply did to the main config: the file if
// this run created it, otherwise the one line it added, whether that was the
// include or the flush header.
func RestoreNftablesInclude(host pluginapi.Host, rec pluginapi.ConfigLineSnapshot) error {
	if host == nil {
		return fmt.Errorf("firewall rollback: host is required")
	}
	if !ValidMainConfig(rec.Path) {
		return fmt.Errorf("firewall rollback: unexpected main config path %q", rec.Path)
	}
	if !rec.Added {
		return nil
	}
	if !rec.FileExisted {
		return host.RunRoot("rm -f " + pluginapi.ShellArg(rec.Path))
	}
	if strings.Join(strings.Fields(rec.Line), " ") == FlushLine {
		return RemoveNftablesFlush(host, rec.Path)
	}
	return RemoveNftablesInclude(host, rec.Path, rec.Line)
}

// restoreNftablesMainConfig reverts the nftables main config to its pre-apply
// bytes, which is what removes the include line apply appended. It skips
// EnforceManagedPath, whose 99-hardline naming rule this file cannot satisfy,
// and checks the two-entry whitelist instead: a tampered journal must not be
// able to name any other path here.
func restoreNftablesMainConfig(host pluginapi.Host, snap pluginapi.FileSnapshot) error {
	if host == nil {
		return fmt.Errorf("firewall rollback: host is required")
	}
	if !ValidMainConfig(snap.Path) {
		return fmt.Errorf("firewall rollback: unexpected main config path %q", snap.Path)
	}

	if !snap.Existed {
		return host.RunRoot("rm -f " + pluginapi.ShellArg(snap.Path))
	}

	mode, err := pluginapi.ParseFileMode(snap.Mode)
	if err != nil {
		return fmt.Errorf("firewall rollback: restore %q: %w", snap.Path, err)
	}

	content, err := base64.StdEncoding.DecodeString(snap.ContentB64)
	if err != nil {
		return fmt.Errorf("decode snapshot content for %q: %w", snap.Path, err)
	}
	if err := host.WriteRootFile(snap.Path, content, mode); err != nil {
		return fmt.Errorf("restore file %q: %w", snap.Path, err)
	}
	return nil
}

func ManagedDestination(fw *Spec) string {
	if fw == nil {
		return ""
	}
	if p := strings.TrimSpace(fw.ManagedDest); p != "" {
		return p
	}
	return ""
}

// FlushLine is the first line of a managed main config. Without it, loading the
// file adds to whatever the kernel already has, so a rule the profile deleted
// stays in force until the next reboot. With it, one load produces exactly the
// ruleset the file describes, the same way on Debian-family hosts, which ship
// it, and RHEL-family hosts, which do not.
const FlushLine = "flush ruleset"

func flushCheckCmd(mainConfig string) string {
	return fmt.Sprintf(`grep -E -q '^[[:space:]]*flush[[:space:]]+ruleset[[:space:]]*$' %s 2>/dev/null`,
		pluginapi.ShellArg(mainConfig))
}

func flushPresent(host pluginapi.Host, mainConfig string) bool {
	if host == nil {
		return false
	}
	return host.RunRoot(flushCheckCmd(mainConfig)) == nil
}

// EnsureNftablesFlush puts "flush ruleset" at the top of the main config. It
// has to be the first line: nft applies the file in order, so a flush after an
// include would discard the very tables the include just defined.
func EnsureNftablesFlush(host pluginapi.Host, mainConfig string) error {
	if host == nil {
		return fmt.Errorf("firewall step: host context is required")
	}
	if !ValidMainConfig(mainConfig) {
		return fmt.Errorf("unsupported firewall main_config %q", mainConfig)
	}
	if flushPresent(host, mainConfig) {
		return nil
	}

	snap, err := pluginapi.SnapshotRemoteFile(host, mainConfig)
	if err != nil {
		return fmt.Errorf("read %s: %w", mainConfig, err)
	}
	mode := os.FileMode(0o644)
	var current []byte
	if snap.Existed {
		if mode, err = pluginapi.ParseFileMode(snap.Mode); err != nil {
			return fmt.Errorf("%s: %w", mainConfig, err)
		}
		if current, err = base64.StdEncoding.DecodeString(snap.ContentB64); err != nil {
			return fmt.Errorf("decode %s: %w", mainConfig, err)
		}
	}

	next := FlushLine + "\n"
	if len(current) > 0 {
		next += string(current)
	}
	if err := host.WriteRootFile(mainConfig, []byte(next), mode); err != nil {
		return fmt.Errorf("ensure %q in %s: %w", FlushLine, mainConfig, err)
	}
	if !flushPresent(host, mainConfig) {
		return fmt.Errorf("verify %q in %s: line is still absent", FlushLine, mainConfig)
	}
	return nil
}

// RemoveNftablesFlush takes back the flush line this run added, leaving the
// rest of the file, including other profiles' includes, untouched.
func RemoveNftablesFlush(host pluginapi.Host, mainConfig string) error {
	if host == nil {
		return fmt.Errorf("firewall rollback: host is required")
	}
	if !ValidMainConfig(mainConfig) {
		return fmt.Errorf("firewall rollback: unexpected main config path %q", mainConfig)
	}

	snap, err := pluginapi.SnapshotRemoteFile(host, mainConfig)
	if err != nil {
		return fmt.Errorf("firewall rollback: read %s: %w", mainConfig, err)
	}
	if !snap.Existed {
		return nil
	}
	mode, err := pluginapi.ParseFileMode(snap.Mode)
	if err != nil {
		return fmt.Errorf("firewall rollback: %s: %w", mainConfig, err)
	}
	current, err := base64.StdEncoding.DecodeString(snap.ContentB64)
	if err != nil {
		return fmt.Errorf("firewall rollback: decode %s: %w", mainConfig, err)
	}

	next, removed := withoutFlushLine(string(current))
	if !removed {
		return nil
	}
	if err := host.WriteRootFile(mainConfig, []byte(next), mode); err != nil {
		return fmt.Errorf("firewall rollback: rewrite %s: %w", mainConfig, err)
	}
	return nil
}

func withoutFlushLine(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if strings.Join(strings.Fields(line), " ") == FlushLine {
			removed = true
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), removed
}

func EnsureNftablesInclude(host pluginapi.Host, mainConfig, dest string) error {
	if host == nil {
		return fmt.Errorf("firewall step: host context is required")
	}
	if err := host.RunRoot(legacyGlobCheckCmd(mainConfig, dest)); err == nil {
		return fmt.Errorf(
			"%s still contains the directory-wide include %q written by an older hardline; "+
				"remove that line so %s is included once, by name",
			mainConfig, fmt.Sprintf(`include "%s/*.nft"`, path.Dir(dest)), dest)
	}

	check := includeCheckCmd(mainConfig, dest)
	if err := host.RunRoot(check); err == nil {
		return nil
	}

	include := IncludeLine(dest)
	appendCmd := fmt.Sprintf("printf '\\n%%s\\n' %s >> %s", pluginapi.ShellArg(include), pluginapi.ShellArg(mainConfig))
	if err := host.RunRoot(appendCmd); err != nil {
		return fmt.Errorf("ensure %q in %s: %w", include, mainConfig, err)
	}

	if err := host.RunRoot(check); err != nil {
		return fmt.Errorf("verify %q in %s: %w", include, mainConfig, err)
	}

	return nil
}

// RemoveNftablesInclude takes back exactly the line this run added and leaves
// every other line, including another profile's include, untouched.
func RemoveNftablesInclude(host pluginapi.Host, mainConfig, line string) error {
	if host == nil {
		return fmt.Errorf("firewall rollback: host is required")
	}
	if !ValidMainConfig(mainConfig) {
		return fmt.Errorf("firewall rollback: unexpected main config path %q", mainConfig)
	}

	snap, err := pluginapi.SnapshotRemoteFile(host, mainConfig)
	if err != nil {
		return fmt.Errorf("firewall rollback: read %s: %w", mainConfig, err)
	}
	if !snap.Existed {
		return nil
	}
	mode, err := pluginapi.ParseFileMode(snap.Mode)
	if err != nil {
		return fmt.Errorf("firewall rollback: %s: %w", mainConfig, err)
	}
	current, err := base64.StdEncoding.DecodeString(snap.ContentB64)
	if err != nil {
		return fmt.Errorf("firewall rollback: decode %s: %w", mainConfig, err)
	}

	next, removed := withoutIncludeLine(string(current), line)
	if !removed {
		return nil
	}
	if err := host.WriteRootFile(mainConfig, []byte(next), mode); err != nil {
		return fmt.Errorf("firewall rollback: rewrite %s: %w", mainConfig, err)
	}
	return nil
}

// withoutIncludeLine drops every occurrence of one include line, comparing the
// way the presence check does: leading and trailing space and the optional
// quotes around the path are not a different line.
func withoutIncludeLine(content, line string) (string, bool) {
	target := normalizeIncludeLine(line)
	if target == "" {
		return content, false
	}

	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	removed := false
	for _, l := range lines {
		if normalizeIncludeLine(l) == target {
			removed = true
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n"), removed
}

func normalizeIncludeLine(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 2 || fields[0] != "include" {
		return ""
	}
	return strings.Trim(fields[1], `"`)
}

func firewallIncludePresent(host pluginapi.Host, mainConfig, dest string) bool {
	if host == nil {
		return false
	}
	return host.RunRoot(includeCheckCmd(mainConfig, dest)) == nil
}

func firewallConfigTest(host pluginapi.Host, mainConfig string) error {
	if host == nil {
		return fmt.Errorf("host is required")
	}
	if !ValidMainConfig(mainConfig) {
		return fmt.Errorf("unsupported firewall main_config %q", mainConfig)
	}
	return host.RunRoot("nft -c -f " + pluginapi.ShellArg(mainConfig) + " >/dev/null 2>&1")
}

func NormalizeDesiredSpec(fw *Spec) (NormalizedSpec, error) {
	family := normalizeFirewallFamily(fw.Family)
	if family == "" {
		return NormalizedSpec{}, fmt.Errorf("firewall family is required")
	}
	switch family {
	case "inet", "ip", "ip6":
	default:
		return NormalizedSpec{}, fmt.Errorf("unsupported firewall family %q", fw.Family)
	}
	table := normalizeFirewallTable(fw.Table)
	if table == "" {
		return NormalizedSpec{}, fmt.Errorf("firewall table is required")
	}
	if !tableNameRe.MatchString(table) {
		return NormalizedSpec{}, fmt.Errorf("firewall table %q is not an nftables identifier", fw.Table)
	}

	out := NormalizedSpec{
		Family:   family,
		Table:    table,
		Policies: make(map[string]string),
	}

	if len(fw.Policies) == 0 {
		return out, fmt.Errorf("firewall policies are required")
	}
	for _, cp := range fw.Policies {
		cn, err := NormalizeChain(cp.Chain)
		if err != nil {
			return out, fmt.Errorf("normalize firewall chain %q: %w", cp.Chain, err)
		}
		if cn == "" {
			return out, fmt.Errorf("normalize firewall chain %q: chain is required", cp.Chain)
		}
		pn, err := NormalizePolicy(cp.Policy)
		if err != nil {
			return out, fmt.Errorf("normalize firewall policy for chain %q: %w", cp.Chain, err)
		}
		// nft takes accept or drop as a base-chain policy and nothing else, so
		// a reject policy is a file the host refuses to load. Rejecting is
		// still available per rule, which is where it belongs.
		if pn == "reject" {
			return out, fmt.Errorf("chain %q policy %q is not a valid base-chain policy; use \"drop\" and add a reject rule if you need one", cp.Chain, cp.Policy)
		}
		out.Policies[cn] = pn
	}

	seen := make(map[string]struct{})
	for idx, rule := range fw.Rules {
		normRules, err := NormalizeDesiredRule(rule)
		if err != nil {
			return out, fmt.Errorf("normalize firewall rule #%d: %w", idx+1, err)
		}
		for _, nr := range normRules {
			key := nr.key()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out.Rules = append(out.Rules, nr)
		}
	}
	for _, rule := range out.Rules {
		if _, ok := out.Policies[rule.Chain]; !ok {
			return out, fmt.Errorf("missing policy for chain %q used by rules", rule.Chain)
		}
		if err := assertAddressFamily(family, rule); err != nil {
			return out, err
		}
	}

	// Declared order is the order the kernel evaluates. Sorting here put every
	// accept ahead of every drop in a chain, so an anti-spoof or invalid-state
	// drop written first in the profile was emitted after the accepts it was
	// meant to precede, and the rule never matched anything.
	return out, nil
}

func NormalizeDesiredRule(rule Rule) ([]NormalizedRule, error) {
	chain, err := NormalizeChain(rule.Chain)
	if err != nil {
		return nil, err
	}
	if chain == "" {
		return nil, fmt.Errorf("rule chain is required")
	}

	action := strings.ToLower(strings.TrimSpace(rule.Action))
	if action == "" {
		return nil, fmt.Errorf("rule action is required")
	}
	if action != "accept" && action != "drop" && action != "reject" {
		return nil, fmt.Errorf("unsupported rule action %q", rule.Action)
	}

	proto := strings.ToLower(strings.TrimSpace(rule.Proto))
	switch proto {
	case "", "tcp", "udp", "icmp", "icmpv6":
	default:
		return nil, fmt.Errorf("unsupported rule proto %q", rule.Proto)
	}

	if len(rule.Ports) > 65535 {
		return nil, fmt.Errorf("rule has too many ports (max 65535)")
	}
	ports := make([]int, 0, len(rule.Ports)+1)
	if rule.Port != 0 {
		ports = append(ports, rule.Port)
	}
	ports = append(ports, rule.Ports...)
	seenPorts := make(map[int]struct{}, len(ports))
	filteredPorts := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %d", port)
		}
		if _, ok := seenPorts[port]; ok {
			continue
		}
		seenPorts[port] = struct{}{}
		filteredPorts = append(filteredPorts, port)
	}
	sort.Ints(filteredPorts)

	src, err := normalizeAddress("source", rule.Source)
	if err != nil {
		return nil, err
	}
	dst, err := normalizeAddress("destination", rule.Destination)
	if err != nil {
		return nil, err
	}
	iif, err := normalizeInterface("in_interface", rule.InInterface)
	if err != nil {
		return nil, err
	}
	oif, err := normalizeInterface("out_interface", rule.OutInterface)
	if err != nil {
		return nil, err
	}
	ctStates, err := normalizeCTStates(rule.CTStates)
	if err != nil {
		return nil, err
	}

	switch proto {
	case "tcp", "udp":
		if len(filteredPorts) == 0 {
			return nil, fmt.Errorf("rule proto %q requires port or ports", proto)
		}
	case "icmp", "icmpv6":
		if len(filteredPorts) > 0 {
			return nil, fmt.Errorf("rule proto %q must not define port or ports", proto)
		}
	case "":
		if len(filteredPorts) > 0 {
			return nil, fmt.Errorf("rule with empty proto must not define port or ports")
		}
	}

	hasMatcher := proto != "" || len(ctStates) > 0 || src != "" || dst != "" || iif != "" || oif != ""
	if !hasMatcher {
		return nil, fmt.Errorf("rule must define at least one matcher (proto/ports, ct_states, interfaces, or addresses)")
	}

	if len(filteredPorts) == 0 {
		return []NormalizedRule{{
			Chain:        chain,
			Action:       action,
			Proto:        proto,
			Port:         0,
			Source:       src,
			Destination:  dst,
			InInterface:  iif,
			OutInterface: oif,
			CTStates:     ctStates,
		}}, nil
	}

	out := make([]NormalizedRule, 0, len(filteredPorts))
	for _, port := range filteredPorts {
		out = append(out, NormalizedRule{
			Chain:        chain,
			Action:       action,
			Proto:        proto,
			Port:         port,
			Source:       src,
			Destination:  dst,
			InInterface:  iif,
			OutInterface: oif,
			CTStates:     ctStates,
		})
	}
	return out, nil
}

func normalizeFirewallFamily(family string) string {
	return strings.ToLower(strings.TrimSpace(family))
}

// tableNameRe is what nft accepts as an identifier. The table name is written
// straight into "table <family> <name> {" in a file loaded as root, so anything
// outside an identifier would be further nft grammar rather than a name.
var tableNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func normalizeFirewallTable(table string) string {
	return strings.TrimSpace(table)
}

// interfaceNameRe follows the kernel's own limit: an interface name is at most
// IFNAMSIZ-1 characters and carries no whitespace, slash or quote. The value is
// rendered inside iif "%s", where a quote would close the string and leave the
// rest to be read as grammar.
var interfaceNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)

func normalizeInterface(field, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil
	}
	if !interfaceNameRe.MatchString(v) {
		return "", fmt.Errorf("rule %s %q is not an interface name", field, raw)
	}
	return v, nil
}

// normalizeAddress accepts one address or one CIDR prefix and nothing else: no
// ranges, no named sets, no lists. Each of those is valid nft that a profile
// cannot express through this field, and accepting the text unparsed is what
// would let it through into a root-loaded ruleset.
func normalizeAddress(field, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil
	}

	if strings.Contains(v, "/") {
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return "", fmt.Errorf("rule %s %q is not an address or CIDR prefix", field, raw)
		}
		if prefix.Addr().Zone() != "" {
			return "", fmt.Errorf("rule %s %q must not carry a zone", field, raw)
		}
		if masked := prefix.Masked(); masked != prefix {
			return "", fmt.Errorf("rule %s %q has host bits set outside its prefix; write it as %q", field, raw, masked.String())
		}
		return prefix.String(), nil
	}

	addr, err := netip.ParseAddr(v)
	if err != nil {
		return "", fmt.Errorf("rule %s %q is not an address or CIDR prefix", field, raw)
	}
	if addr.Zone() != "" {
		return "", fmt.Errorf("rule %s %q must not carry a zone", field, raw)
	}
	return addr.String(), nil
}

// addressIsV6 reports how an already-normalized address should be rendered. It
// decides the nft keyword per address rather than per table, so an inet table
// can carry both without emitting "ip saddr" in front of an IPv6 address.
func addressIsV6(addr string) bool {
	if addr == "" {
		return false
	}
	if strings.Contains(addr, "/") {
		prefix, err := netip.ParsePrefix(addr)
		return err == nil && prefix.Addr().Is6()
	}
	parsed, err := netip.ParseAddr(addr)
	return err == nil && parsed.Is6()
}

// addressKeyword is the nft protocol keyword an address matches under. A table
// pinned to one family keeps that family's keyword even for a value that failed
// to parse, so a malformed record renders as it always did rather than silently
// switching protocol.
func addressKeyword(family, addr string) string {
	switch family {
	case "ip":
		return "ip"
	case "ip6":
		return "ip6"
	}
	if addressIsV6(addr) {
		return "ip6"
	}
	return "ip"
}

// assertAddressFamily keeps a rule's addresses inside the table's family. An
// ip table cannot match an IPv6 address, and nft rejects the whole file at load
// rather than the one rule, so this is caught while the profile is still text.
func assertAddressFamily(family string, rule NormalizedRule) error {
	for _, entry := range []struct{ field, value string }{
		{"source", rule.Source},
		{"destination", rule.Destination},
	} {
		if entry.value == "" {
			continue
		}
		isV6 := addressIsV6(entry.value)
		if family == "ip" && isV6 {
			return fmt.Errorf("rule %s %q is IPv6, which an %q table cannot match", entry.field, entry.value, family)
		}
		if family == "ip6" && !isV6 {
			return fmt.Errorf("rule %s %q is IPv4, which an %q table cannot match", entry.field, entry.value, family)
		}
	}
	return nil
}

func NormalizePolicy(policy string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(policy))
	switch p {
	case "accept":
		return "accept", nil
	case "drop":
		return "drop", nil
	case "reject":
		return "reject", nil
	default:
		return "", fmt.Errorf("unsupported policy %q", policy)
	}
}

func NormalizeChain(chain string) (string, error) {
	c := strings.ToLower(strings.TrimSpace(chain))
	if c == "" {
		return "", fmt.Errorf("chain is required")
	}
	switch c {
	case "input", "output", "forward":
		return c, nil
	default:
		return "", fmt.Errorf("unsupported chain %q", chain)
	}
}

func normalizeCTStates(states []string) ([]string, error) {
	if len(states) == 0 {
		return nil, nil
	}
	allowed := map[string]struct{}{
		"new":         {},
		"established": {},
		"related":     {},
		"invalid":     {},
		"untracked":   {},
	}
	seen := make(map[string]struct{}, len(states))
	out := make([]string, 0, len(states))
	for _, state := range states {
		s := strings.ToLower(strings.TrimSpace(state))
		if s == "" {
			continue
		}
		if _, ok := allowed[s]; !ok {
			return nil, fmt.Errorf("unsupported ct state %q", state)
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

type nftJSONDocument struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type nftJSONChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type nftJSONRule struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Expr   []json.RawMessage `json:"expr"`
}

func NormalizeCurrentState(nftJSON, family, table string) (NormalizedSpec, error) {
	out := NormalizedSpec{
		Family:   family,
		Table:    table,
		Policies: make(map[string]string),
	}

	var doc nftJSONDocument
	if err := json.Unmarshal([]byte(nftJSON), &doc); err != nil {
		return out, fmt.Errorf("decode nftables json state: %w", err)
	}

	seenRules := make(map[string]struct{})
	for _, entry := range doc.Nftables {
		if rawChain, ok := entry["chain"]; ok {
			var c nftJSONChain
			if err := json.Unmarshal(rawChain, &c); err == nil {
				if c.Family == family && c.Table == table && strings.TrimSpace(c.Hook) != "" {
					chain, err := NormalizeChain(c.Hook)
					if err == nil && strings.TrimSpace(c.Policy) != "" {
						pol, err := NormalizePolicy(c.Policy)
						if err == nil {
							out.Policies[chain] = pol
						}
					}
				}
			}
		}
		if rawRule, ok := entry["rule"]; ok {
			var r nftJSONRule
			if err := json.Unmarshal(rawRule, &r); err != nil {
				continue
			}
			if r.Family != family || r.Table != table {
				continue
			}
			rules := normalizeNftRuleExpr(r)
			for _, nr := range rules {
				key := nr.key()
				if _, ok := seenRules[key]; ok {
					continue
				}
				seenRules[key] = struct{}{}
				out.Rules = append(out.Rules, nr)
			}
		}
	}

	// nft lists a chain's rules in evaluation order, which is the whole point of
	// reading them back: sorting the live state would compare a set against a
	// set and call a reordered ruleset aligned.
	return out, nil
}

func normalizeNftRuleExpr(r nftJSONRule) []NormalizedRule {
	chain, err := NormalizeChain(r.Chain)
	if err != nil {
		return nil
	}

	proto := ""
	ports := []int{}
	src := ""
	dst := ""
	iif := ""
	oif := ""
	action := ""
	ctStates := []string{}

	for _, rawExpr := range r.Expr {
		var expr map[string]json.RawMessage
		if err := json.Unmarshal(rawExpr, &expr); err != nil {
			continue
		}

		if _, ok := expr["accept"]; ok {
			action = "accept"
			continue
		}
		if _, ok := expr["drop"]; ok {
			action = "drop"
			continue
		}
		if _, ok := expr["reject"]; ok {
			action = "reject"
			continue
		}

		rawMatch, ok := expr["match"]
		if !ok {
			continue
		}

		var match struct {
			Left  map[string]json.RawMessage `json:"left"`
			Right json.RawMessage            `json:"right"`
		}
		if err := json.Unmarshal(rawMatch, &match); err != nil {
			continue
		}

		if rawPayload, ok := match.Left["payload"]; ok {
			var payload struct {
				Protocol string `json:"protocol"`
				Field    string `json:"field"`
			}
			if err := json.Unmarshal(rawPayload, &payload); err == nil {
				switch {
				case (payload.Protocol == "tcp" || payload.Protocol == "udp") && payload.Field == "dport":
					if p := DecodeNftPortValues(match.Right); len(p) > 0 {
						proto = payload.Protocol
						ports = append(ports, p...)
					}
				case (payload.Protocol == "ip" || payload.Protocol == "ip6") && payload.Field == "saddr":
					if s := DecodeNftStringValue(match.Right); s != "" {
						src = s
					}
				case (payload.Protocol == "ip" || payload.Protocol == "ip6") && payload.Field == "daddr":
					if s := DecodeNftStringValue(match.Right); s != "" {
						dst = s
					}
				case payload.Protocol == "ip" && payload.Field == "protocol":
					if s := strings.ToLower(strings.TrimSpace(DecodeNftStringValue(match.Right))); s == "icmp" {
						proto = "icmp"
					}
				case payload.Protocol == "ip6" && payload.Field == "nexthdr":
					if s := strings.ToLower(strings.TrimSpace(DecodeNftStringValue(match.Right))); s == "icmpv6" || s == "ipv6-icmp" {
						proto = "icmpv6"
					}
				}
			}
		}

		if rawMeta, ok := match.Left["meta"]; ok {
			var meta struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(rawMeta, &meta); err == nil {
				switch meta.Key {
				case "iifname", "iif":
					if s := DecodeNftStringValue(match.Right); s != "" {
						iif = s
					}
				case "oifname", "oif":
					if s := DecodeNftStringValue(match.Right); s != "" {
						oif = s
					}
				}
			}
		}

		if rawCT, ok := match.Left["ct"]; ok {
			var ct struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(rawCT, &ct); err == nil && ct.Key == "state" {
				ctStates = append(ctStates, DecodeNftStringValues(match.Right)...)
			}
		}
	}

	if action == "" {
		return nil
	}

	ctStates, err = normalizeCTStates(ctStates)
	if err != nil {
		return nil
	}

	seenPorts := make(map[int]struct{})
	filteredPorts := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := seenPorts[port]; ok {
			continue
		}
		seenPorts[port] = struct{}{}
		filteredPorts = append(filteredPorts, port)
	}
	sort.Ints(filteredPorts)

	if len(filteredPorts) > 0 {
		if proto != "tcp" && proto != "udp" {
			return nil
		}
		out := make([]NormalizedRule, 0, len(filteredPorts))
		for _, port := range filteredPorts {
			out = append(out, NormalizedRule{
				Chain:        chain,
				Action:       action,
				Proto:        proto,
				Port:         port,
				Source:       src,
				Destination:  dst,
				InInterface:  iif,
				OutInterface: oif,
				CTStates:     ctStates,
			})
		}
		return out
	}

	if proto == "tcp" || proto == "udp" {
		return nil
	}
	if proto == "" && len(ctStates) == 0 && src == "" && dst == "" && iif == "" && oif == "" {
		return nil
	}
	return []NormalizedRule{{
		Chain:        chain,
		Action:       action,
		Proto:        proto,
		Source:       src,
		Destination:  dst,
		InInterface:  iif,
		OutInterface: oif,
		CTStates:     ctStates,
	}}
}

func DecodeNftPortValues(raw json.RawMessage) []int {
	var anyVal any
	if err := json.Unmarshal(raw, &anyVal); err != nil {
		return nil
	}

	values := []int{}
	appendIfPort := func(v any) {
		switch t := v.(type) {
		case float64:
			n := int(t)
			if float64(n) == t {
				values = append(values, n)
			}
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(t))
			if err == nil {
				values = append(values, n)
			}
		}
	}

	switch t := anyVal.(type) {
	case map[string]any:
		if setVal, ok := t["set"]; ok {
			if arr, ok := setVal.([]any); ok {
				for _, v := range arr {
					appendIfPort(v)
				}
				return values
			}
		}
	case []any:
		for _, v := range t {
			appendIfPort(v)
		}
		return values
	default:
		appendIfPort(anyVal)
		return values
	}

	return values
}

func DecodeNftStringValues(raw json.RawMessage) []string {
	var anyVal any
	if err := json.Unmarshal(raw, &anyVal); err != nil {
		return nil
	}

	values := []string{}
	appendOne := func(v any) {
		switch t := v.(type) {
		case string:
			for _, part := range strings.Split(t, ",") {
				s := strings.ToLower(strings.TrimSpace(part))
				if s != "" {
					values = append(values, s)
				}
			}
		}
	}

	switch t := anyVal.(type) {
	case map[string]any:
		if setVal, ok := t["set"]; ok {
			if arr, ok := setVal.([]any); ok {
				for _, v := range arr {
					appendOne(v)
				}
			}
		}
	case []any:
		for _, v := range t {
			appendOne(v)
		}
	default:
		appendOne(anyVal)
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func DecodeNftStringValue(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	values := DecodeNftStringValues(raw)
	if len(values) == 1 {
		return values[0]
	}
	return ""
}

func DiffNormalized(current, desired NormalizedSpec) NormalizedDiff {
	diff := NormalizedDiff{}

	managedChains := make(map[string]struct{})
	for chain := range desired.Policies {
		managedChains[chain] = struct{}{}
	}
	for _, rule := range desired.Rules {
		managedChains[rule.Chain] = struct{}{}
	}

	chains := make([]string, 0, len(managedChains))
	for c := range managedChains {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	for _, chain := range chains {
		desiredPolicy := desired.Policies[chain]
		currentPolicy := current.Policies[chain]
		if currentPolicy == "" {
			currentPolicy = "accept"
		}
		if desiredPolicy != currentPolicy {
			diff.PolicyChanges = append(diff.PolicyChanges,
				fmt.Sprintf("chain %s policy: %s -> %s", chain, currentPolicy, desiredPolicy))
		}
	}

	desiredSet := make(map[string]NormalizedRule, len(desired.Rules))
	for _, rule := range desired.Rules {
		desiredSet[rule.key()] = rule
	}
	currentSet := make(map[string]NormalizedRule)
	var currentManaged []NormalizedRule
	for _, rule := range current.Rules {
		if _, managed := managedChains[rule.Chain]; !managed {
			continue
		}
		currentSet[rule.key()] = rule
		currentManaged = append(currentManaged, rule)
	}

	for _, rule := range desired.Rules {
		if _, ok := currentSet[rule.key()]; !ok {
			diff.RulesToAdd = append(diff.RulesToAdd, rule)
		}
	}
	for _, rule := range currentManaged {
		if _, ok := desiredSet[rule.key()]; !ok {
			diff.RulesToRemove = append(diff.RulesToRemove, rule)
		}
	}

	diff.Reordered = reorderedChains(currentManaged, desired.Rules, chains)
	return diff
}

// reorderedChains reports the chains whose rules are all present but evaluated
// in a different order than the profile declared. A firewall with the right set
// of rules in the wrong order is a different firewall, so this is drift even
// though nothing has to be added or removed.
func reorderedChains(current, desired []NormalizedRule, chains []string) []string {
	var out []string
	for _, chain := range chains {
		currentKeys := chainRuleKeys(current, chain)
		desiredKeys := chainRuleKeys(desired, chain)
		if len(currentKeys) != len(desiredKeys) {
			continue
		}
		for i := range desiredKeys {
			if currentKeys[i] != desiredKeys[i] {
				out = append(out, chain)
				break
			}
		}
	}
	return out
}

func chainRuleKeys(rules []NormalizedRule, chain string) []string {
	var out []string
	for _, rule := range rules {
		if rule.Chain == chain {
			out = append(out, rule.key())
		}
	}
	return out
}

func RenderNormalized(spec NormalizedSpec) string {
	managedChains := make(map[string]struct{})
	for chain := range spec.Policies {
		managedChains[chain] = struct{}{}
	}
	for _, rule := range spec.Rules {
		managedChains[rule.Chain] = struct{}{}
	}

	chains := orderedFirewallChains(managedChains)
	var b strings.Builder

	fmt.Fprintf(&b, "table %s %s {\n", spec.Family, spec.Table)
	for _, chain := range chains {
		policy := spec.Policies[chain]
		fmt.Fprintf(&b, "  chain %s {\n", chain)
		fmt.Fprintf(&b, "    type filter hook %s priority 0;\n", chain)
		fmt.Fprintf(&b, "    policy %s;\n\n", policy)

		for _, rule := range spec.Rules {
			if rule.Chain != chain {
				continue
			}
			fmt.Fprintf(&b, "    %s\n", RenderNormalizedRule(spec.Family, rule))
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func orderedFirewallChains(set map[string]struct{}) []string {
	preferred := []string{"input", "forward", "output"}
	seen := make(map[string]struct{}, len(set))
	out := make([]string, 0, len(set))
	for _, chain := range preferred {
		if _, ok := set[chain]; ok {
			out = append(out, chain)
			seen[chain] = struct{}{}
		}
	}
	var rest []string
	for chain := range set {
		if _, ok := seen[chain]; ok {
			continue
		}
		rest = append(rest, chain)
	}
	sort.Strings(rest)
	out = append(out, rest...)
	return out
}

func RenderNormalizedRule(family string, r NormalizedRule) string {
	parts := make([]string, 0, 10)
	if r.InInterface != "" {
		parts = append(parts, fmt.Sprintf(`iif "%s"`, r.InInterface))
	}
	if r.OutInterface != "" {
		parts = append(parts, fmt.Sprintf(`oif "%s"`, r.OutInterface))
	}

	// The keyword follows the address, not the table: an inet table can carry
	// both, and "ip saddr" in front of an IPv6 address is a file nft refuses.
	if r.Source != "" {
		parts = append(parts, fmt.Sprintf("%s saddr %s", addressKeyword(family, r.Source), r.Source))
	}
	if r.Destination != "" {
		parts = append(parts, fmt.Sprintf("%s daddr %s", addressKeyword(family, r.Destination), r.Destination))
	}

	if len(r.CTStates) > 0 {
		parts = append(parts, "ct state "+strings.Join(r.CTStates, ","))
	}

	switch r.Proto {
	case "tcp", "udp":
		parts = append(parts, fmt.Sprintf("%s dport %d", r.Proto, r.Port))
	case "icmp":
		parts = append(parts, "ip protocol icmp")
	case "icmpv6":
		parts = append(parts, "ip6 nexthdr icmpv6")
	}
	parts = append(parts, r.Action)
	return strings.Join(parts, " ")
}

const firewallDiffPreviewLimit = 40

// firewallDiffMaxLines bounds the inputs to the LCS diff so a malicious or
// corrupt remote file can't trigger an O(n*m) DP table large enough to OOM
// the local process. Beyond this, the diff degrades to a notice line.
const firewallDiffMaxLines = 2000

type firewallDiffEdit struct {
	kind byte
	line string
}

func renderFirewallContentDiff(dest string, current string, desired string, existed bool) []string {
	edits := diffFirewallLines(current, desired)
	changed := 0
	for _, edit := range edits {
		if edit.kind != ' ' {
			changed++
		}
	}
	if changed == 0 {
		return nil
	}

	lines := []string{
		fmt.Sprintf(`--- current %s%s`, dest, firewallCurrentSuffix(existed)),
		fmt.Sprintf(`+++ desired %s`, dest),
	}
	emitted := 0
	for _, edit := range edits {
		if edit.kind == ' ' {
			continue
		}
		lines = append(lines, fmt.Sprintf("%c%s", edit.kind, edit.line))
		emitted++
		if emitted >= firewallDiffPreviewLimit {
			break
		}
	}
	if emitted < changed {
		lines = append(lines, fmt.Sprintf("... %d more content diff line(s) omitted", changed-emitted))
	}
	return lines
}

func firewallCurrentSuffix(existed bool) string {
	if existed {
		return ""
	}
	return " (absent)"
}

func diffFirewallLines(current string, desired string) []firewallDiffEdit {
	currentLines := splitFirewallDiffLines(current)
	desiredLines := splitFirewallDiffLines(desired)

	if len(currentLines) > firewallDiffMaxLines || len(desiredLines) > firewallDiffMaxLines {
		return []firewallDiffEdit{{
			kind: '!',
			line: fmt.Sprintf("content too large to diff (%d/%d lines, max %d)", len(currentLines), len(desiredLines), firewallDiffMaxLines),
		}}
	}

	dp := make([][]int, len(currentLines)+1)
	for i := range dp {
		dp[i] = make([]int, len(desiredLines)+1)
	}

	for i := len(currentLines) - 1; i >= 0; i-- {
		for j := len(desiredLines) - 1; j >= 0; j-- {
			if currentLines[i] == desiredLines[j] {
				dp[i][j] = dp[i+1][j+1] + 1
				continue
			}
			if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
				continue
			}
			dp[i][j] = dp[i][j+1]
		}
	}

	var edits []firewallDiffEdit
	i := 0
	j := 0
	for i < len(currentLines) && j < len(desiredLines) {
		if currentLines[i] == desiredLines[j] {
			edits = append(edits, firewallDiffEdit{kind: ' ', line: currentLines[i]})
			i++
			j++
			continue
		}
		if dp[i+1][j] >= dp[i][j+1] {
			edits = append(edits, firewallDiffEdit{kind: '-', line: currentLines[i]})
			i++
			continue
		}
		edits = append(edits, firewallDiffEdit{kind: '+', line: desiredLines[j]})
		j++
	}
	for i < len(currentLines) {
		edits = append(edits, firewallDiffEdit{kind: '-', line: currentLines[i]})
		i++
	}
	for j < len(desiredLines) {
		edits = append(edits, firewallDiffEdit{kind: '+', line: desiredLines[j]})
		j++
	}
	return edits
}

func splitFirewallDiffLines(text string) []string {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	if normalized == "" {
		return nil
	}
	lines := strings.Split(normalized, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func (r NormalizedRule) Key() string {
	return r.key()
}

func (r NormalizedRule) key() string {
	return strings.Join([]string{
		r.Chain,
		r.Action,
		r.Proto,
		strconv.Itoa(r.Port),
		r.Source,
		r.Destination,
		r.InInterface,
		r.OutInterface,
		strings.Join(r.CTStates, ","),
	}, "|")
}
