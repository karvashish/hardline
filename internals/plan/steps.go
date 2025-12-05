package plan

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
)

type StepPlan struct {
	StepID    string
	StepType  string
	Severity  string
	RiskClass string

	Summary string
	Details []string
}

func planStep(insp inspector.Inspector, s profile.Step) (StepPlan, error) {
	stepType := strings.ToLower(strings.TrimSpace(s.Type))

	plan := StepPlan{
		StepID:    s.ID,
		StepType:  stepType,
		Severity:  s.Severity,
		RiskClass: s.RiskClass,
	}

	switch stepType {
	case "packages":
		if s.Packages == nil {
			return plan, fmt.Errorf("step %q (type=%s): packages spec missing", s.ID, s.Type)
		}
		summary, details, noop, err := planPackages(insp, s.Packages)
		if err != nil {
			return plan, err
		}
		plan.Summary = summary
		plan.Details = details
		switch noop {
		case 1:
			plan.Severity = "medium"
		case 0:
			plan.Severity = "low"
		}
		return plan, nil

	case "template":
		if s.Template == nil {
			return plan, fmt.Errorf("step %q (type=%s): template spec missing", s.ID, s.Type)
		}
		summary, details, err := planTemplate(insp, s.Template)
		if err != nil {
			return plan, err
		}
		plan.Summary = summary
		plan.Details = details
		return plan, nil

	case "service":
		if s.Service == nil {
			return plan, fmt.Errorf("step %q (type=%s): service spec missing", s.ID, s.Type)
		}
		summary, details, err := planService(insp, s.Service)
		if err != nil {
			return plan, err
		}
		plan.Summary = summary
		plan.Details = details
		return plan, nil

	case "firewall":
		if s.Firewall == nil {
			return plan, fmt.Errorf("step %q (type=%s): firewall spec missing", s.ID, s.Type)
		}
		summary, details, err := planFirewall(insp, s.Firewall)
		if err != nil {
			return plan, err
		}
		plan.Summary = summary
		plan.Details = details
		return plan, nil

	case "validate":
		kind := strings.TrimSpace(s.Validate)
		if kind == "" {
			return plan, fmt.Errorf("step %q (type=%s): validate spec missing", s.ID, s.Type)
		}
		summary, details, err := planValidate(insp, kind)
		if err != nil {
			return plan, err
		}
		plan.Summary = summary
		plan.Details = details
		return plan, nil

	default:
		plan.Summary = fmt.Sprintf("unknown or empty step type %q (no-op in planning)", s.Type)
		return plan, nil
	}
}

func planPackages(insp inspector.Inspector, pk *profile.PackageSpec) (string, []string, int, error) {
	logger.Debugf("planPackages: update=%v upgrade=%v install=%v purge=%v autoremove=%v\n",
		pk.Update, pk.Upgrade, pk.Install, pk.Purge, pk.Autoremove)

	var details []string

	var installWillChange []string
	var installDepsWillChange []string
	var purgeWillChange []string
	var upgradeWillChange []string
	var autoremoveWillChange []string

	if pk.Update {
		details = append(details, logger.ColorGreen+"will run: apt-get update -y"+logger.ColorReset)
	}
	if pk.Upgrade {
		up, err := insp.AptUpgradePreview()
		if err != nil {
			details = append(details,
				logger.ColorRed+fmt.Sprintf("upgrade: failed to preview upgrades (%v)", err)+logger.ColorReset,
			)
		} else if len(up) == 0 {
			details = append(details,
				logger.ColorBlue+"upgrade: no packages would be upgraded (no-op)"+logger.ColorReset,
			)
		} else {
			upgradeWillChange = up
			details = append(details,
				logger.ColorGreen+fmt.Sprintf("upgrade: would upgrade %d package(s): %s",
					len(up), strings.Join(up, ", "))+logger.ColorReset,
			)
		}
	}

	for _, name := range pk.Install {
		if insp.PackageInstalled(name) {
			line := fmt.Sprintf(
				"%spackage %q:%s %scurrently installed (no install change)%s",
				logger.ColorBlue, name, logger.ColorReset,
				logger.ColorYellow, logger.ColorReset,
			)
			details = append(details, line)
		} else {
			installWillChange = append(installWillChange, name)

			line := fmt.Sprintf(
				"%spackage %q:%s %snot installed (will be installed)%s",
				logger.ColorBlue, name, logger.ColorReset,
				logger.ColorGreen, logger.ColorReset,
			)
			details = append(details, line)
		}
	}

	if len(pk.Install) > 0 {
		all, err := insp.AptInstallPreview(pk.Install)
		if err != nil {
			details = append(details,
				logger.ColorRed+fmt.Sprintf("install: failed to preview dependency installs (%v)", err)+logger.ColorReset,
			)
		} else if len(all) > 0 {
			explicit := make(map[string]struct{}, len(pk.Install))
			for _, name := range pk.Install {
				explicit[name] = struct{}{}
			}
			for _, name := range all {
				if _, ok := explicit[name]; ok {
					continue
				}
				installDepsWillChange = append(installDepsWillChange, name)
			}
			if len(installDepsWillChange) > 0 {
				details = append(details,
					logger.ColorDim+fmt.Sprintf("apt will also install %d dependency package(s): %s",
						len(installDepsWillChange), strings.Join(installDepsWillChange, ", "))+logger.ColorReset,
				)
			}
		}
	}

	for _, name := range pk.Purge {
		if insp.PackageInstalled(name) {
			purgeWillChange = append(purgeWillChange, name)

			line := fmt.Sprintf(
				"%spackage %q:%s %scurrently installed (will be purged)%s",
				logger.ColorBlue, name, logger.ColorReset,
				logger.ColorRed, logger.ColorReset,
			)
			details = append(details, line)
		} else {
			line := fmt.Sprintf(
				"%spackage %q:%s %snot installed (purge has no effect)%s",
				logger.ColorBlue, name, logger.ColorReset,
				logger.ColorDim, logger.ColorReset,
			)
			details = append(details, line)
		}
	}

	if pk.Autoremove {
		pkgs, err := insp.AptAutoremovePreview()
		if err != nil {
			details = append(details,
				logger.ColorRed+fmt.Sprintf("autoremove: failed to preview packages to be removed (%v)", err)+logger.ColorReset,
			)
		} else if len(pkgs) == 0 {
			msg := "autoremove: no packages would be removed (no-op)"
			if pk.Upgrade {
				msg = "autoremove: no packages would be removed (current state; may change after upgrade)"
			}
			details = append(details, logger.ColorBlue+msg+logger.ColorReset)
		} else {
			autoremoveWillChange = pkgs
			msg := fmt.Sprintf("autoremove: would remove %d package(s): %s", len(pkgs), strings.Join(pkgs, ", "))
			if pk.Upgrade {
				msg += " (may change after upgrade)"
			}
			details = append(details, logger.ColorGreen+msg+logger.ColorReset)
		}
	}

	var summary string
	var noop int = 2
	if !pk.Update &&
		(!pk.Upgrade || len(upgradeWillChange) == 0) &&
		len(installWillChange) == 0 &&
		len(installDepsWillChange) == 0 &&
		len(purgeWillChange) == 0 &&
		(!pk.Autoremove || len(autoremoveWillChange) == 0) {
		noop = 0
		summary = "packages step: no-op (no update/upgrade/install/purge/autoremove specified or no changes required)"
	} else if pk.Update &&
		len(upgradeWillChange) == 0 &&
		len(installWillChange) == 0 &&
		len(installDepsWillChange) == 0 &&
		len(purgeWillChange) == 0 &&
		(!pk.Autoremove || len(autoremoveWillChange) == 0) {
		summary = "packages step: update package index (install/upgrade/purge/autoremove currently no-op; may change after update)"
		noop = 1
	} else {
		var summaryParts []string
		if pk.Update {
			summaryParts = append(summaryParts, "update package index")
		}
		if pk.Upgrade {
			if len(upgradeWillChange) == 0 {
				if pk.Update {
					summaryParts = append(summaryParts,
						fmt.Sprintf("upgrade installed packages %s(none currently; may change after update)%s", logger.ColorYellow, logger.ColorReset))
				} else {
					summaryParts = append(summaryParts, fmt.Sprintf("upgrade installed packages %s(none)%s", logger.ColorGreen, logger.ColorReset))
				}
			} else {
				summaryParts = append(summaryParts,
					"upgrade: "+strings.Join(upgradeWillChange, ", "))
			}
		}

		if len(installWillChange) > 0 {
			summaryParts = append(summaryParts, "install: "+strings.Join(installWillChange, ", "))
		}
		if len(installDepsWillChange) > 0 {
			summaryParts = append(summaryParts, "install dependencies: "+strings.Join(installDepsWillChange, ", "))
		}
		if len(purgeWillChange) > 0 {
			summaryParts = append(summaryParts, "purge: "+strings.Join(purgeWillChange, ", "))
		}
		if pk.Autoremove {
			if len(autoremoveWillChange) == 0 {
				if pk.Upgrade {
					summaryParts = append(summaryParts,
						fmt.Sprintf("autoremove %s(none currently; may change after upgrade)%s", logger.ColorYellow, logger.ColorReset))
				} else {
					summaryParts = append(summaryParts,
						"autoremove unused packages (no packages to remove)")
				}
			} else {
				line := "autoremove unused packages: " + strings.Join(autoremoveWillChange, ", ")
				if pk.Upgrade {
					line += " (may change after upgrade)"
				}
				summaryParts = append(summaryParts, line)
			}
		}
		summary = "packages step: " + strings.Join(summaryParts, "; ")
	}

	return summary, details, noop, nil
}

func planTemplate(insp inspector.Inspector, t *profile.TemplateSpec) (string, []string, error) {
	logger.Debugf("planTemplate: src=%q dest=%q mode=%q\n", t.Src, t.Dest, t.Mode)

	var details []string

	info, err := insp.Stat(t.Dest)
	if err != nil {
		line := fmt.Sprintf(
			"%sdestination %q:%s %sdoes not exist (file will be created)%s",
			logger.ColorBlue, t.Dest, logger.ColorReset,
			logger.ColorGreen, logger.ColorReset,
		)
		details = append(details, line)
	} else {
		line := fmt.Sprintf(
			"%sdestination %q:%s %sexists (size=%d bytes, mode=%#o)%s",
			logger.ColorBlue, t.Dest, logger.ColorReset,
			logger.ColorYellow, info.Size(), info.Mode().Perm(), logger.ColorReset,
		)
		details = append(details, line)
	}

	mode := strings.TrimSpace(t.Mode)
	if mode == "" {
		mode = "0600 (default in executor)"
	}
	details = append(details,
		logger.ColorGreen+fmt.Sprintf("desired: template %q rendered to %q with mode %s", t.Src, t.Dest, mode)+logger.ColorReset,
	)

	if strings.HasPrefix(t.Dest, "/etc/ssh/") {
		details = append(details, logger.ColorDim+"note: this template affects SSH daemon configuration"+logger.ColorReset)
	}
	if strings.Contains(t.Dest, "nftables") {
		details = append(details, logger.ColorDim+"note: this template affects nftables firewall configuration"+logger.ColorReset)
	}

	summary := fmt.Sprintf("template step: render %q to %q (mode %s)", t.Src, t.Dest, mode)
	return summary, details, nil
}

func planService(insp inspector.Inspector, s *profile.ServiceSpec) (string, []string, error) {
	if s.Name == "" {
		return "service step: invalid (missing service name)", nil, fmt.Errorf("service name is required")
	}

	unit := s.Name

	if unit == "sshd" {
		unit = "ssh"
	}
	logger.Debugf("planService: name=%q unit=%q enabled=%v state=%q\n", s.Name, unit, s.Enabled, s.State)

	var details []string

	enabledState := "unknown"
	if insp.IsServiceEnabled(unit) {
		enabledState = "enabled"
	} else {
		enabledState = "disabled or not-found"
	}

	activeState := "unknown"
	if insp.IsServiceActive(unit) {
		activeState = "active"
	} else {
		activeState = "inactive or not-found"
	}

	details = append(details,
		logger.ColorYellow+fmt.Sprintf("current: enabled=%s, active=%s", enabledState, activeState)+logger.ColorReset,
	)

	desiredEnabled := "unchanged"
	if s.Enabled != nil {
		if *s.Enabled {
			desiredEnabled = "enabled"
		} else {
			desiredEnabled = "disabled"
		}
	}
	state := strings.ToLower(strings.TrimSpace(s.State))
	desiredState := "unchanged"
	switch state {
	case "":

	case "started", "start":
		desiredState = "active"
	case "stopped", "stop":
		desiredState = "inactive"
	case "restarted", "restart":
		desiredState = "restarted (active)"
	case "reloaded", "reload":
		desiredState = "reloaded or restarted (active)"
	default:
		desiredState = fmt.Sprintf("unsupported (%q)", s.State)
	}

	details = append(details,
		logger.ColorGreen+fmt.Sprintf("desired: enabled=%s, state=%s", desiredEnabled, desiredState)+logger.ColorReset,
	)

	var summaryParts []string
	if s.Enabled != nil {
		if *s.Enabled {
			summaryParts = append(summaryParts, fmt.Sprintf("enable %s at boot", unit))
		} else {
			summaryParts = append(summaryParts, fmt.Sprintf("disable %s at boot", unit))
		}
	}
	switch state {
	case "":

	case "started", "start":
		summaryParts = append(summaryParts, fmt.Sprintf("ensure %s is started", unit))
	case "stopped", "stop":
		summaryParts = append(summaryParts, fmt.Sprintf("ensure %s is stopped", unit))
	case "restarted", "restart":
		summaryParts = append(summaryParts, fmt.Sprintf("restart %s", unit))
	case "reloaded", "reload":
		summaryParts = append(summaryParts, fmt.Sprintf("reload or restart %s", unit))
	default:
		summaryParts = append(summaryParts, fmt.Sprintf("unsupported state %q requested for %s", s.State, unit))
	}

	var summary string
	if len(summaryParts) == 0 {
		summary = fmt.Sprintf("service step: no-op for %s (no enable/state change requested)", unit)
	} else {
		summary = "service step: " + strings.Join(summaryParts, "; ")
	}

	return summary, details, nil
}

func planFirewall(insp inspector.Inspector, fw *profile.FirewallSpec) (string, []string, error) {
	logger.Debugf("planFirewall: backend=%q allow_rules=%d\n", fw.Backend, len(fw.Allow))

	var details []string

	if fw.Backend != "nftables" {
		summary := fmt.Sprintf("firewall step: unsupported backend %q (no-op)", fw.Backend)
		return summary, []string{"only nftables backend is supported by executor"}, nil
	}

	tmplPath := strings.TrimSpace(fw.TemplateSrc)
	if tmplPath == "" {
		tmplPath = "templates/nftables_base.tmpl"
	}
	destPath := strings.TrimSpace(fw.TemplateDest)
	if destPath == "" {
		destPath = "/etc/nftables.d/10-hardline.nft"
	}

	info, err := insp.Stat(destPath)
	if err != nil {
		line := fmt.Sprintf(
			"%sdestination %q:%s %sdoes not exist (file will be created)%s",
			logger.ColorBlue, destPath, logger.ColorReset,
			logger.ColorGreen, logger.ColorReset,
		)
		details = append(details, line)
	} else {
		line := fmt.Sprintf(
			"%sdestination %q:%s %sexists (size=%d bytes, mode=%#o)%s",
			logger.ColorBlue, destPath, logger.ColorReset,
			logger.ColorYellow, info.Size(), info.Mode().Perm(), logger.ColorReset,
		)
		details = append(details, line)
	}

	details = append(details,
		logger.ColorBlue+fmt.Sprintf("template source: %q", tmplPath)+logger.ColorReset,
	)

	if len(fw.Allow) == 0 {
		details = append(details,
			logger.ColorDim+"no allow rules specified (policy in template will apply as-is)"+logger.ColorReset,
		)
	} else {
		details = append(details, logger.ColorDim+"allow rules to be enforced:"+logger.ColorReset)
		for _, rule := range fw.Allow {
			proto := strings.ToLower(strings.TrimSpace(rule.Proto))
			if proto == "" {
				proto = "tcp"
			}
			line := fmt.Sprintf(
				"  %s- %s dport %d accept%s",
				logger.ColorGreen, proto, rule.Port, logger.ColorReset,
			)
			details = append(details, line)
		}
	}

	summary := fmt.Sprintf("firewall step: backend=nftables, template=%q -> %q, %d allow rule(s)",
		tmplPath, destPath, len(fw.Allow))

	return summary, details, nil
}

func planValidate(insp inspector.Inspector, kind string) (string, []string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "sshd":
		logger.Debugf("planValidate: kind=sshd\n")

		var details []string

		if insp.SSHIncludePresent() {
			details = append(details,
				logger.ColorGreen+"sshd_config: Include for /etc/ssh/sshd_config.d/*.conf is present"+logger.ColorReset,
			)
		} else {
			details = append(details,
				logger.ColorYellow+"sshd_config: Include for /etc/ssh/sshd_config.d/*.conf is missing (apply will append it)"+logger.ColorReset,
			)
		}

		testErr := insp.SSHConfigTest()
		if testErr == nil {
			details = append(details,
				logger.ColorGreen+"current sshd configuration: passes sshd -t"+logger.ColorReset,
			)
		} else {
			details = append(details,
				logger.ColorRed+fmt.Sprintf("current sshd configuration: sshd -t reports errors (%v)", testErr)+logger.ColorReset,
			)
		}

		summary := "validate sshd: check Include hook and sshd -t on /etc/ssh/sshd_config"
		return summary, details, nil

	case "firewall":
		logger.Debugf("planValidate: kind=firewall\n")

		var details []string

		if insp.FirewallIncludePresent() {
			details = append(details,
				logger.ColorGreen+`nftables.conf: include "/etc/nftables.d/*.nft" is present`+logger.ColorReset,
			)
		} else {
			details = append(details,
				logger.ColorYellow+`nftables.conf: include "/etc/nftables.d/*.nft" is missing (apply will append it)`+logger.ColorReset,
			)
		}

		testErr := insp.FirewallConfigTest()
		if testErr == nil {
			details = append(details,
				logger.ColorGreen+"current nftables configuration: passes nft -c -f /etc/nftables.conf"+logger.ColorReset,
			)
		} else {
			details = append(details,
				logger.ColorRed+fmt.Sprintf("current nftables configuration: nft -c reports errors (%v)", testErr)+logger.ColorReset,
			)
		}

		summary := "validate firewall: check include for /etc/nftables.d/*.nft and nft -c on /etc/nftables.conf"
		return summary, details, nil

	default:
		summary := fmt.Sprintf("validate step: unsupported kind %q", kind)
		return summary, []string{"no validation logic implemented for this kind"}, nil
	}
}
