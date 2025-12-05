package executor

import (
	"os"
	"strings"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func Plan(c cli.Command) {
	/*
		1. Load and validate a profile (and its actions/templates).
		2. Contact the target server and inspect current state (read-only).
		3. Generate a logical diff of what `apply` would do`.
		4. Compute per-step risk scores and priority order.
		5. Derive mitigations and rollback strategies for each step and use them to reduce risk.
		6. Aggregate a final run-level risk and present it clearly to the user.
	*/
	if !c.Debug {
		logger.Infof("plan %s\n", c.Profile)
	}

	logger.Debugf("plan: profile=%q host=%q user=%q key=%q\n", c.Profile, c.Host, c.User, c.KeyPath)

	p, err := profile.Load(c.Profile)
	if err != nil {
		logger.Errorf("profile load failed: %v\n", err)
		os.Exit(1)
	}

	logger.Debugf("profile loaded, starting validation\n")

	ver, schemaVer, err := cli.VersionCmd()
	if err != nil {
		logger.Errorf("hardline version check failed: %v\n", err)
		os.Exit(1)
	}

	cmp, err := cli.CompareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		logger.Errorf("invalid profile.min_hardline value %q: %v\n", p.MinHardline, err)
		os.Exit(1)
	}

	if cmp < 0 {
		logger.Errorf("hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline)
		os.Exit(1)
	}

	if p.ProfileSchema > schemaVer {
		logger.Errorf("profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer)
		os.Exit(1)
	}

	if err := p.Affirm(); err != nil {
		logger.Errorf("profile validation failed: %v\n", err)
		os.Exit(1)
	}

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}

	sshClient, err := connection.NewSSHClient(*config)
	if err != nil {
		logger.Errorf("connect failed: %v\n", err)
		os.Exit(1)
	}
	defer sshClient.Close()

	logger.Debugf("ssh connection established\n")

	if err := planProfile(sshClient, p, c.Host); err != nil {
		logger.Errorf("plan failed: %v\n", err)
		os.Exit(1)
	}

	if !c.Debug {
		logger.Infof("ok\n")
	}

	logger.Debugf("plan completed\n")

	// TODO:
	// 3. Generate diff of what apply would do.
	// 4. Compute per-step risk scores and priority order.
	// 5. Derive mitigations and rollback strategies.
	// 6. Aggregate final run-level risk and print report.
}

func planProfile(client *ssh.Client, p *profile.Profile, host string) error {
	logger.Debugf("planProfile: %d action files\n", len(p.ActionFiles))

	var plans []StepPlan

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			if !logger.DebugMode() {
				logger.Infof("step: %s (%s)", step.ID, step.Type)
			}
			logger.Debugf("planStep: id=%q type=%q\n", step.ID, step.Type)

			var stop func()
			if !logger.DebugMode() {
				stop = throbber()
			}

			sp, err := planStep(client, step)

			if stop != nil {
				stop()
			}

			if err != nil {
				return err
			}

			plans = append(plans, sp)

			if !logger.DebugMode() {
				logger.Infof("%s✓\n%s", logger.ColorGreen, logger.ColorReset)
			}
		}
	}
	printPlan(*p, plans, host)

	return nil
}

func printPlan(profile profile.Profile, steps []StepPlan, hostname string) {

	logger.Infof("\n%sHARDLINE PLAN%s\n",
		logger.ColorCyan+logger.ColorBold, logger.ColorReset)

	logger.Infof("%sProfile%s : %s\n",
		logger.ColorBold, logger.ColorReset, profile.DisplayName)

	logger.Infof("%sVersion%s : %s\n",
		logger.ColorBold, logger.ColorReset, profile.Version)

	logger.Infof("%sTarget %s : %s (%s %s)\n",
		logger.ColorBold, logger.ColorReset,
		hostname, profile.OS.Family, profile.OS.Version)

	logger.Infof(strings.Repeat("-", 60) + "\n\n")

	logger.Infof("%sSUMMARY%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
	logger.Infof(strings.Repeat("-", 60) + "\n")

	logger.Infof("%sPlanned steps%s : %s%d%s\n",
		logger.ColorBold, logger.ColorReset,
		logger.ColorGreen, len(steps), logger.ColorReset)

	overall := overallSeverity(steps)
	logger.Infof("%sOverall risk%s  : %s\n",
		logger.ColorBold, logger.ColorReset, severityColor(overall))

	logger.Infof("%sRollback%s     : %sAVAILABLE%s\n\n",
		logger.ColorBold, logger.ColorReset,
		logger.ColorGreen, logger.ColorReset)

	logger.Infof("%sNo changes will be made until 'hardline apply' is executed.%s\n\n",
		logger.ColorDim, logger.ColorReset)

	logger.Infof("%sACTIONS%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
	logger.Infof(strings.Repeat("=", 60) + "\n")

	for _, s := range steps {

		logger.Infof("\n%s[%s] (%s)%s\n",
			logger.ColorWhite+logger.ColorBold, s.StepID, s.StepType, logger.ColorReset)

		logger.Infof(strings.Repeat("-", 60) + "\n")

		logger.Infof("%sSummary%s : %s\n",
			logger.ColorBold, logger.ColorReset, s.Summary)

		logger.Infof("%sRisk%s    : %s\n",
			logger.ColorBold, logger.ColorReset, s.RiskClass)

		logger.Infof("%sSeverity%s: %s\n",
			logger.ColorBold, logger.ColorReset, severityColor(s.Severity))

		if logger.DebugMode() {
			if len(s.Details) > 0 {
				logger.Infof("%sDetails%s:\n", logger.ColorBold, logger.ColorReset)
				for _, line := range s.Details {
					logger.Infof("  - %s\n", line)
				}
			}
		}
	}

	logger.Infof("\n%sNEXT STEPS%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
	logger.Infof(strings.Repeat("-", 60) + "\n")

	logger.Infof("Apply changes:\n  %s\n\n",
		logger.ColorBold+"hardline apply "+profile.ID+" --host "+hostname+logger.ColorReset)

	logger.Infof("Rollback last run:\n  %s\n\n",
		logger.ColorBold+"hardline rollback last --host "+hostname+logger.ColorReset)

	logger.Infof("%sPlan complete. No changes have been made.%s\n",
		logger.ColorGreen, logger.ColorReset)
}

func overallSeverity(steps []StepPlan) string {
	max := "low"
	for _, s := range steps {
		switch strings.ToLower(s.Severity) {
		case "critical":
			return "critical"
		case "high":
			if max != "critical" {
				max = "high"
			}
		case "medium":
			if max == "low" {
				max = "medium"
			}
		}
	}
	return max
}

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return logger.ColorBrightRed + "CRITICAL" + logger.ColorReset
	case "high":
		return logger.ColorRed + "HIGH" + logger.ColorReset
	case "medium":
		return logger.ColorYellow + "MEDIUM" + logger.ColorReset
	case "low":
		return logger.ColorGreen + "LOW" + logger.ColorReset
	default:

		return sev
	}
}
