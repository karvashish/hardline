package executor

import (
	"fmt"
	"os"
	"strings"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

const colorReset = "\033[0m"

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
		logger.Infof("plan %s", c.Profile)
	}

	logger.Debugf("plan: profile=%q host=%q user=%q key=%q", c.Profile, c.Host, c.User, c.KeyPath)

	p, err := profile.Load(c.Profile)
	if err != nil {
		logger.Infof("profile load failed: %v", err)
		os.Exit(1)
	}

	logger.Debugf("profile loaded, starting validation")

	ver, schemaVer, err := cli.VersionCmd()
	if err != nil {
		logger.Infof("hardline version check failed: %v", err)
		os.Exit(1)
	}

	cmp, err := cli.CompareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		logger.Infof("invalid profile.min_hardline value %q: %v", p.MinHardline, err)
		os.Exit(1)
	}

	if cmp < 0 {
		logger.Infof("hardline version %s is too old; minimum required is %s",
			ver.String(), p.MinHardline)
		os.Exit(1)
	}

	if p.ProfileSchema > schemaVer {
		logger.Infof("profile schema %d is newer than supported %d; please upgrade hardline",
			p.ProfileSchema, schemaVer)
		os.Exit(1)
	}

	if err := p.Affirm(); err != nil {
		logger.Infof("profile validation failed: %v", err)
		os.Exit(1)
	}

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}

	sshClient, err := connection.NewSSHClient(*config)
	if err != nil {
		logger.Infof("connect failed: %v", err)
		os.Exit(1)
	}
	defer sshClient.Close()

	logger.Debugf("ssh connection established")

	if err := planProfile(sshClient, p); err != nil {
		logger.Infof("plan failed: %v", err)
		os.Exit(1)
	}

	if !c.Debug {
		logger.Infof("ok")
	}

	logger.Debugf("plan completed")

	// TODO:
	// 3. Generate diff of what apply would do.
	// 4. Compute per-step risk scores and priority order.
	// 5. Derive mitigations and rollback strategies.
	// 6. Aggregate final run-level risk and print report.
}

func planProfile(client *ssh.Client, p *profile.Profile) error {
	logger.Debugf("planProfile: %d action files", len(p.ActionFiles))

	var plans []StepPlan

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			if !logger.DebugMode() {
				fmt.Fprintf(os.Stderr, "step: %s (%s) ", step.ID, step.Type)
			}
			logger.Debugf("planStep: id=%q type=%q", step.ID, step.Type)

			var stop func()
			if !logger.DebugMode() {
				stop = throbber(os.Stderr)
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
				logger.Infof("✓")
			}
		}
	}

	printPlanSummary(p, plans)
	return nil
}

func printPlanSummary(p *profile.Profile, plans []StepPlan) {
	if len(plans) == 0 {
		logger.Infof("plan: profile %s has no steps", p.ID)
		return
	}

	logger.Infof(logger.ColorBold+"plan for profile %s"+colorReset, p.ID)
	logger.Infof(logger.ColorDim+"  %d step(s) across %d action file(s)"+colorReset,
		len(plans), len(p.ActionFiles))
	logger.Infof("")

	for i, sp := range plans {
		if i > 0 {
			logger.Infof("") // blank line between steps
		}

		sevLabel, sevColor := severityLabelAndColor(sp.Severity)
		riskLabel := strings.ToLower(strings.TrimSpace(sp.RiskClass))

		// Header: [severity] (risk=...) step_id (type)
		logger.Infof(
			"%s[%s]%s %s(risk=%s)%s %s%s (%s)%s",
			sevColor, sevLabel, colorReset,
			logger.ColorDim, riskLabel, colorReset,
			logger.ColorBold, sp.StepID, sp.StepType, colorReset,
		)

		logger.Infof("  %s", sp.Summary)

		if logger.DebugMode() {
			for _, line := range sp.Details {
				logger.Infof("    %s", line)
			}
		}
	}

	logger.Infof("")
}

func severityLabelAndColor(severity string) (string, string) {
	sev := strings.ToLower(strings.TrimSpace(severity))

	switch sev {
	case "critical":
		return "critical", logger.ColorRed
	case "high":
		return "high", logger.ColorYellow
	case "medium":
		return "medium", logger.ColorBlue
	case "low":
		return "low", logger.ColorGreen
	default:
		if sev == "" {
			return "unknown", logger.ColorDim
		}
		return sev, logger.ColorDim
	}
}
