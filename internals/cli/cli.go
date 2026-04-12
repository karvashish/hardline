package cli

import (
	"flag"
	"io"
	"os"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
)

var (
	infof    = logger.Infof
	errorf   = logger.Errorf
	exitFunc = os.Exit
)

func Usage() {
	infof("%s", rootUsageText())
}

func UsageFor(command string) {
	infof("%s", commandUsageText(command))
}

func rootUsageText() string {
	return `Usage:
  hardline [-h|--help|-help]
  hardline [-v|-V|--version|-version]
  hardline <command> [args]

Global Flags:
  -h, --help, -help    show usage
  -v, -V, --version, -version
                        show version info

Commands:
  plan <profile> [--host HOST| -H HOST] [--port PORT| -p PORT] [--user USER| -u USER] [--keypath PATH| -k PATH] [--overrides-file PATH] [--allow-local-key] [--log-file PATH] [--report-file PATH] [--report-format json|yaml|md] [--debug| -d]
                         run plan with profile
  apply <profile> [--host HOST| -H HOST] [--port PORT| -p PORT] [--user USER| -u USER] [--keypath PATH| -k PATH] [--overrides-file PATH] [--allow-local-key] [--log-file PATH] [--report-file PATH] [--report-format json|yaml|md] [--keep-local-rollback] [--debug| -d]
                         run apply with profile
  rollback <profile> [--host HOST| -H HOST] [--port PORT| -p PORT] [--user USER| -u USER] [--keypath PATH| -k PATH] [--allow-local-key] [--log-file PATH] [--force-rollback] [--debug| -d]
                         rollback the last successful apply run for a profile
  verify-profile <profile> [--overrides-file PATH] [--allow-local-key] [--log-file PATH] [--debug| -d]
                         run verify-profile with profile
  verify <profile> [--overrides-file PATH] [--allow-local-key] [--log-file PATH] [--debug| -d]
                         alias for verify-profile
  vp <profile> [--overrides-file PATH] [--allow-local-key] [--log-file PATH] [--debug| -d]
                         alias for verify-profile
  version                show version info

Examples:
  hardline --help
  hardline --version
  hardline <command> --help
  hardline plan dev --host example.com --user deploy --keypath ~/.ssh/id_rsa
  hardline plan dev                 # auto-loads profile.overrides.json from the profile directory when present
  hardline plan dev --overrides-file ./runtime/dev-overrides.json
  hardline plan dev --report-file ./reports/dev-plan.yaml
  hardline apply prod -H example.com -u deploy -k ~/.ssh/id_rsa --keep-local-rollback -d
  hardline rollback starter-secure-ubuntu-24.04-lts -H example.com -u deploy -k ~/.ssh/id_rsa
  hardline verify staging --debug
  hardline -V
`
}

func commandUsageText(command string) string {
	switch normalizeUsageCommand(command) {
	case "plan":
		return `Usage:
  hardline plan <profile> [--host HOST| -H HOST] [--port PORT| -p PORT] [--user USER| -u USER] [--keypath PATH| -k PATH] [--overrides-file PATH] [--allow-local-key] [--log-file PATH] [--report-file PATH] [--report-format json|yaml|md] [--debug| -d]

Arguments:
  <profile>              profile directory to plan

Flags:
  --help, -h, -help      show plan usage
  --host, -H HOST        remote host
  --port, -p PORT        ssh port (default 22)
  --user, -u USER        remote user
  --keypath, -k PATH     ssh key path
  --overrides-file PATH  load runtime overrides from a JSON object file; when omitted, auto-load profile.overrides.json from the profile directory
  --allow-local-key      verify profile using a local signing key from /etc/hardline/profile_signing_pub.pem
  --log-file PATH        write plain-text logs to file
  --report-file PATH     write plan report to file
  --report-format VALUE  report format: json, yaml, or md
  --debug, -d            enable debug output

Example:
  hardline plan dev --host example.com --user deploy --keypath ~/.ssh/id_rsa --overrides-file ./runtime/dev-overrides.json
`
	case "apply":
		return `Usage:
  hardline apply <profile> [--host HOST| -H HOST] [--port PORT| -p PORT] [--user USER| -u USER] [--keypath PATH| -k PATH] [--overrides-file PATH] [--allow-local-key] [--log-file PATH] [--report-file PATH] [--report-format json|yaml|md] [--keep-local-rollback] [--debug| -d]

Arguments:
  <profile>              profile directory to apply

Flags:
  --help, -h, -help      show apply usage
  --host, -H HOST        remote host
  --port, -p PORT        ssh port (default 22)
  --user, -u USER        remote user
  --keypath, -k PATH     ssh key path
  --overrides-file PATH  load runtime overrides from a JSON object file; when omitted, auto-load profile.overrides.json from the profile directory
  --allow-local-key      verify profile using a local signing key from /etc/hardline/profile_signing_pub.pem
  --log-file PATH        write plain-text logs to file
  --report-file PATH     write plan report to file
  --report-format VALUE  report format: json, yaml, or md
  --keep-local-rollback  keep the runner-side rollback journal after a successful apply
  --debug, -d            enable debug output

Example:
  hardline apply prod -H example.com -u deploy -k ~/.ssh/id_rsa --overrides-file ./runtime/prod-overrides.json --keep-local-rollback
`
	case "rollback":
		return `Usage:
  hardline rollback <profile> [--host HOST| -H HOST] [--port PORT| -p PORT] [--user USER| -u USER] [--keypath PATH| -k PATH] [--allow-local-key] [--log-file PATH] [--force-rollback] [--debug| -d]

Arguments:
  <profile>              profile directory to rollback

Flags:
  --help, -h, -help      show rollback usage
  --host, -H HOST        remote host
  --port, -p PORT        ssh port (default 22)
  --user, -u USER        remote user
  --keypath, -k PATH     ssh key path
  --allow-local-key      verify profile using a local signing key from /etc/hardline/profile_signing_pub.pem
  --log-file PATH        write plain-text logs to file
  --force-rollback       proceed even when a file was modified after this profile ran
                         (use when another profile or manual edit changed an overlapping file)
  --debug, -d            enable debug output

Example:
  hardline rollback starter-secure-ubuntu-24.04-lts -H example.com -u deploy -k ~/.ssh/id_rsa
`
	case "verify-profile":
		return `Usage:
  hardline verify-profile <profile> [--overrides-file PATH] [--allow-local-key] [--log-file PATH] [--debug| -d]

Aliases:
  verify
  vp

Arguments:
  <profile>              profile directory to verify

Flags:
  --help, -h, -help      show verify-profile usage
  --overrides-file PATH  load runtime overrides from a JSON object file; when omitted, auto-load profile.overrides.json from the profile directory
  --allow-local-key      verify profile using a local signing key from /etc/hardline/profile_signing_pub.pem
  --log-file PATH        write plain-text logs to file
  --debug, -d            enable debug output

Example:
  hardline verify staging --debug
`
	case "version":
		return `Usage:
  hardline version
  hardline -v
  hardline -V
  hardline --version
  hardline -version

Flags:
  --help, -h, -help      show version usage

Example:
  hardline --version
`
	default:
		return rootUsageText()
	}
}

func normalizeUsageCommand(command string) string {
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "verify", "vp":
		return "verify-profile"
	default:
		return strings.ToLower(strings.TrimSpace(command))
	}
}

func isHelpFlag(arg string) bool {
	switch strings.TrimSpace(arg) {
	case "-h", "--help", "-help":
		return true
	default:
		return false
	}
}

func Parse(command string, args []string) Command {
	if len(args) >= 1 && isHelpFlag(args[0]) {
		UsageFor(command)
		exitFunc(0)
		return Command{}
	}

	if len(args) < 1 {
		errorf("%s requires a profile\n", command)
		exitFunc(1)
		return Command{}
	}

	profile := args[0]
	rest := args[1:]

	var (
		host              string
		port              int
		user              string
		keypath           string
		overridesFile     string
		logFile           string
		reportFile        string
		reportFormat      string
		keepLocalRollback bool
		forceRollback     bool
		allowLocalKey     bool
		help              bool
		debug             bool
	)

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&help, "help", false, "show usage")
	fs.BoolVar(&help, "h", false, "show usage (shorthand)")
	fs.StringVar(&logFile, "log-file", "", "write plain-text logs to file")
	fs.BoolVar(&allowLocalKey, "allow-local-key", false, "verify profile using a local signing key")

	switch command {
	case "plan", "apply", "verify-profile", "verify", "vp":
		fs.StringVar(&overridesFile, "overrides-file", "", "load runtime overrides from a JSON object file")
	}

	switch command {
	case "plan", "apply", "rollback":
		fs.StringVar(&host, "host", "", "remote host")
		fs.StringVar(&host, "H", "", "remote host (shorthand)")
		fs.IntVar(&port, "port", 0, "ssh port (default 22)")
		fs.IntVar(&port, "p", 0, "ssh port (shorthand)")
		fs.StringVar(&user, "user", "", "remote user")
		fs.StringVar(&user, "u", "", "remote user (shorthand)")
		fs.StringVar(&keypath, "keypath", "", "ssh key path")
		fs.StringVar(&keypath, "k", "", "ssh key path (shorthand)")
		fs.BoolVar(&debug, "debug", false, "enable debug output")
		fs.BoolVar(&debug, "d", false, "enable debug output (shorthand)")
		if command == "plan" || command == "apply" {
			fs.StringVar(&reportFile, "report-file", "", "write plan report to file")
			fs.StringVar(&reportFormat, "report-format", "", "report format: json, yaml, or md")
		}
		if command == "apply" {
			fs.BoolVar(&keepLocalRollback, "keep-local-rollback", false, "keep the runner-side rollback journal after a successful apply")
		}
		if command == "rollback" {
			fs.BoolVar(&forceRollback, "force-rollback", false, "proceed even when a file was modified after this profile ran")
		}
	default:
		fs.BoolVar(&debug, "debug", false, "enable debug output")
		fs.BoolVar(&debug, "d", false, "enable debug output (shorthand)")
	}

	if err := fs.Parse(rest); err != nil {
		errorf("invalid flags for %s: %v\n", command, err)
		exitFunc(2)
		return Command{}
	}
	if help {
		UsageFor(command)
		exitFunc(0)
		return Command{}
	}

	if debug {
		logger.Debugf("cli: name=%s profile=%s host=%s port=%d user=%s key=%s overrides_file=%s log_file=%s report_file=%s report_format=%s keep_local_rollback=%t allow_local_key=%t debug=%t",
			command, profile, host, port, user, keypath, overridesFile, logFile, reportFile, reportFormat, keepLocalRollback, allowLocalKey, debug)
	}

	return Command{
		Name:              command,
		Profile:           profile,
		Host:              host,
		Port:              port,
		User:              user,
		KeyPath:           keypath,
		OverridesFile:     strings.TrimSpace(overridesFile),
		LogFile:           logFile,
		ReportFile:        reportFile,
		ReportFormat:      reportFormat,
		KeepLocalRollback: keepLocalRollback,
		ForceRollback:     forceRollback,
		AllowLocalKey:     allowLocalKey,
		Debug:             debug,
	}
}
