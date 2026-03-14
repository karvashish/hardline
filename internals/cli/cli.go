package cli

import (
	"flag"
	"io"
	"os"

	"github.com/karvashish/hardline/pkg/logger"
)

var (
	infof    = logger.Infof
	errorf   = logger.Errorf
	exitFunc = os.Exit
)

func Usage() {
	infof(`Usage:
  hardline <command> [args]

Commands:
  plan <profile> [--host HOST| -h HOST] [--user USER| -u USER] [--keypath PATH| -k PATH] [--log-file PATH] [--report-file PATH] [--report-format json|yaml|md] [--debug| -d]
                         run plan with profile
  apply <profile> [--host HOST| -h HOST] [--user USER| -u USER] [--keypath PATH| -k PATH] [--log-file PATH] [--report-file PATH] [--report-format json|yaml|md] [--debug| -d]
                         run apply with profile
  rollback last [--host HOST| -h HOST] [--user USER| -u USER] [--keypath PATH| -k PATH] [--log-file PATH] [--debug| -d]
                         rollback the last successful apply run
  verify-profile <profile> [--log-file PATH] [--debug| -d]
                         run verify-profile with profile
  vp <profile> [--log-file PATH] [--debug| -d]
                         alias for verify-profile
  version                show version info
  -v                     alias for version

Examples:
  hardline plan dev --host example.com --user deploy --keypath ~/.ssh/id_rsa
  hardline plan dev --report-file ./reports/dev-plan.yaml
  hardline apply prod -h example.com -u deploy -k ~/.ssh/id_rsa -d
  hardline rollback last -h example.com -u deploy -k ~/.ssh/id_rsa
  hardline vp staging --debug
  hardline -v
`)
}

func Parse(command string, args []string) Command {
	if len(args) < 1 {
		errorf("%s requires a profile\n", command)
		exitFunc(1)
		return Command{}
	}

	profile := args[0]
	rest := args[1:]

	var (
		host         string
		user         string
		keypath      string
		logFile      string
		reportFile   string
		reportFormat string
		debug        bool
	)

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&logFile, "log-file", "", "write plain-text logs to file")

	switch command {
	case "plan", "apply", "rollback":
		fs.StringVar(&host, "host", "", "remote host")
		fs.StringVar(&host, "h", "", "remote host (shorthand)")
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
	default:
		fs.BoolVar(&debug, "debug", false, "enable debug output")
		fs.BoolVar(&debug, "d", false, "enable debug output (shorthand)")
	}

	if err := fs.Parse(rest); err != nil {
		errorf("invalid flags for %s: %v\n", command, err)
		exitFunc(2)
		return Command{}
	}

	if debug {
		logger.Debugf("cli: name=%s profile=%s host=%s user=%s key=%s log_file=%s report_file=%s report_format=%s debug=%t",
			command, profile, host, user, keypath, logFile, reportFile, reportFormat, debug)
	}

	return Command{
		Name:         command,
		Profile:      profile,
		Host:         host,
		User:         user,
		KeyPath:      keypath,
		LogFile:      logFile,
		ReportFile:   reportFile,
		ReportFormat: reportFormat,
		Debug:        debug,
	}
}
