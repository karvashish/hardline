package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/karvashish/hardline/pkg/logger"
)

func Usage() {
	fmt.Println(`Usage:
  hardline <command> [args]

Commands:
  plan <profile> [--host HOST| -h HOST] [--user USER| -u USER] [--keypath PATH| -k PATH] [--debug| -d]
                         run plan with profile
  apply <profile> [--host HOST| -h HOST] [--user USER| -u USER] [--keypath PATH| -k PATH] [--debug| -d]
                         run apply with profile
  verify-profile <profile> [--debug| -d]
                         run verify-profile with profile
  vp <profile> [--debug| -d]
                         alias for verify-profile
  version                show version info
  -v                     alias for version

Examples:
  hardline plan dev --host example.com --user deploy --keypath ~/.ssh/id_rsa
  hardline apply prod -h example.com -u deploy -k ~/.ssh/id_rsa -d
  hardline vp staging --debug
  hardline -v`)
}

func Parse(command string, args []string) Command {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "%s requires a profile\n", command)
		os.Exit(1)
	}

	profile := args[0]
	rest := args[1:]

	var (
		host    string
		user    string
		keypath string
		debug   bool
	)

	fs := flag.NewFlagSet(command, flag.ExitOnError)

	switch command {
	case "plan", "apply":
		fs.StringVar(&host, "host", "", "remote host")
		fs.StringVar(&host, "h", "", "remote host (shorthand)")
		fs.StringVar(&user, "user", "", "remote user")
		fs.StringVar(&user, "u", "", "remote user (shorthand)")
		fs.StringVar(&keypath, "keypath", "", "ssh key path")
		fs.StringVar(&keypath, "k", "", "ssh key path (shorthand)")
		fs.BoolVar(&debug, "debug", false, "enable debug output")
		fs.BoolVar(&debug, "d", false, "enable debug output (shorthand)")
	default:
		fs.BoolVar(&debug, "debug", false, "enable debug output")
		fs.BoolVar(&debug, "d", false, "enable debug output (shorthand)")
	}

	if err := fs.Parse(rest); err != nil {
		os.Exit(2)
	}

	if debug {
		logger.Debugf("cli: name=%s profile=%s host=%s user=%s key=%s debug=%t",
			command, profile, host, user, keypath, debug)
	}

	return Command{
		Name:    command,
		Profile: profile,
		Host:    host,
		User:    user,
		KeyPath: keypath,
		Debug:   debug,
	}
}
