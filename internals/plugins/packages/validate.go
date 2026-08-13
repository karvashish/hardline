// Package packages holds the lifecycle engine and leaf helpers shared by the
// apt, dnf4 and dnf5 package plugins. It registers no plugin of its own; each
// backend supplies its package syntax, commands, query and preview parsers.
package packages

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateNames bounds every name from the profile against the caller's own
// naming rule before it reaches a root command. The leading alphanumeric each
// pattern requires is what rejects a name like --force that would otherwise be
// read as an option.
func ValidateNames(nameRe *regexp.Regexp, names []string) error {
	for _, name := range names {
		if !nameRe.MatchString(name) {
			return fmt.Errorf("invalid package name %q: must match %s", name, nameRe.String())
		}
	}
	return nil
}

// ValidateLists checks the install and purge lists for empties, duplicates and
// entries asking to be installed and purged at once, then bounds every name
// against the caller's naming rule.
func ValidateLists(nameRe *regexp.Regexp, installList, purgeList []string) error {
	install := make(map[string]struct{}, len(installList))
	for _, raw := range installList {
		name := strings.TrimSpace(raw)
		if name == "" {
			return fmt.Errorf("packages install entries must not be empty")
		}
		if _, exists := install[name]; exists {
			return fmt.Errorf("package %q is duplicated in install list", name)
		}
		install[name] = struct{}{}
	}

	purge := make(map[string]struct{}, len(purgeList))
	for _, raw := range purgeList {
		name := strings.TrimSpace(raw)
		if name == "" {
			return fmt.Errorf("packages purge entries must not be empty")
		}
		if _, exists := purge[name]; exists {
			return fmt.Errorf("package %q is duplicated in purge list", name)
		}
		purge[name] = struct{}{}
		if _, exists := install[name]; exists {
			return fmt.Errorf("package %q cannot be both installed and purged in one step", name)
		}
	}

	if err := ValidateNames(nameRe, installList); err != nil {
		return err
	}
	return ValidateNames(nameRe, purgeList)
}

// ValidatePurgeCollateral keeps purge_also_removes an acknowledgement of what
// the purge transaction drags out, not a second list of package operations.
func ValidatePurgeCollateral(installList, purgeList, collateralList []string) error {
	install := make(map[string]struct{}, len(installList))
	for _, raw := range installList {
		install[strings.TrimSpace(raw)] = struct{}{}
	}
	purge := make(map[string]struct{}, len(purgeList))
	for _, raw := range purgeList {
		purge[strings.TrimSpace(raw)] = struct{}{}
	}

	seen := make(map[string]struct{}, len(collateralList))
	for _, raw := range collateralList {
		name := strings.TrimSpace(raw)
		if name == "" {
			return fmt.Errorf("packages purge_also_removes entries must not be empty")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("package %q is duplicated in purge_also_removes list", name)
		}
		seen[name] = struct{}{}
		if _, exists := install[name]; exists {
			return fmt.Errorf("package %q cannot be both installed and acknowledged as purge collateral in one step", name)
		}
		if _, exists := purge[name]; exists {
			return fmt.Errorf("package %q is already explicitly purged and must not also appear in purge_also_removes", name)
		}
	}
	return nil
}
