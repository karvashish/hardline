package packages

import (
	"fmt"
	"regexp"
	"strings"
)

func ValidateNames(nameRe *regexp.Regexp, names []string) error {
	for _, name := range names {
		if !nameRe.MatchString(name) {
			return fmt.Errorf("invalid package name %q: must match %s", name, nameRe.String())
		}
	}
	return nil
}

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
