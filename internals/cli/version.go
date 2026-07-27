package cli

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type versionInfo struct {
	Version       string `json:"version"`
	ProfileSchema int    `json:"profile_schema"`
}

type SemVer struct {
	Major int
	Minor int
	Patch int
	Pre   string
}

//go:embed version.json
var versionJSON []byte

func VersionCmd() (SemVer, int, error) {
	if len(versionJSON) == 0 {
		return SemVer{}, 0, fmt.Errorf("embedded version.json is empty")
	}

	var info versionInfo
	if err := json.Unmarshal(versionJSON, &info); err != nil || info.Version == "" {
		if err == nil {
			err = fmt.Errorf("empty or invalid version field in embedded version.json")
		}
		return SemVer{}, 0, err
	}

	sem, err := ParseSemVer(info.Version)
	if err != nil {
		return SemVer{}, 0, fmt.Errorf("invalid semver %q in embedded version.json: %w", info.Version, err)
	}

	return sem, info.ProfileSchema, nil
}

func ParseSemVer(s string) (SemVer, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")

	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return SemVer{}, fmt.Errorf("invalid semver %q: expected MAJOR.MINOR.PATCH", s)
	}

	pre := ""
	if i := strings.IndexByte(parts[2], '-'); i >= 0 {
		pre = parts[2][i+1:]
		parts[2] = parts[2][:i]
		if !validPrerelease(pre) {
			return SemVer{}, fmt.Errorf("invalid prerelease in %q: expected [a-zA-Z0-9.]+", s)
		}
	}

	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid major in %q: %w", s, err)
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid minor in %q: %w", s, err)
	}
	pat, err := strconv.Atoi(parts[2])
	if err != nil {
		return SemVer{}, fmt.Errorf("invalid patch in %q: %w", s, err)
	}

	return SemVer{
		Major: maj,
		Minor: min,
		Patch: pat,
		Pre:   pre,
	}, nil
}

func validPrerelease(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.':
		default:
			return false
		}
	}
	return true
}

// prerelease is ignored: an rc satisfies the same min_hardline as its final release.
func CompareSemVer(a, b string) (int, error) {
	va, err := ParseSemVer(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseSemVer(b)
	if err != nil {
		return 0, err
	}

	if va.Major != vb.Major {
		if va.Major < vb.Major {
			return -1, nil
		}
		return 1, nil
	}
	if va.Minor != vb.Minor {
		if va.Minor < vb.Minor {
			return -1, nil
		}
		return 1, nil
	}
	if va.Patch != vb.Patch {
		if va.Patch < vb.Patch {
			return -1, nil
		}
		return 1, nil
	}
	return 0, nil
}

func (v SemVer) String() string {
	if v.Pre != "" {
		return fmt.Sprintf("%d.%d.%d-%s", v.Major, v.Minor, v.Patch, v.Pre)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
