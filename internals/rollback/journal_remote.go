package rollback

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

var (
	resolveRemoteStatePath  = defaultRemoteStatePath
	runRemoteRoot           = (*remote.Client).RunRoot
	runRemoteRootWithOutput = (*remote.Client).RunRootWithOutput
	readRemoteRootFile      = (*remote.Client).ReadRootFile
	writeRemoteRootFile     = (*remote.Client).WriteRootFile
)

// SaveRemoteLast writes a timestamped journal under /var/lib/hardline/runs/<profileID>/<runID>.json.
// Each apply gets its own file; they stack up and rollback pops the most recent.
func SaveRemoteLast(client *remote.Client, j *Journal) error {
	if j == nil {
		return fmt.Errorf("journal is nil")
	}

	remotePath := strings.TrimSpace(resolveRemoteStatePath(j.ProfileID, j.RunID))
	if remotePath == "" {
		return fmt.Errorf("remote rollback state path is empty")
	}

	dir := path.Dir(remotePath)
	if dir != "" && dir != "." {
		if err := runRemoteRoot(client, "mkdir -p "+pluginapi.ShellArg(dir)); err != nil {
			return fmt.Errorf("create remote rollback state dir %q: %w", dir, err)
		}
	}

	data, err := marshalJournal(j)
	if err != nil {
		return err
	}

	if err := writeRemoteRootFile(client, remotePath, data, 0o600); err != nil {
		return fmt.Errorf("persist remote rollback state %q: %w", remotePath, err)
	}
	return nil
}

// journalFileNamePattern is the exact shape SaveRemoteLast writes: a RunID
// timestamp plus ".json". The directory is root-owned but is still a directory
// on a host hardline does not otherwise control, and the name selected here is
// read back as the instruction set for a root-level restore. Anything that does
// not match is not a journal this hardline wrote.
var journalFileNamePattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z\.json$`)

// LoadRemoteLast finds the most recent journal for the profile. RunIDs are
// zero-padded timestamps, so the lexicographically last well-formed name is
// also the newest.
func LoadRemoteLast(client *remote.Client, profileID string) (*Journal, error) {
	dir := path.Dir(resolveRemoteStatePath(profileID, "x"))

	output, err := runRemoteRootWithOutput(client, "ls -1 "+pluginapi.ShellArg(dir)+" 2>/dev/null || true")
	if err != nil {
		return nil, fmt.Errorf("list remote journals for %q: %w", profileID, err)
	}

	filename := ""
	for _, line := range strings.Split(output, "\n") {
		name := strings.TrimSpace(line)
		if !journalFileNamePattern.MatchString(name) {
			continue
		}
		if name > filename {
			filename = name
		}
	}
	if filename == "" {
		return nil, fmt.Errorf("no journal found for profile %q", profileID)
	}

	remotePath := path.Join(dir, filename)
	data, err := readRemoteRootFile(client, remotePath)
	if err != nil {
		return nil, fmt.Errorf("read remote rollback state %q: %w", remotePath, err)
	}

	journal, err := decodeJournal([]byte(data), remotePath)
	if err != nil {
		return nil, err
	}
	// The filename is derived from the RunID, so a journal whose body names a
	// different run has been moved or rewritten.
	if journal.RunID+".json" != filename {
		return nil, fmt.Errorf("remote journal %q records run %q; the file has been renamed", remotePath, journal.RunID)
	}
	return journal, nil
}

// DeleteRemoteJournal removes the specific timestamped journal after a successful rollback,
// so the next rollback targets the previous apply.
func DeleteRemoteJournal(client *remote.Client, profileID, runID string) error {
	remotePath := strings.TrimSpace(resolveRemoteStatePath(profileID, runID))
	if remotePath == "" {
		return fmt.Errorf("remote rollback state path is empty")
	}
	if err := runRemoteRoot(client, "rm -f "+pluginapi.ShellArg(remotePath)); err != nil {
		return fmt.Errorf("delete remote journal %q: %w", remotePath, err)
	}
	return nil
}

func defaultRemoteStatePath(profileID, runID string) string {
	profileKey := sanitizePath(profileID)
	if profileKey == "" {
		profileKey = "unknown"
	}
	runKey := sanitizePath(runID)
	if runKey == "" {
		runKey = "unknown"
	}
	return "/var/lib/hardline/runs/" + profileKey + "/" + runKey + ".json"
}
