package rollback

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/remote"
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
		if err := runRemoteRoot(client, "mkdir -p "+strconv.Quote(dir)); err != nil {
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

// LoadRemoteLast finds the most recent journal for the profile by listing the remote directory
// and reading the lexicographically last filename (RunIDs are timestamp-based, so sort order = time order).
func LoadRemoteLast(client *remote.Client, profileID string) (*Journal, error) {
	dir := path.Dir(resolveRemoteStatePath(profileID, "x"))

	output, err := runRemoteRootWithOutput(client, "ls -1 "+strconv.Quote(dir)+" 2>/dev/null | sort | tail -1")
	if err != nil {
		return nil, fmt.Errorf("list remote journals for %q: %w", profileID, err)
	}

	filename := strings.TrimSpace(output)
	if filename == "" {
		return nil, fmt.Errorf("no journal found for profile %q", profileID)
	}

	remotePath := path.Join(dir, filename)
	data, err := readRemoteRootFile(client, remotePath)
	if err != nil {
		return nil, fmt.Errorf("read remote rollback state %q: %w", remotePath, err)
	}
	return decodeJournal([]byte(data), remotePath)
}

// DeleteRemoteJournal removes the specific timestamped journal after a successful rollback,
// so the next rollback targets the previous apply.
func DeleteRemoteJournal(client *remote.Client, profileID, runID string) error {
	remotePath := strings.TrimSpace(resolveRemoteStatePath(profileID, runID))
	if remotePath == "" {
		return fmt.Errorf("remote rollback state path is empty")
	}
	if err := runRemoteRoot(client, "rm -f "+strconv.Quote(remotePath)); err != nil {
		return fmt.Errorf("delete remote journal %q: %w", remotePath, err)
	}
	return nil
}

func defaultRemoteStatePath(profileID, runID string) string {
	profileKey := sanitizePath(profileID)
	if profileKey == "" {
		profileKey = "unknown"
	}
	return "/var/lib/hardline/runs/" + profileKey + "/" + runID + ".json"
}
