package rollback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	journalVersion = 3
)

type Journal struct {
	Version     int          `json:"version"`
	RunID       string       `json:"run_id"`
	CreatedAt   string       `json:"created_at"`
	Host        string       `json:"host"`
	ProfileID   string       `json:"profile_id"`
	ProfilePath string       `json:"profile_path"`
	Status      string       `json:"status"`
	Steps       []StepRecord `json:"steps"`
	Checksum    string       `json:"checksum,omitempty"`
}

type StepRecord struct {
	ID           string                   `json:"id"`
	Type         string                   `json:"type"`
	RollbackMode string                   `json:"rollback_mode"`
	Before       []pluginapi.ObjectRecord `json:"before,omitempty"`
	After        []pluginapi.ObjectRecord `json:"after,omitempty"`
	Notes        []string                 `json:"notes,omitempty"`
	Reload       *pluginapi.ServiceReload `json:"reload,omitempty"`
}

var (
	nowUTC          = time.Now
	resolveStateDir = defaultStateDir
)

func NewJournal(host, profileID, profilePath string) *Journal {
	ts := nowUTC().UTC()
	return &Journal{
		Version:     journalVersion,
		RunID:       ts.Format("20060102T150405.000000000Z"),
		CreatedAt:   ts.Format(time.RFC3339Nano),
		Host:        strings.TrimSpace(host),
		ProfileID:   strings.TrimSpace(profileID),
		ProfilePath: strings.TrimSpace(profilePath),
		Status:      "in_progress",
		Steps:       nil,
	}
}

func NewStepRecordFromCapture(stepID, stepType string, capture pluginapi.CaptureResult) StepRecord {
	return StepRecord{
		ID:           stepID,
		Type:         stepType,
		RollbackMode: capture.RollbackMode,
		Before:       cloneObjectRecords(capture.Objects),
		Notes:        append([]string(nil), capture.Notes...),
		Reload:       cloneServiceReload(capture.Reload),
	}
}

func cloneServiceReload(r *pluginapi.ServiceReload) *pluginapi.ServiceReload {
	if r == nil {
		return nil
	}
	clone := *r
	clone.RestartDeps = append([]string(nil), r.RestartDeps...)
	return &clone
}

func (s *StepRecord) SetAfterFromCapture(capture pluginapi.CaptureResult) {
	if s == nil {
		return
	}
	s.After = cloneObjectRecords(capture.Objects)
}

func (j *Journal) SaveLast() error {
	if j == nil {
		return fmt.Errorf("journal is nil")
	}

	dir, lastPath, tmpPath, err := localLastPaths(j.Host, j.ProfileID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create rollback state dir %q: %w", dir, err)
	}

	data, err := marshalJournal(j)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write rollback state %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, lastPath); err != nil {
		return fmt.Errorf("persist rollback state %q: %w", lastPath, err)
	}

	return nil
}

func (j *Journal) RemoveLast() error {
	if j == nil {
		return fmt.Errorf("journal is nil")
	}

	dir, lastPath, _, err := localLastPaths(j.Host, j.ProfileID)
	if err != nil {
		return err
	}

	if err := os.Remove(lastPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove rollback state %q: %w", lastPath, err)
	}
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {

		if !strings.Contains(err.Error(), "directory not empty") && !strings.Contains(err.Error(), "not empty") {
			return fmt.Errorf("remove rollback state dir %q: %w", dir, err)
		}
	}
	return nil
}

func LoadLast(host, profileID string) (*Journal, error) {
	_, path, _, err := localLastPaths(host, profileID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rollback state %q: %w", path, err)
	}
	return decodeJournal(data, path)
}

func defaultStateDir() (string, error) {
	if p := strings.TrimSpace(os.Getenv("HARDLINE_STATE_DIR")); p != "" {
		return p, nil
	}
	return filepath.Join(os.TempDir(), "hardline", "runs"), nil
}

func sanitizePath(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	out := []byte(s)
	for i := 0; i < len(out); i++ {
		c := out[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-':
		default:
			out[i] = '_'
		}
	}
	if strings.Trim(string(out), ".") == "" {
		return ""
	}
	return string(out)
}

func localLastPaths(host, profileID string) (string, string, string, error) {
	root, err := resolveStateDir()
	if err != nil {
		return "", "", "", err
	}

	hostKey := sanitizePath(host)
	if hostKey == "" {
		return "", "", "", fmt.Errorf("host is required")
	}

	profileKey := sanitizePath(profileID)
	if profileKey == "" {
		return "", "", "", fmt.Errorf("profile ID is required")
	}

	dir := filepath.Join(root, hostKey)
	lastPath := filepath.Join(dir, profileKey+".json")
	tmpPath := filepath.Join(dir, profileKey+".json.tmp")
	return dir, lastPath, tmpPath, nil
}

func marshalJournal(j *Journal) ([]byte, error) {
	tmp := *j
	tmp.Checksum = ""
	bare, err := json.MarshalIndent(&tmp, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal rollback journal: %w", err)
	}
	sum := sha256.Sum256(bare)
	tmp.Checksum = hex.EncodeToString(sum[:])
	data, err := json.MarshalIndent(&tmp, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal rollback journal: %w", err)
	}
	return append(data, '\n'), nil
}

func decodeJournal(data []byte, source string) (*Journal, error) {
	var j Journal
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("decode rollback state %q: %w", source, err)
	}

	if j.Version != journalVersion {
		return nil, fmt.Errorf(
			"unsupported rollback state version %d (this hardline writes and reads version %d); a journal from an older hardline cannot be replayed safely, roll back with the version that wrote it or discard it",
			j.Version, journalVersion)
	}

	if j.Checksum == "" {
		return nil, fmt.Errorf("rollback journal %q carries no checksum: refusing to trust it", source)
	}

	saved := j.Checksum
	j.Checksum = ""
	clean, err := json.MarshalIndent(&j, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("verify rollback journal checksum: %w", err)
	}
	sum := sha256.Sum256(clean)
	if hex.EncodeToString(sum[:]) != saved {
		return nil, fmt.Errorf("rollback journal %q checksum mismatch: file may be corrupted", source)
	}
	j.Checksum = saved

	return &j, nil
}

func cloneObjectRecords(records []pluginapi.ObjectRecord) []pluginapi.ObjectRecord {
	if len(records) == 0 {
		return nil
	}

	cloned := make([]pluginapi.ObjectRecord, len(records))
	for i, record := range records {
		cloned[i] = record
		if record.File != nil {
			file := *record.File
			cloned[i].File = &file
		}
		if record.FileMeta != nil {
			fileMeta := *record.FileMeta
			cloned[i].FileMeta = &fileMeta
		}
		if record.Service != nil {
			service := *record.Service
			cloned[i].Service = &service
		}
		if record.Package != nil {
			pkg := *record.Package
			cloned[i].Package = &pkg
		}
		if record.ConfigLine != nil {
			line := *record.ConfigLine
			cloned[i].ConfigLine = &line
		}
		if record.RuntimePolicy != nil {
			policy := *record.RuntimePolicy
			cloned[i].RuntimePolicy = &policy
		}
	}
	return cloned
}
