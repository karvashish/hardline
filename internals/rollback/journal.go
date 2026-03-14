package rollback

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	journalVersion = 2

	ModeDeterministic = pluginapi.ModeDeterministic
	ModeBestEffort    = pluginapi.ModeBestEffort
	ModeNoop          = pluginapi.ModeNoop

	ObjectFile     = pluginapi.ObjectFile
	ObjectService  = pluginapi.ObjectService
	ObjectPackage  = pluginapi.ObjectPackage
	ObjectValidate = pluginapi.ObjectValidate
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
}

type ObjectRecord = pluginapi.ObjectRecord
type FileSnapshot = pluginapi.FileSnapshot
type ServiceState = pluginapi.ServiceState
type PackageState = pluginapi.PackageState

type StepRecord struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	RollbackMode string         `json:"rollback_mode"`
	Before       []ObjectRecord `json:"before,omitempty"`
	After        []ObjectRecord `json:"after,omitempty"`
	Notes        []string       `json:"notes,omitempty"`
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
	}
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

	dir, lastPath, tmpPath, err := localLastPaths(j.Host)
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

	dir, lastPath, _, err := localLastPaths(j.Host)
	if err != nil {
		return err
	}

	if err := os.Remove(lastPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove rollback state %q: %w", lastPath, err)
	}
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		// Ignore non-empty host directories; only prune empty leftovers.
		if !strings.Contains(err.Error(), "directory not empty") && !strings.Contains(err.Error(), "not empty") {
			return fmt.Errorf("remove rollback state dir %q: %w", dir, err)
		}
	}
	return nil
}

func LoadLast(host string) (*Journal, error) {
	_, path, _, err := localLastPaths(host)
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

func sanitizeHostPath(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}

	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		" ", "_",
		"\t", "_",
		"\n", "_",
	)
	return replacer.Replace(h)
}

func localLastPaths(host string) (string, string, string, error) {
	root, err := resolveStateDir()
	if err != nil {
		return "", "", "", err
	}

	hostKey := sanitizeHostPath(host)
	if hostKey == "" {
		return "", "", "", fmt.Errorf("host is required")
	}

	dir := filepath.Join(root, hostKey)
	lastPath := filepath.Join(dir, "last.json")
	tmpPath := filepath.Join(dir, "last.json.tmp")
	return dir, lastPath, tmpPath, nil
}

func marshalJournal(j *Journal) ([]byte, error) {
	data, err := json.MarshalIndent(j, "", "  ")
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
		return nil, fmt.Errorf("unsupported rollback state version %d", j.Version)
	}
	return &j, nil
}

func cloneObjectRecords(records []ObjectRecord) []ObjectRecord {
	if len(records) == 0 {
		return nil
	}

	cloned := make([]ObjectRecord, len(records))
	for i, record := range records {
		cloned[i] = record
		if record.File != nil {
			file := *record.File
			cloned[i].File = &file
		}
		if record.Service != nil {
			service := *record.Service
			cloned[i].Service = &service
		}
		if record.Package != nil {
			pkg := *record.Package
			cloned[i].Package = &pkg
		}
	}
	return cloned
}
