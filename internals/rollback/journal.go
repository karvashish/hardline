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
	journalVersion = 1

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

type StepRecord = pluginapi.StepRecord
type ObjectRecord = pluginapi.ObjectRecord
type FileSnapshot = pluginapi.FileSnapshot
type ServiceState = pluginapi.ServiceState
type PackageState = pluginapi.PackageState

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

func (j *Journal) SaveLast() error {
	if j == nil {
		return fmt.Errorf("journal is nil")
	}

	root, err := resolveStateDir()
	if err != nil {
		return err
	}

	hostKey := sanitizeHostPath(j.Host)
	if hostKey == "" {
		return fmt.Errorf("journal host is empty")
	}

	dir := filepath.Join(root, hostKey)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create rollback state dir %q: %w", dir, err)
	}

	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rollback journal: %w", err)
	}
	data = append(data, '\n')

	tmpPath := filepath.Join(dir, "last.json.tmp")
	lastPath := filepath.Join(dir, "last.json")

	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write rollback state %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, lastPath); err != nil {
		return fmt.Errorf("persist rollback state %q: %w", lastPath, err)
	}

	return nil
}

func LoadLast(host string) (*Journal, error) {
	root, err := resolveStateDir()
	if err != nil {
		return nil, err
	}

	hostKey := sanitizeHostPath(host)
	if hostKey == "" {
		return nil, fmt.Errorf("host is required")
	}

	path := filepath.Join(root, hostKey, "last.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rollback state %q: %w", path, err)
	}

	var j Journal
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("decode rollback state %q: %w", path, err)
	}

	if j.Version != journalVersion {
		return nil, fmt.Errorf("unsupported rollback state version %d", j.Version)
	}
	return &j, nil
}

func defaultStateDir() (string, error) {
	if p := strings.TrimSpace(os.Getenv("HARDLINE_STATE_DIR")); p != "" {
		return p, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory for rollback state: %w", err)
	}
	return filepath.Join(wd, ".hardline", "runs"), nil
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
