package pluginapi

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/karvashish/hardline/pkg/profile"
)

const (
	ModeDeterministic = "deterministic"
	ModeBestEffort    = "best_effort"
	ModeNoop          = "noop"

	ObjectFile     = "file"
	ObjectFileMeta = "file_meta"
	ObjectService  = "service"
	ObjectPackage  = "package"
	ObjectValidate = "validate"
)

type FileSnapshot struct {
	Path       string `json:"path"`
	Existed    bool   `json:"existed"`
	Mode       string `json:"mode,omitempty"`
	ContentB64 string `json:"content_b64,omitempty"`
}

// FileMetaSnapshot records path metadata for file-meta rollback; unlike
// FileSnapshot it carries no file content.
type FileMetaSnapshot struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Mode    string `json:"mode,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	Attrs   string `json:"attrs,omitempty"`
}

type ServiceState struct {
	Unit    string `json:"unit"`
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
	Known   bool   `json:"known"`
}

// ServiceReload is step-level service intent (not observed state) the rollback consults to re-run the action.
type ServiceReload struct {
	Action        string   `json:"action,omitempty"`
	RestartPolicy string   `json:"restart_policy,omitempty"`
	RestartDeps   []string `json:"restart_deps,omitempty"`
}

type PackageState struct {
	Name             string `json:"name"`
	WasInstalled     bool   `json:"was_installed"`
	Version          string `json:"version,omitempty"`
	RequestedInstall bool   `json:"requested_install,omitempty"`
	RequestedPurge   bool   `json:"requested_purge,omitempty"`
}

type ObjectRecord struct {
	Kind     string            `json:"kind"`
	File     *FileSnapshot     `json:"file,omitempty"`
	FileMeta *FileMetaSnapshot `json:"file_meta,omitempty"`
	Service  *ServiceState     `json:"service,omitempty"`
	Package  *PackageState     `json:"package,omitempty"`
	Message  string            `json:"message,omitempty"`
}

type CaptureResult struct {
	RollbackMode string         `json:"rollback_mode"`
	Objects      []ObjectRecord `json:"objects"`
	Notes        []string       `json:"notes,omitempty"`
	Reload       *ServiceReload `json:"reload,omitempty"`
}

type FirewallRuleInfo struct {
	Family string
	Table  string
	Chain  string
	Proto  string
	Port   int
	Iif    string
	Oif    string
}

type Host interface {
	RunRoot(cmd string) error
	RunRootWithOutput(cmd string) (string, error)
	RunRootWithTimeout(cmd string, timeout time.Duration) (string, error)
	Stat(path string) (os.FileInfo, error)
	ReadRootFile(path string) (string, error)
	WriteRootFile(path string, data []byte, mode os.FileMode) error
}

type Context struct {
	Host      Host
	Profile   *profile.Profile
	Overrides map[string]json.RawMessage
	// StepChanges maps step IDs to whether the step caused (or will cause) a
	// state change. In plan mode, this reflects the plugin's prediction
	// (WillChange from PlanResult). In apply mode, this reflects the actual
	// outcome measured by comparing before/after captures via CapturesDiffer.
	// Service restart policies with type=on_change consult this map to decide
	// whether to restart.
	StepChanges map[string]bool
}

type PlanResult struct {
	Summary         string
	Details         []string
	Diff            []string
	WillChange      bool
	OperatorSummary string
	Highlights      []string
}

type Plugin struct {
	Name               string
	InternalValidation bool
	Apply              func(Context, profile.Step) error
	Plan               func(Context, profile.Step) (PlanResult, error)
	Capture            func(Context, profile.Step) (CaptureResult, error)
	Rollback           func(Host, ObjectRecord) error
	DetectConflict     func(Host, ObjectRecord) []string
}

type Registry struct {
	plugins []Plugin
}

func NewRegistry() *Registry {
	return &Registry{}
}

func normalizePluginName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func preparePlugin(p Plugin) (Plugin, error) {
	name := normalizePluginName(p.Name)
	if name == "" {
		return Plugin{}, fmt.Errorf("plugin name is required")
	}
	if p.Apply == nil {
		return Plugin{}, fmt.Errorf("plugin %q is missing Apply func", name)
	}
	if p.Plan == nil {
		return Plugin{}, fmt.Errorf("plugin %q is missing Plan func", name)
	}
	if p.Capture == nil {
		return Plugin{}, fmt.Errorf("plugin %q is missing Capture func", name)
	}
	if p.Rollback == nil {
		return Plugin{}, fmt.Errorf("plugin %q is missing Rollback func", name)
	}
	if p.DetectConflict == nil {
		return Plugin{}, fmt.Errorf("plugin %q is missing DetectConflict func", name)
	}

	p.Name = name
	return p, nil
}

func (r *Registry) Register(p Plugin) error {
	if r == nil {
		return fmt.Errorf("plugin registry is nil")
	}

	prepared, err := preparePlugin(p)
	if err != nil {
		return err
	}

	for _, existing := range r.plugins {
		if existing.Name == prepared.Name {
			return fmt.Errorf("plugin already registered for name %q", prepared.Name)
		}
	}

	r.plugins = append(r.plugins, prepared)
	return nil
}

func (r *Registry) Lookup(name string) (Plugin, bool) {
	if r == nil {
		return Plugin{}, false
	}

	needle := normalizePluginName(name)
	for _, plugin := range r.plugins {
		if plugin.Name == needle {
			return plugin, true
		}
	}
	return Plugin{}, false
}

func RequireStepPlugin(r *Registry, step profile.Step) (Plugin, error) {
	name := step.PluginName()
	if name == "" {
		return Plugin{}, fmt.Errorf("step %q: plugin is required", step.ID)
	}

	plugin, ok := r.Lookup(name)
	if !ok {
		return Plugin{}, fmt.Errorf("step %q: required plugin %q is not registered", step.ID, name)
	}

	return plugin, nil
}

func EnsureProfilePlugins(r *Registry, p *profile.Profile) error {
	if p == nil {
		return fmt.Errorf("profile is nil")
	}

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			if _, err := RequireStepPlugin(r, step); err != nil {
				return err
			}
		}
	}

	return nil
}

func NoopCapture(_ profile.Step, message string) CaptureResult {
	return CaptureResult{
		RollbackMode: ModeNoop,
		Objects: []ObjectRecord{
			{
				Kind:    ObjectValidate,
				Message: message,
			},
		},
	}
}

func EnsureValidationPolicy(step profile.Step, plugin Plugin) error {
	if plugin.InternalValidation || step.AllowUnvalidated {
		return nil
	}
	return fmt.Errorf(
		"step %q (%s): plugin %q does not internally validate; set allow_unvalidated=true to acknowledge it",
		step.ID,
		step.PluginName(),
		plugin.Name,
	)
}
