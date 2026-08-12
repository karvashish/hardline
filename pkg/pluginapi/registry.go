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
	// ModeIrreversible is plan vocabulary only: it describes work no journal
	// can undo, such as a package index refresh, so it never names a capture's
	// rollback mode.
	ModeIrreversible = "irreversible"

	ObjectFile       = "file"
	ObjectFileMeta   = "file_meta"
	ObjectService    = "service"
	ObjectPackage    = "package"
	ObjectValidate   = "validate"
	ObjectConfigLine = "config_line"
)

// FileSnapshot is the recorded state of a managed file. Owner and group are
// carried alongside content because restoring the right bytes under the wrong
// ownership is not a restoration, and a change of ownership alone is still a
// change to the host.
type FileSnapshot struct {
	Path       string `json:"path"`
	Existed    bool   `json:"existed"`
	Mode       string `json:"mode,omitempty"`
	Owner      string `json:"owner"`
	Group      string `json:"group"`
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

// ServiceState is the recorded state of a systemd unit. Enabled and Active are
// the booleans rollback acts on; EnabledState and ActiveState carry what
// systemctl actually reported, because "not enabled" covers disabled, masked,
// static, indirect and generated, and restoring those as a plain "disable" is
// not the same unit configuration the host had.
type ServiceState struct {
	Unit         string `json:"unit"`
	Enabled      bool   `json:"enabled"`
	Active       bool   `json:"active"`
	EnabledState string `json:"enabled_state"`
	ActiveState  string `json:"active_state"`
	Known        bool   `json:"known"`
}

// ServiceReload is step-level service intent (not observed state) the rollback consults to re-run the action.
type ServiceReload struct {
	Action        string   `json:"action,omitempty"`
	RestartPolicy string   `json:"restart_policy,omitempty"`
	RestartDeps   []string `json:"restart_deps,omitempty"`
}

type PackageState struct {
	Name         string `json:"name"`
	WasInstalled bool   `json:"was_installed"`
	// Version is the human-readable version, used for display and for detecting
	// a change since apply. PinSpec is the same state in the capturing
	// backend's own exact-install syntax, which is the only form that restores
	// a specific version: apt wants name=version, rpm a full NEVRA. The plugin
	// that wrote the record is identified by the journalled step type, so
	// neither field has to name a backend.
	Version          string `json:"version"`
	PinSpec          string `json:"pin_spec"`
	RequestedInstall bool   `json:"requested_install,omitempty"`
	RequestedPurge   bool   `json:"requested_purge,omitempty"`
}

// ConfigLineSnapshot records a single line this run added to a file it does not
// own. Restoring such a file wholesale is wrong once more than one profile
// writes to it: the later profile's line would be erased by the earlier
// profile's rollback. Undoing exactly the line that was added leaves every
// other owner's lines in place.
type ConfigLineSnapshot struct {
	Path string `json:"path"`
	Line string `json:"line"`
	// FileExisted distinguishes "we appended to someone's file" from "we
	// created the file", which rollback undoes by deleting it.
	FileExisted bool `json:"file_existed"`
	// Added is false when the line was already there, which makes the rollback
	// a no-op rather than a removal of something this run did not do.
	Added bool `json:"added"`
}

type ObjectRecord struct {
	Kind       string              `json:"kind"`
	File       *FileSnapshot       `json:"file,omitempty"`
	FileMeta   *FileMetaSnapshot   `json:"file_meta,omitempty"`
	Service    *ServiceState       `json:"service,omitempty"`
	Package    *PackageState       `json:"package,omitempty"`
	ConfigLine *ConfigLineSnapshot `json:"config_line,omitempty"`
	Message    string              `json:"message,omitempty"`
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
	// RollbackFidelity is what a rollback of this step would actually restore:
	// ModeDeterministic, ModeBestEffort or ModeIrreversible. A plan that
	// announces rollback as available for a package upgrade or an index refresh
	// promises something no rollback can deliver, so a step that will change
	// state has to say which of the three it is.
	RollbackFidelity string
}

type Plugin struct {
	Name               string
	InternalValidation bool
	// Validate decodes and checks a step without touching a host, so a typo in
	// a signed profile fails at verify rather than partway through an apply
	// that has already changed the machine. It gets the same resolved
	// overrides the run will use, because a step is only as valid as the
	// values it will actually run with. A plugin that claims
	// InternalValidation must supply it; the checks it runs are the same ones
	// Apply, Plan and Capture run.
	Validate       func(profile.Step, map[string]json.RawMessage) error
	Apply          func(Context, profile.Step) error
	Plan           func(Context, profile.Step) (PlanResult, error)
	Capture        func(Context, profile.Step) (CaptureResult, error)
	Rollback       func(Host, ObjectRecord) error
	DetectConflict func(Host, ObjectRecord) []string
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
	if p.InternalValidation && p.Validate == nil {
		return Plugin{}, fmt.Errorf("plugin %q claims internal validation but is missing Validate func", name)
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

// ValidateProfileSteps is the verify-time pass over every step: the plugin has
// to exist, the step has to satisfy the validation policy, and the plugin's own
// decoder has to accept the config. Schema validation alone leaves the semantic
// rules - a dest augenrules never compiles, a mode nothing can parse - to be
// discovered on the host, mid-apply.
func ValidateProfileSteps(r *Registry, p *profile.Profile, overrides map[string]json.RawMessage) error {
	if p == nil {
		return fmt.Errorf("profile is nil")
	}

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			plugin, err := RequireStepPlugin(r, step)
			if err != nil {
				return err
			}
			if err := EnsureValidationPolicy(step, plugin); err != nil {
				return err
			}
			if plugin.Validate == nil {
				continue
			}
			if err := plugin.Validate(step, overrides); err != nil {
				return fmt.Errorf("step %q (%s): %w", step.ID, step.PluginName(), err)
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
