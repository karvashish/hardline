package pluginapi

import (
	"fmt"
	"os"
	"strings"

	"github.com/karvashish/hardline/pkg/profile"
)

const (
	ModeDeterministic = "deterministic"
	ModeBestEffort    = "best_effort"
	ModeNoop          = "noop"

	ObjectFile     = "file"
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

type ServiceState struct {
	Unit    string `json:"unit"`
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
	Known   bool   `json:"known"`
}

type PackageState struct {
	Name             string `json:"name"`
	WasInstalled     bool   `json:"was_installed"`
	Version          string `json:"version,omitempty"`
	RequestedInstall bool   `json:"requested_install,omitempty"`
	RequestedPurge   bool   `json:"requested_purge,omitempty"`
}

type ObjectRecord struct {
	Kind    string        `json:"kind"`
	File    *FileSnapshot `json:"file,omitempty"`
	Service *ServiceState `json:"service,omitempty"`
	Package *PackageState `json:"package,omitempty"`
	Message string        `json:"message,omitempty"`
}

type StepRecord struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	RollbackMode string         `json:"rollback_mode"`
	Objects      []ObjectRecord `json:"objects"`
	Notes        []string       `json:"notes,omitempty"`
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
	Stat(path string) (os.FileInfo, error)
	ReadRootFile(path string) (string, error)
	WriteRootFile(path string, data []byte, mode os.FileMode) error
}

type Context struct {
	Host    Host
	Profile *profile.Profile
}

type ApplyContext = Context
type PlanContext = Context
type CaptureContext = Context

type PlanResult struct {
	Summary string
	Details []string
	Noop    int
}

type Plugin struct {
	Name               string
	InternalValidation bool
	Apply              func(ApplyContext, profile.Step) error
	Plan               func(PlanContext, profile.Step) (PlanResult, error)
	Capture            func(CaptureContext, profile.Step) (StepRecord, error)
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

func NoopRecord(step profile.Step, message string) StepRecord {
	return StepRecord{
		ID:           step.ID,
		Type:         step.PluginName(),
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
