package pluginapi

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
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

type PlanInspector interface {
	PackageInstalled(name string) bool
	AptAutoremovePreview() ([]string, error)
	AptUpgradePreview() ([]string, error)
	AptInstallPreview(pkgs []string) ([]string, error)

	Stat(path string) (os.FileInfo, error)
	ReadRootFile(path string) (string, error)

	IsServiceEnabled(unit string) bool
	IsServiceActive(unit string) bool

	SSHIncludePresent() bool
	SSHConfigTest() error

	FirewallIncludePresent() bool
	FirewallConfigTest() error
	FirewallAllowedPorts() (map[string][]int, error)
	FirewallPolicySummary() ([]string, error)
	FirewallOtherManagers() ([]string, error)
	FirewallOnDiskPolicySummary(confPath string) ([]string, error)
	FirewallHasStatefulBaseline() (bool, error)
	FirewallHasDefaultDropInput() (bool, error)
	FirewallAllowedPortsDetailed() ([]FirewallRuleInfo, error)
}

type ApplyContext struct {
	Client  *ssh.Client
	Profile *profile.Profile
}

type PlanContext struct {
	Inspector PlanInspector
	Profile   *profile.Profile
}

type RollbackContext struct {
	Client  *ssh.Client
	Profile *profile.Profile
}

type PlanResult struct {
	Summary string
	Details []string
	Noop    int
}

type ApplyHandler struct {
	Type          string
	Apply         func(ApplyContext, profile.Step) error
	ValidateKinds map[string]func(ApplyContext) error
}

type PlanHandler struct {
	Type          string
	Plan          func(PlanContext, profile.Step) (PlanResult, error)
	ValidateKinds map[string]func(PlanContext) (PlanResult, error)
}

type RollbackHandler struct {
	Type    string
	Capture func(RollbackContext, profile.Step) (StepRecord, error)
}

type PluginBundle struct {
	Name             string
	ApplyHandlers    []ApplyHandler
	PlanHandlers     []PlanHandler
	RollbackHandlers []RollbackHandler
}

type Registry struct {
	mu sync.RWMutex

	applyByType     map[string]ApplyHandler
	applyByValidate map[string]func(ApplyContext) error

	planByType     map[string]PlanHandler
	planByValidate map[string]func(PlanContext) (PlanResult, error)

	rollbackByType map[string]RollbackHandler
}

func NewRegistry() *Registry {
	return &Registry{
		applyByType:     make(map[string]ApplyHandler),
		applyByValidate: make(map[string]func(ApplyContext) error),
		planByType:      make(map[string]PlanHandler),
		planByValidate:  make(map[string]func(PlanContext) (PlanResult, error)),
		rollbackByType:  make(map[string]RollbackHandler),
	}
}

func normalizeType(t string) string {
	return strings.ToLower(strings.TrimSpace(t))
}

func normalizeApplyValidateKinds(typ string, in map[string]func(ApplyContext) error) (map[string]func(ApplyContext) error, error) {
	out := make(map[string]func(ApplyContext) error, len(in))
	for kind, fn := range in {
		k := normalizeType(kind)
		if k == "" {
			return nil, fmt.Errorf("apply validate kind cannot be empty for type %q", typ)
		}
		if fn == nil {
			return nil, fmt.Errorf("apply validate kind %q has nil func", k)
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("apply validate kind %q already registered", k)
		}
		out[k] = fn
	}
	return out, nil
}

func normalizePlanValidateKinds(typ string, in map[string]func(PlanContext) (PlanResult, error)) (map[string]func(PlanContext) (PlanResult, error), error) {
	out := make(map[string]func(PlanContext) (PlanResult, error), len(in))
	for kind, fn := range in {
		k := normalizeType(kind)
		if k == "" {
			return nil, fmt.Errorf("plan validate kind cannot be empty for type %q", typ)
		}
		if fn == nil {
			return nil, fmt.Errorf("plan validate kind %q has nil func", k)
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("plan validate kind %q already registered", k)
		}
		out[k] = fn
	}
	return out, nil
}

func (r *Registry) RegisterApply(h ApplyHandler) error {
	if r == nil {
		return fmt.Errorf("plugin registry is nil")
	}
	typ := normalizeType(h.Type)
	if typ == "" {
		return fmt.Errorf("apply handler type is required")
	}
	if h.Apply == nil {
		return fmt.Errorf("apply handler %q is missing Apply func", typ)
	}

	normalizedValidate, err := normalizeApplyValidateKinds(typ, h.ValidateKinds)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.applyByType[typ]; exists {
		return fmt.Errorf("apply handler already registered for type %q", typ)
	}
	for k := range normalizedValidate {
		if _, exists := r.applyByValidate[k]; exists {
			return fmt.Errorf("apply validate kind %q already registered", k)
		}
	}

	h.Type = typ
	h.ValidateKinds = normalizedValidate
	r.applyByType[typ] = h
	for k, fn := range normalizedValidate {
		r.applyByValidate[k] = fn
	}
	return nil
}

func (r *Registry) RegisterPlan(h PlanHandler) error {
	if r == nil {
		return fmt.Errorf("plugin registry is nil")
	}
	typ := normalizeType(h.Type)
	if typ == "" {
		return fmt.Errorf("plan handler type is required")
	}
	if h.Plan == nil {
		return fmt.Errorf("plan handler %q is missing Plan func", typ)
	}

	normalizedValidate, err := normalizePlanValidateKinds(typ, h.ValidateKinds)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.planByType[typ]; exists {
		return fmt.Errorf("plan handler already registered for type %q", typ)
	}
	for k := range normalizedValidate {
		if _, exists := r.planByValidate[k]; exists {
			return fmt.Errorf("plan validate kind %q already registered", k)
		}
	}

	h.Type = typ
	h.ValidateKinds = normalizedValidate
	r.planByType[typ] = h
	for k, fn := range normalizedValidate {
		r.planByValidate[k] = fn
	}
	return nil
}

func (r *Registry) RegisterRollback(h RollbackHandler) error {
	if r == nil {
		return fmt.Errorf("plugin registry is nil")
	}
	typ := normalizeType(h.Type)
	if typ == "" {
		return fmt.Errorf("rollback handler type is required")
	}
	if h.Capture == nil {
		return fmt.Errorf("rollback handler %q is missing Capture func", typ)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.rollbackByType[typ]; exists {
		return fmt.Errorf("rollback handler already registered for type %q", typ)
	}

	h.Type = typ
	r.rollbackByType[typ] = h
	return nil
}

func preparePluginApplyHandlers(handlers []ApplyHandler) (map[string]map[string]struct{}, []ApplyHandler, error) {
	if len(handlers) == 0 {
		return nil, nil, fmt.Errorf("plugin must export at least one apply handler")
	}

	validateByType := make(map[string]map[string]struct{}, len(handlers))
	prepared := make([]ApplyHandler, 0, len(handlers))
	for _, h := range handlers {
		typ := normalizeType(h.Type)
		if typ == "" {
			return nil, nil, fmt.Errorf("plugin apply handler type is required")
		}
		if _, exists := validateByType[typ]; exists {
			return nil, nil, fmt.Errorf("plugin apply handler type %q is duplicated", typ)
		}
		if h.Apply == nil {
			return nil, nil, fmt.Errorf("plugin apply handler %q is missing Apply func", typ)
		}
		normalizedValidate, err := normalizeApplyValidateKinds(typ, h.ValidateKinds)
		if err != nil {
			return nil, nil, err
		}
		if len(normalizedValidate) == 0 {
			return nil, nil, fmt.Errorf("plugin apply handler %q must define at least one validate kind", typ)
		}

		h.Type = typ
		h.ValidateKinds = normalizedValidate
		validateByType[typ] = make(map[string]struct{}, len(normalizedValidate))
		for kind := range normalizedValidate {
			validateByType[typ][kind] = struct{}{}
		}
		prepared = append(prepared, h)
	}
	return validateByType, prepared, nil
}

func preparePluginPlanHandlers(handlers []PlanHandler) (map[string]map[string]struct{}, []PlanHandler, error) {
	if len(handlers) == 0 {
		return nil, nil, fmt.Errorf("plugin must export at least one plan handler")
	}

	validateByType := make(map[string]map[string]struct{}, len(handlers))
	prepared := make([]PlanHandler, 0, len(handlers))
	for _, h := range handlers {
		typ := normalizeType(h.Type)
		if typ == "" {
			return nil, nil, fmt.Errorf("plugin plan handler type is required")
		}
		if _, exists := validateByType[typ]; exists {
			return nil, nil, fmt.Errorf("plugin plan handler type %q is duplicated", typ)
		}
		if h.Plan == nil {
			return nil, nil, fmt.Errorf("plugin plan handler %q is missing Plan func", typ)
		}
		normalizedValidate, err := normalizePlanValidateKinds(typ, h.ValidateKinds)
		if err != nil {
			return nil, nil, err
		}
		if len(normalizedValidate) == 0 {
			return nil, nil, fmt.Errorf("plugin plan handler %q must define at least one validate kind", typ)
		}

		h.Type = typ
		h.ValidateKinds = normalizedValidate
		validateByType[typ] = make(map[string]struct{}, len(normalizedValidate))
		for kind := range normalizedValidate {
			validateByType[typ][kind] = struct{}{}
		}
		prepared = append(prepared, h)
	}
	return validateByType, prepared, nil
}

func preparePluginRollbackHandlers(handlers []RollbackHandler) (map[string]struct{}, []RollbackHandler, error) {
	if len(handlers) == 0 {
		return nil, nil, fmt.Errorf("plugin must export at least one rollback handler")
	}

	types := make(map[string]struct{}, len(handlers))
	prepared := make([]RollbackHandler, 0, len(handlers))
	for _, h := range handlers {
		typ := normalizeType(h.Type)
		if typ == "" {
			return nil, nil, fmt.Errorf("plugin rollback handler type is required")
		}
		if _, exists := types[typ]; exists {
			return nil, nil, fmt.Errorf("plugin rollback handler type %q is duplicated", typ)
		}
		if h.Capture == nil {
			return nil, nil, fmt.Errorf("plugin rollback handler %q is missing Capture func", typ)
		}

		h.Type = typ
		types[typ] = struct{}{}
		prepared = append(prepared, h)
	}
	return types, prepared, nil
}

func validatePluginValidateKindCoverage(typ string, applyKinds, planKinds map[string]struct{}) error {
	for kind := range applyKinds {
		if _, ok := planKinds[kind]; !ok {
			return fmt.Errorf("plugin missing plan validate kind %q for type %q", kind, typ)
		}
	}
	for kind := range planKinds {
		if _, ok := applyKinds[kind]; !ok {
			return fmt.Errorf("plugin missing apply validate kind %q for type %q", kind, typ)
		}
	}
	return nil
}

func validatePluginHandlerCoverage(
	applyValidateByType map[string]map[string]struct{},
	planValidateByType map[string]map[string]struct{},
	rollbackTypes map[string]struct{},
) error {
	for typ, applyKinds := range applyValidateByType {
		planKinds, ok := planValidateByType[typ]
		if !ok {
			return fmt.Errorf("plugin missing plan handler for type %q", typ)
		}
		if _, ok := rollbackTypes[typ]; !ok {
			return fmt.Errorf("plugin missing rollback handler for type %q", typ)
		}
		if err := validatePluginValidateKindCoverage(typ, applyKinds, planKinds); err != nil {
			return err
		}
	}
	for typ := range planValidateByType {
		if _, ok := applyValidateByType[typ]; !ok {
			return fmt.Errorf("plugin missing apply handler for type %q", typ)
		}
	}
	for typ := range rollbackTypes {
		if _, ok := applyValidateByType[typ]; !ok {
			return fmt.Errorf("plugin missing apply handler for type %q", typ)
		}
	}
	return nil
}

func (r *Registry) RegisterBundle(bundle PluginBundle) error {
	if r == nil {
		return fmt.Errorf("plugin registry is nil")
	}

	applyValidateByType, preparedApply, err := preparePluginApplyHandlers(bundle.ApplyHandlers)
	if err != nil {
		return err
	}
	planValidateByType, preparedPlan, err := preparePluginPlanHandlers(bundle.PlanHandlers)
	if err != nil {
		return err
	}
	rollbackTypes, preparedRollback, err := preparePluginRollbackHandlers(bundle.RollbackHandlers)
	if err != nil {
		return err
	}
	if err := validatePluginHandlerCoverage(applyValidateByType, planValidateByType, rollbackTypes); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	nextApplyByType := make(map[string]ApplyHandler, len(r.applyByType)+len(preparedApply))
	for typ, h := range r.applyByType {
		nextApplyByType[typ] = h
	}
	nextApplyByValidate := make(map[string]func(ApplyContext) error, len(r.applyByValidate))
	for kind, fn := range r.applyByValidate {
		nextApplyByValidate[kind] = fn
	}
	nextPlanByType := make(map[string]PlanHandler, len(r.planByType)+len(preparedPlan))
	for typ, h := range r.planByType {
		nextPlanByType[typ] = h
	}
	nextPlanByValidate := make(map[string]func(PlanContext) (PlanResult, error), len(r.planByValidate))
	for kind, fn := range r.planByValidate {
		nextPlanByValidate[kind] = fn
	}
	nextRollbackByType := make(map[string]RollbackHandler, len(r.rollbackByType)+len(preparedRollback))
	for typ, h := range r.rollbackByType {
		nextRollbackByType[typ] = h
	}

	for _, h := range preparedApply {
		if _, exists := nextApplyByType[h.Type]; exists {
			return fmt.Errorf("apply handler already registered for type %q", h.Type)
		}
		for kind, fn := range h.ValidateKinds {
			if _, exists := nextApplyByValidate[kind]; exists {
				return fmt.Errorf("apply validate kind %q already registered", kind)
			}
			nextApplyByValidate[kind] = fn
		}
		nextApplyByType[h.Type] = h
	}
	for _, h := range preparedPlan {
		if _, exists := nextPlanByType[h.Type]; exists {
			return fmt.Errorf("plan handler already registered for type %q", h.Type)
		}
		for kind, fn := range h.ValidateKinds {
			if _, exists := nextPlanByValidate[kind]; exists {
				return fmt.Errorf("plan validate kind %q already registered", kind)
			}
			nextPlanByValidate[kind] = fn
		}
		nextPlanByType[h.Type] = h
	}
	for _, h := range preparedRollback {
		if _, exists := nextRollbackByType[h.Type]; exists {
			return fmt.Errorf("rollback handler already registered for type %q", h.Type)
		}
		nextRollbackByType[h.Type] = h
	}

	r.applyByType = nextApplyByType
	r.applyByValidate = nextApplyByValidate
	r.planByType = nextPlanByType
	r.planByValidate = nextPlanByValidate
	r.rollbackByType = nextRollbackByType

	return nil
}

func (r *Registry) LookupApplyType(stepType string) (ApplyHandler, bool) {
	if r == nil {
		return ApplyHandler{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.applyByType[normalizeType(stepType)]
	return h, ok
}

func (r *Registry) LookupPlanType(stepType string) (PlanHandler, bool) {
	if r == nil {
		return PlanHandler{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.planByType[normalizeType(stepType)]
	return h, ok
}

func (r *Registry) LookupRollbackType(stepType string) (RollbackHandler, bool) {
	if r == nil {
		return RollbackHandler{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.rollbackByType[normalizeType(stepType)]
	return h, ok
}

func (r *Registry) LookupApplyValidate(kind string) (func(ApplyContext) error, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.applyByValidate[normalizeType(kind)]
	return fn, ok
}

func (r *Registry) LookupPlanValidate(kind string) (func(PlanContext) (PlanResult, error), bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.planByValidate[normalizeType(kind)]
	return fn, ok
}
