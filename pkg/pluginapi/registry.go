package pluginapi

import (
	"fmt"
	"strings"
	"sync"

	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

type ApplyContext struct {
	Client  *ssh.Client
	Profile *profile.Profile
}

type PlanContext struct {
	Inspector inspector.Inspector
	Profile   *profile.Profile
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

type PluginBundle struct {
	Name          string
	ApplyHandlers []ApplyHandler
	PlanHandlers  []PlanHandler
}

type ApplyRegistry struct {
	mu         sync.RWMutex
	byType     map[string]ApplyHandler
	byValidate map[string]func(ApplyContext) error
}

type PlanRegistry struct {
	mu         sync.RWMutex
	byType     map[string]PlanHandler
	byValidate map[string]func(PlanContext) (PlanResult, error)
}

func NewApplyRegistry() *ApplyRegistry {
	return &ApplyRegistry{
		byType:     make(map[string]ApplyHandler),
		byValidate: make(map[string]func(ApplyContext) error),
	}
}

func NewPlanRegistry() *PlanRegistry {
	return &PlanRegistry{
		byType:     make(map[string]PlanHandler),
		byValidate: make(map[string]func(PlanContext) (PlanResult, error)),
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

func (r *ApplyRegistry) Register(h ApplyHandler) error {
	if r == nil {
		return fmt.Errorf("apply registry is nil")
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

	if _, exists := r.byType[typ]; exists {
		return fmt.Errorf("apply handler already registered for type %q", typ)
	}
	for k := range normalizedValidate {
		if _, exists := r.byValidate[k]; exists {
			return fmt.Errorf("apply validate kind %q already registered", k)
		}
	}

	h.Type = typ
	h.ValidateKinds = normalizedValidate
	r.byType[typ] = h
	for k, fn := range normalizedValidate {
		r.byValidate[k] = fn
	}
	return nil
}

func (r *PlanRegistry) Register(h PlanHandler) error {
	if r == nil {
		return fmt.Errorf("plan registry is nil")
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

	if _, exists := r.byType[typ]; exists {
		return fmt.Errorf("plan handler already registered for type %q", typ)
	}
	for k := range normalizedValidate {
		if _, exists := r.byValidate[k]; exists {
			return fmt.Errorf("plan validate kind %q already registered", k)
		}
	}

	h.Type = typ
	h.ValidateKinds = normalizedValidate
	r.byType[typ] = h
	for k, fn := range normalizedValidate {
		r.byValidate[k] = fn
	}
	return nil
}

func (r *ApplyRegistry) LookupType(stepType string) (ApplyHandler, bool) {
	if r == nil {
		return ApplyHandler{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.byType[normalizeType(stepType)]
	return h, ok
}

func (r *PlanRegistry) LookupType(stepType string) (PlanHandler, bool) {
	if r == nil {
		return PlanHandler{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.byType[normalizeType(stepType)]
	return h, ok
}

func (r *ApplyRegistry) LookupValidate(kind string) (func(ApplyContext) error, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.byValidate[normalizeType(kind)]
	return fn, ok
}

func (r *PlanRegistry) LookupValidate(kind string) (func(PlanContext) (PlanResult, error), bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.byValidate[normalizeType(kind)]
	return fn, ok
}
