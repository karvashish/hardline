package apply

import (
	"testing"

	"github.com/karvashish/hardline/pkg/profile"
)

func TestRegistryContextHelpers(t *testing.T) {
	p := &profile.Profile{ID: "p2"}
	actx := applyActionContext(nil, p)
	if actx.Profile != p || actx.Host != nil {
		t.Fatalf("unexpected apply action context: %+v", actx)
	}

	cctx := applyCaptureContext(nil, p)
	if cctx.Profile != p || cctx.Host != nil {
		t.Fatalf("unexpected capture context: %+v", cctx)
	}
}
