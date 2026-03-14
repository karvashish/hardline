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

	rctx := applyRollbackContext(nil, p)
	if rctx.Profile != p || rctx.Host != nil {
		t.Fatalf("unexpected rollback context: %+v", rctx)
	}
}
