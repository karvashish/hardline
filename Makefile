BINARY := hardline
OUTDIR := tmp
CMD := ./cmd/$(BINARY)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X internals/cli.version=$(VERSION)

.PHONY: all build tidy clean

all: build

build: tidy
	@echo "== building $(BINARY) ($(VERSION)) =="
	GO111MODULE=on CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS)" \
		-o $(OUTDIR)/$(BINARY) \
		$(CMD)

tidy:
	@go mod tidy

clean:
	rm -rf $(OUTDIR)
