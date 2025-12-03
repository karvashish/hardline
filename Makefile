BINARY := hardline
OUTDIR := tmp
CMD := ./cmd/$(BINARY)
SCHEMA_BIN := $(OUTDIR)/genschema
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X internals/cli.version=$(VERSION)

.PHONY: all build genschema tidy clean

all: build

build: tidy genschema
	@echo "== building $(BINARY) ($(VERSION)) =="
	GO111MODULE=on CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS)" \
		-o $(OUTDIR)/$(BINARY) \
		$(CMD)

genschema:
	@echo "== building genschema tool =="
	GO111MODULE=on CGO_ENABLED=0 go build \
		-o $(SCHEMA_BIN) \
		./cmd/genschema

	@echo "== generating JSON schemas =="
	$(SCHEMA_BIN)

tidy:
	@go mod tidy

clean:
	rm -rf $(OUTDIR)
