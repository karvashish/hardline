BINARY := hardline
OUTDIR := tmp
CMD := ./cmd/$(BINARY)
SCHEMA_BIN := $(OUTDIR)/genschema
PROFILE_TOOL_BIN := $(OUTDIR)/profiletool
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X internals/cli.version=$(VERSION)
COVER_PACKAGES := ./cmd/profiletool ./internals/verify
COVER_PROFILE := $(abspath $(OUTDIR)/active.cover.out)
GO_CACHE_DIR := $(abspath $(OUTDIR)/.gocache)
MIN_COVERAGE ?= 90

PROFILE_DIR ?= base-secure-ubuntu-24.04-lts
SIGNING_KEY ?= profile_signing.key
SIGNING_PUB ?= profile_signing_pub.pem

.PHONY: all test build profiletool ensure-embedded-pubkey keygen sign-profile genschema tidy clean

all: test build

checkversion:
	@test -f internals/cli/version.json || (echo "version.json missing"; exit 1)

test:
	@echo "== running targeted tests with coverage =="
	@mkdir -p $(OUTDIR)
	GOCACHE=$(GO_CACHE_DIR) GO111MODULE=on go test $(COVER_PACKAGES) -coverprofile=$(COVER_PROFILE)
	@go tool cover -func=$(COVER_PROFILE) | tail -n 1
	@cov=$$(go tool cover -func=$(COVER_PROFILE) | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
		awk "BEGIN { if ($$cov < $(MIN_COVERAGE)) exit 1 }" || \
		(echo "coverage $$cov% is below minimum $(MIN_COVERAGE)%"; exit 1)

build: tidy checkversion ensure-embedded-pubkey genschema
	@echo "== building $(BINARY) ($(VERSION)) =="
	@mkdir -p $(OUTDIR)
	GO111MODULE=on CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS)" \
		-o $(OUTDIR)/$(BINARY) \
		$(CMD)

profiletool:
	@echo "== building profiletool =="
	@mkdir -p $(OUTDIR)
	GO111MODULE=on CGO_ENABLED=0 go build \
		-o $(PROFILE_TOOL_BIN) \
		./cmd/profiletool

ensure-embedded-pubkey: profiletool
	@if [ -f "internals/verify/profile_signing_pub.pem" ]; then \
		echo "== embedded profile signing key present: internals/verify/profile_signing_pub.pem =="; \
	else \
		echo "== embedded profile signing key missing: internals/verify/profile_signing_pub.pem =="; \
		echo "== generating profile signing keypair and embedded pubkey =="; \
		$(PROFILE_TOOL_BIN) keygen \
			--private-out $(SIGNING_KEY) \
			--public-out $(SIGNING_PUB); \
	fi

keygen: profiletool
	@echo "== generating profile signing keypair =="
	$(PROFILE_TOOL_BIN) keygen \
		--private-out $(SIGNING_KEY) \
		--public-out $(SIGNING_PUB)

sign-profile: profiletool
	@echo "== signing profile $(PROFILE_DIR) =="
	$(PROFILE_TOOL_BIN) sign \
		--profile-dir $(PROFILE_DIR) \
		--private-key $(SIGNING_KEY)

genschema:
	@echo "== building genschema tool =="
	@mkdir -p $(OUTDIR)
	GO111MODULE=on CGO_ENABLED=0 go build \
		-o $(SCHEMA_BIN) \
		./cmd/genschema

	@echo "== generating JSON schemas =="
	$(SCHEMA_BIN)

tidy:
	@go mod tidy

clean:
	rm -rf $(OUTDIR)
