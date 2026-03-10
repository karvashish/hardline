BINARY := hardline
OUTDIR := tmp
CMD := ./cmd/$(BINARY)
SCHEMA_BIN := $(OUTDIR)/genschema
PROFILE_TOOL_BIN := $(OUTDIR)/profiletool
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X internals/cli.version=$(VERSION)
COVER_PROFILE := $(abspath $(OUTDIR)/active.cover.out)
GO_CACHE_DIR := $(abspath $(OUTDIR)/.gocache)
MIN_COVERAGE ?= 90
TERRAFORM ?= terraform
ITEST_TF_DIR := integration-tests/terraform
ITEST_TF_STATE := $(abspath $(OUTDIR)/itest-gcp.tfstate)
ITEST_TF_OUTPUTS := $(abspath $(OUTDIR)/itest-gcp.outputs.json)
ITEST_TFVARS ?= $(ITEST_TF_DIR)/terraform.tfvars
ITEST_PROFILE ?= base-secure-ubuntu-24.04-lts
ITEST_E2E_SCRIPT := $(abspath integration-tests/run-e2e.sh)

PROFILE_DIR ?= base-secure-ubuntu-24.04-lts
SIGNING_KEY ?= profile_signing.key
SIGNING_PUB ?= profile_signing_pub.pem

.PHONY: all test build profiletool ensure-embedded-pubkey keygen sign-profile genschema tidy clean itest itest-gcp-preflight itest-gcp-init itest-gcp-plan itest-gcp-up itest-gcp-down itest-gcp-clean

all: test build

checkversion:
	@test -f internals/cli/version.json || (echo "version.json missing"; exit 1)

test:
	@echo "== running repo-wide tests with coverage =="
	@mkdir -p $(OUTDIR)
	@GOCACHE=$(GO_CACHE_DIR) GO111MODULE=on go test ./... -coverprofile=$(COVER_PROFILE); \
	cov=$$(GOCACHE=$(GO_CACHE_DIR) GO111MODULE=on go tool cover -func=$(COVER_PROFILE) | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	echo "repo-wide coverage: $$cov%"; \
	awk "BEGIN { if ($$cov < $(MIN_COVERAGE)) exit 1 }" || \
		{ echo "repo-wide coverage $$cov% is below minimum $(MIN_COVERAGE)%"; exit 1; }

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

itest-gcp-preflight:
	@command -v gcloud >/dev/null 2>&1 || { echo "gcloud CLI not found; install Google Cloud SDK first"; exit 1; }
	@command -v $(TERRAFORM) >/dev/null 2>&1 || { echo "terraform binary '$(TERRAFORM)' not found"; exit 1; }
	@active_account="$$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -n 1)"; \
	if [ -z "$$active_account" ]; then \
		echo "gcloud is not logged in. Run: gcloud auth login"; \
		exit 1; \
	fi; \
	echo "gcloud active account: $$active_account"
	@project="$$(gcloud config get-value project 2>/dev/null | tr -d '\n')"; \
	if [ -z "$$project" ] || [ "$$project" = "(unset)" ]; then \
		echo "gcloud project is not set. Run: gcloud config set project <PROJECT_ID>"; \
		exit 1; \
	fi; \
	echo "gcloud project: $$project"
	@if [ ! -f "$(abspath $(ITEST_TFVARS))" ]; then \
		echo "missing tfvars file: $(abspath $(ITEST_TFVARS))"; \
		echo "create it from template: cp $(ITEST_TF_DIR)/terraform.tfvars.example $(ITEST_TFVARS)"; \
		exit 1; \
	fi
	@tf_project="$$(awk -F= '/^[[:space:]]*project_id[[:space:]]*=/{gsub(/[[:space:]"]/, "", $$2); print $$2}' "$(abspath $(ITEST_TFVARS))" | head -n 1)"; \
	if [ -z "$$tf_project" ] || [ "$$tf_project" = "REPLACE_WITH_YOUR_GCP_PROJECT_ID" ]; then \
		echo "set project_id in $(abspath $(ITEST_TFVARS)) before running itest"; \
		exit 1; \
	fi; \
	echo "tfvars project_id: $$tf_project"; \
	gc_project="$$(gcloud config get-value project 2>/dev/null | tr -d '\n')"; \
	if [ "$$gc_project" != "$$tf_project" ]; then \
		echo "warning: gcloud project ($$gc_project) differs from tfvars project_id ($$tf_project)"; \
	fi
	@tf_account="$$(awk -F= '/^[[:space:]]*expected_gcloud_account[[:space:]]*=/{gsub(/[[:space:]"]/, "", $$2); print $$2}' "$(abspath $(ITEST_TFVARS))" | head -n 1)"; \
	if [ -z "$$tf_account" ] || [ "$$tf_account" = "REPLACE_WITH_GCLOUD_ACCOUNT_EMAIL" ]; then \
		echo "set expected_gcloud_account in $(abspath $(ITEST_TFVARS)) before running itest"; \
		exit 1; \
	fi; \
	echo "tfvars expected_gcloud_account: $$tf_account"
	@gcloud auth print-access-token >/dev/null 2>&1 || { \
		echo "gcloud user token is invalid. Re-authenticate: gcloud auth login"; \
		exit 1; \
	}
	@gcloud auth application-default print-access-token >/dev/null 2>&1 || { \
		echo "application-default credentials are invalid. Re-authenticate: gcloud auth application-default login"; \
		exit 1; \
	}
	@active_account="$$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -n 1)"; \
	tf_account="$$(awk -F= '/^[[:space:]]*expected_gcloud_account[[:space:]]*=/{gsub(/[[:space:]"]/, "", $$2); print $$2}' "$(abspath $(ITEST_TFVARS))" | head -n 1)"; \
	if [ "$$active_account" != "$$tf_account" ]; then \
		echo "active account ($$active_account) does not match expected_gcloud_account ($$tf_account)"; \
		exit 1; \
	fi

itest-gcp-init: itest-gcp-preflight
	@mkdir -p $(OUTDIR)
	@cd $(ITEST_TF_DIR) && $(TERRAFORM) init -reconfigure -backend-config="path=$(ITEST_TF_STATE)"

itest-gcp-plan: itest-gcp-init
	@cd $(ITEST_TF_DIR) && \
	TFVARS_ARG=""; \
	if [ -f "$(abspath $(ITEST_TFVARS))" ]; then TFVARS_ARG="-var-file=$(abspath $(ITEST_TFVARS))"; fi; \
	$(TERRAFORM) plan $$TFVARS_ARG

itest-gcp-up: itest-gcp-init
	@cd $(ITEST_TF_DIR) && \
	TFVARS_ARG=""; \
	if [ -f "$(abspath $(ITEST_TFVARS))" ]; then TFVARS_ARG="-var-file=$(abspath $(ITEST_TFVARS))"; fi; \
	$(TERRAFORM) apply -auto-approve $$TFVARS_ARG && \
	$(TERRAFORM) output -json > "$(ITEST_TF_OUTPUTS)"
	@echo "wrote outputs to $(ITEST_TF_OUTPUTS)"

itest-gcp-down: itest-gcp-init
	@cd $(ITEST_TF_DIR) && \
	TFVARS_ARG=""; \
	if [ -f "$(abspath $(ITEST_TFVARS))" ]; then TFVARS_ARG="-var-file=$(abspath $(ITEST_TFVARS))"; fi; \
	$(TERRAFORM) destroy -auto-approve $$TFVARS_ARG

itest-gcp-clean: itest-gcp-down

itest:
	@integration-tests/itest-gcp.sh "ITEST_PROFILE=$(ITEST_PROFILE) ITEST_TFVARS=$(abspath $(ITEST_TFVARS)) ITEST_OUTPUTS_JSON=$(ITEST_TF_OUTPUTS) $(ITEST_E2E_SCRIPT)"
