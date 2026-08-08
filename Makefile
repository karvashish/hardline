BINARY := hardline
OUTDIR := tmp
CMD := ./cmd/$(BINARY)
PLUGIN_OUTDIR := $(OUTDIR)/plugins
FIREWALL_TEMPLATE_PLUGIN := $(PLUGIN_OUTDIR)/firewall_template.so
SCHEMA_BIN := $(OUTDIR)/genschema
PROFILE_TOOL_BIN := $(OUTDIR)/profiletool
VERSION := $(shell sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' internals/cli/version.json 2>/dev/null)
LDFLAGS := -s -w
COVER_PROFILE := $(abspath $(OUTDIR)/active.cover.out)
GO_CACHE_DIR := $(abspath $(OUTDIR)/.gocache)
MIN_COVERAGE ?= 90
TERRAFORM ?= terraform
ITEST_TF_DIR := integration-tests/terraform
ITEST_TF_STATE := $(abspath $(OUTDIR)/itest-gcp.tfstate)
ITEST_TF_OUTPUTS := $(abspath $(OUTDIR)/itest-gcp.outputs.json)
ITEST_TFVARS ?= $(ITEST_TF_DIR)/terraform.tfvars
ITEST_PROFILE ?= integration-tests/profiles/multi-plugin-success
ITEST_SCENARIO ?= smoke
PROFILE_DIR ?= starter-secure-ubuntu-24.04-lts
SIGNING_KEY ?= $(OUTDIR)/profile_signing.key
SIGNING_PUB ?= internals/verify/profile_signing_pub.pem
PROFILE_DIRS := \
	starter-secure-ubuntu-24.04-lts \
	demo-profile \
	$(patsubst %/,%,$(sort $(dir $(wildcard integration-tests/profiles/*/profile.json))))

WIN_GOARCH ?= amd64
WIN_OUTDIR := $(OUTDIR)/windows/$(WIN_GOARCH)

.PHONY: all test check-schemas check-standalone build build-plugins build-firewall-template-plugin build-windows profiletool ensure-embedded-pubkey keygen sign-profile sign-profiles genschema tidy clean itest itest-scenario itest-scenarios itest-all examples itest-gcp-preflight itest-gcp-init itest-gcp-plan itest-gcp-up itest-gcp-down itest-gcp-clean

all: test build

checkversion:
	@test -f internals/cli/version.json || (echo "version.json missing"; exit 1)

test:
	@echo "== running repo-wide tests with coverage =="
	@mkdir -p $(OUTDIR)
	@GOCACHE=$(GO_CACHE_DIR) GO111MODULE=on go test ./... -count=1 -coverprofile=$(COVER_PROFILE) -cover | tee $(OUTDIR)/coverage.txt; \
	cov=$$(GOCACHE=$(GO_CACHE_DIR) GO111MODULE=on go tool cover -func=$(COVER_PROFILE) | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	echo "repo-wide coverage: $$cov%"; \
	for pkg in $$(GOCACHE=$(GO_CACHE_DIR) GO111MODULE=on go list ./...); do \
		pkg_name=$$(printf "%s" "$$pkg" | sed 's#/#_#g'); \
		pkg_profile="$(OUTDIR)/$${pkg_name}.cover.out"; \
		pkg_log="$(OUTDIR)/$${pkg_name}.cover.log"; \
		GOCACHE=$(GO_CACHE_DIR) GO111MODULE=on go test "$$pkg" -count=1 -coverprofile="$$pkg_profile" >"$$pkg_log" 2>&1 || { cat "$$pkg_log"; exit 1; }; \
		if [ "$$(wc -l <"$$pkg_profile")" -le 1 ]; then continue; fi; \
		pkg_cov=$$(GOCACHE=$(GO_CACHE_DIR) GO111MODULE=on go tool cover -func="$$pkg_profile" | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
		if ! awk "BEGIN { exit !($$pkg_cov >= $(MIN_COVERAGE)) }"; then \
			echo "package coverage below minimum: $$pkg $$pkg_cov%"; \
			bad=1; \
		fi; \
	done; \
	test -z "$$bad" || \
		{ echo "one or more packages are below minimum $(MIN_COVERAGE)%"; exit 1; }; \
	awk "BEGIN { if ($$cov < $(MIN_COVERAGE)) exit 1 }" || \
		{ echo "repo-wide coverage $$cov% is below minimum $(MIN_COVERAGE)%"; exit 1; }

build: tidy checkversion ensure-embedded-pubkey genschema build-plugins
	@echo "== building $(BINARY) ($(VERSION)) =="
	@mkdir -p $(OUTDIR)
	GO111MODULE=on CGO_ENABLED=1 go build \
		-ldflags "$(LDFLAGS)" \
		-o $(OUTDIR)/$(BINARY) \
		$(CMD)

build-windows: tidy checkversion ensure-embedded-pubkey genschema
	@echo "== building $(BINARY) for windows/$(WIN_GOARCH) ($(VERSION)) =="
	@echo "== external plugins are NOT supported on windows (CGO disabled, plugin system is unix-only) =="
	@mkdir -p $(WIN_OUTDIR)
	GOOS=windows GOARCH=$(WIN_GOARCH) GO111MODULE=on CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS)" \
		-o $(WIN_OUTDIR)/$(BINARY).exe \
		$(CMD)
	GOOS=windows GOARCH=$(WIN_GOARCH) GO111MODULE=on CGO_ENABLED=0 go build \
		-o $(WIN_OUTDIR)/profiletool.exe \
		./cmd/profiletool

build-plugins: build-firewall-template-plugin

build-firewall-template-plugin:
	@echo "== building firewall_template plugin =="
	@mkdir -p $(PLUGIN_OUTDIR)
	GO111MODULE=on CGO_ENABLED=1 go build \
		-buildmode=plugin \
		-o $(FIREWALL_TEMPLATE_PLUGIN) \
		./pluginprojects/firewalltemplate

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

sign-profiles: profiletool
	@for dir in $(PROFILE_DIRS); do \
		echo "== signing profile $$dir =="; \
		$(PROFILE_TOOL_BIN) sign --profile-dir "$$dir" --private-key $(SIGNING_KEY) || exit $$?; \
	done

genschema:
	@echo "== building genschema tool =="
	@mkdir -p $(OUTDIR)
	GO111MODULE=on CGO_ENABLED=0 go build \
		-o $(SCHEMA_BIN) \
		./cmd/genschema

	@echo "== generating JSON schemas =="
	$(SCHEMA_BIN)

# Fails if the committed schemas drift from the Go structs they are reflected
# from. They are embedded into the binary, so a stale commit ships stale rules.
check-schemas: genschema
	@git diff --exit-code -- schema/ || \
		{ echo "schema/ is stale; run 'make genschema' and commit the result"; exit 1; }

check-standalone:
	@scripts/check-standalone.sh

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
	@integration-tests/wait-host-ready.sh "$(ITEST_TF_OUTPUTS)"

itest-gcp-down: itest-gcp-init
	@cd $(ITEST_TF_DIR) && \
	TFVARS_ARG=""; \
	if [ -f "$(abspath $(ITEST_TFVARS))" ]; then TFVARS_ARG="-var-file=$(abspath $(ITEST_TFVARS))"; fi; \
	$(TERRAFORM) destroy -auto-approve $$TFVARS_ARG

itest-gcp-clean: itest-gcp-down

itest:
	@$(MAKE) itest-gcp-up
	@integration-tests/itest.sh smoke "$(ITEST_PROFILE)" "$(ITEST_TF_OUTPUTS)" "$(abspath $(OUTDIR)/$(BINARY))"

itest-scenario:
	@$(MAKE) itest-gcp-up
	@integration-tests/itest.sh "$(ITEST_SCENARIO)" "$(ITEST_PROFILE)" "$(ITEST_TF_OUTPUTS)" "$(abspath $(OUTDIR)/$(BINARY))"

itest-scenarios:
	@$(MAKE) itest-gcp-up
	@integration-tests/itest.sh all "$(ITEST_PROFILE)" "$(ITEST_TF_OUTPUTS)" "$(abspath $(OUTDIR)/$(BINARY))"

# One-shot full run: build a fresh binary, provision (itest-gcp-up now blocks
# until the host is ready), run every scenario, then ALWAYS tear the host down.
# Exits with the scenario status; flags a failed teardown loudly so a billable
# VM is never left running silently.
itest-all: build
	@scen=0; down=0; \
	if $(MAKE) itest-gcp-up; then \
		integration-tests/itest.sh all "$(ITEST_PROFILE)" "$(ITEST_TF_OUTPUTS)" "$(abspath $(OUTDIR)/$(BINARY))" || scen=$$?; \
	else \
		scen=1; \
	fi; \
	$(MAKE) itest-gcp-down || down=$$?; \
	if [ $$down -ne 0 ]; then echo "WARNING: teardown failed (down=$$down) — destroy the leftover VM with: make itest-gcp-down"; exit $$down; fi; \
	exit $$scen

# Regenerate docs/examples/<profile> from a real run: build a fresh binary,
# provision a throwaway Ubuntu 24.04 host, capture verify/plan/apply/rollback
# and the journal, normalize host/home/version placeholders, then ALWAYS tear
# the host down. PROFILE_DIR selects the profile; EXAMPLES_DIR the output dir.
EXAMPLES_DIR ?= docs/examples/$(PROFILE_DIR)
examples: build
	@gen=0; down=0; \
	if $(MAKE) itest-gcp-up; then \
		integration-tests/regen-examples.sh "$(PROFILE_DIR)" "$(ITEST_TF_OUTPUTS)" "$(abspath $(OUTDIR)/$(BINARY))" "$(abspath $(EXAMPLES_DIR))" || gen=$$?; \
	else \
		gen=1; \
	fi; \
	$(MAKE) itest-gcp-down || down=$$?; \
	if [ $$down -ne 0 ]; then echo "WARNING: teardown failed (down=$$down) — destroy the leftover VM with: make itest-gcp-down"; exit $$down; fi; \
	exit $$gen
