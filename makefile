# Core Definitions -------------------------------------------------------------

# Directories
SRC_DIR := src/core
LIB_DIR := $(SRC_DIR)/lib
BUILD_DIR := build
TEST_DIR := test
TOOLS_DIR := tools
T_COSE_DIR := $(TOOLS_DIR)/t_cose
QCBOR_DIR := $(TOOLS_DIR)/qcbor

# Files
SRCS := $(wildcard $(SRC_DIR)/*.c)
TEST_SRC := $(wildcard $(TEST_DIR)/test_*_unit.c)
T_COSE_SRCS := \
    $(T_COSE_DIR)/src/t_cose_sign1_verify.c \
    $(T_COSE_DIR)/src/t_cose_util.c \
    $(T_COSE_DIR)/src/t_cose_parameters.c \
    $(T_COSE_DIR)/src/t_cose_short_circuit.c \
	$(T_COSE_DIR)/crypto_adapters/t_cose_openssl_crypto.c
QCBOR_SRCS := \
    $(QCBOR_DIR)/src/qcbor_decode.c \
    $(QCBOR_DIR)/src/qcbor_encode.c \
    $(QCBOR_DIR)/src/UsefulBuf.c \
    $(QCBOR_DIR)/src/ieee754.c
LIB_SRCS := \
	$(wildcard $(LIB_DIR)/*.c) \
	$(wildcard $(LIB_DIR)/*.S) \
	$(T_COSE_SRCS) \
	$(QCBOR_SRCS)
BINS := $(addprefix $(BUILD_DIR)/,$(notdir $(SRCS:.c=)))
TEST_BINS := $(addprefix $(BUILD_DIR)/,$(notdir $(TEST_SRC:.c=)))

# Compiler
CC := gcc
CFLAGS := -Wall -Wextra -O2 \
	-Isrc/core \
	-I$(QCBOR_DIR)/inc \
	-I$(T_COSE_DIR)/inc -I$(T_COSE_DIR)/src \
	-DT_COSE_USE_OPENSSL_CRYPTO=1
LDFLAGS := -lcrypto -lm

ifdef COVERAGE
	CFLAGS += --coverage -O0
	LDFLAGS += --coverage
endif

ifdef ASAN
	CFLAGS  += -fsanitize=address -fno-omit-frame-pointer -g
	LDFLAGS += -fsanitize=address
	export ASAN_OPTIONS = detect_leaks=1:print_summary=1
endif

# Default target ---------------------------------------------------------------

all: core bindings

clean:
	rm -rf $(BUILD_DIR)

# Building C library -----------------------------------------------------------

core: $(T_COSE_DIR) $(QCBOR_DIR) $(BINS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(TOOLS_DIR):
	@mkdir -p $(TOOLS_DIR)

$(T_COSE_DIR):
	@if [ ! -d "$(T_COSE_DIR)" ]; then \
		git clone --recursive https://github.com/laurencelundblade/t_cose.git \
			$(T_COSE_DIR); \
	fi

$(QCBOR_DIR):
	@if [ ! -d "$(QCBOR_DIR)" ]; then \
		git clone https://github.com/laurencelundblade/qcbor.git \
			$(QCBOR_DIR); \
	fi

$(BUILD_DIR)/%: $(SRC_DIR)/%.c $(LIB_SRCS) | $(BUILD_DIR) $(T_COSE_DIR) $(QCBOR_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/test_%_unit: $(TEST_DIR)/test_%_unit.c $(LIB_DIR)/%.c $(LIB_SRCS) | $(BUILD_DIR) $(TOOLS_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Building Bindings ------------------------------------------------------------

bindings: python docker

python: core
	pip install -e src/bindings/python

docker: core
	docker compose build

# Testing ----------------------------------------------------------------------

lint: $(T_COSE_DIR) $(QCBOR_DIR)
	@if ! command -v clang-tidy >/dev/null 2>&1; then \
		sudo apt-get update -qq && sudo apt-get install -y -qq clang-tidy; \
	fi
	clang-tidy $(LIB_DIR)/*.c -- $(CFLAGS)
	@echo "Linting complete."

test: test-unit test-system test-bindings

test-unit: $(T_COSE_DIR) $(QCBOR_DIR) $(TEST_BINS)
	@for bin in $(TEST_BINS); do \
		$$bin || exit 1; \
	done

test-system: core
	./build/get_attestation_ccf "example-report-data" \
		| xargs -0 ./build/verify_attestation_ccf \
			--report-data "example-report-data" \
			--security-policy-b64 "$$(cat examples/security_policies/allow_all.rego | base64 -w 0)"

DEPLOYMENT_NAME ?= test-aci
test-aci:
	@if ! command -v c-aci-testing >/dev/null 2>&1; then \
		pip install git+https://github.com/microsoft/confidential-aci-testing@1.2.7; \
	fi
	c-aci-testing target run . \
		--policy-type "allow_all" \
		--deployment-name $(DEPLOYMENT_NAME) | tee /tmp/logs.txt
	@grep -q "All tests passed" /tmp/logs.txt

test-bindings: test-python test-docker test-server

test-python: python
	@echo "Running python tests..."
	pip install -r test/python/requirements.txt
	pytest -q test/python

test-docker: docker
	@echo "Running docker tests..."
	docker compose up --build --abort-on-container-failure

test-server: docker
	@echo "Running server tests..."
	@docker compose run -d --remove-orphans attestation server
	@docker compose run attestation verify_attestation_ccf \
		--report-data "example-report-data" \
		--security-policy-b64 "$$(cat examples/security_policies/allow_all.rego | base64 -w 0)" \
		"$$(curl localhost:5000/get_attestation_ccf?report_data=example_report_data)"
	@docker compose down

coverage: clean
	@if ! command -v lcov >/dev/null 2>&1; then \
		sudo apt-get update -qq && sudo apt-get install -y -qq lcov; \
	fi
	-@$(MAKE) COVERAGE=1 test-unit
	@lcov --capture --directory build --output-file build/coverage.info
	@lcov --extract build/coverage.info '*/src/core/lib/*' --output-file build/coverage_filtered.info
	@genhtml build/coverage_filtered.info --output-directory build/coverage_html

asan: clean
	$(MAKE) ASAN=1 test-system

# Release ----------------------------------------------------------------------

login-docker:
	@unset GITHUB_TOKEN && \
	gh auth login && \
	gh auth token | docker login ghcr.io -u ${GITHUB_USER} --password-stdin

release-docker: docker
	docker compose push
