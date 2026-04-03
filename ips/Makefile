CC := gcc
CFLAGS := -O2 -Wall -Wextra -std=c11
CPPFLAGS := -D_DEFAULT_SOURCE -Isrc/inline
LDFLAGS :=
LDLIBS :=
.DEFAULT_GOAL := main
VALGRIND ?= valgrind
VALGRIND_FLAGS ?= --leak-check=full --show-leak-kinds=all --track-origins=yes --num-callers=32 --error-exitcode=1
CLANG_FORMAT ?= clang-format
HS_CFLAGS = $(shell \
	if command -v pkg-config >/dev/null 2>&1; then \
		pkg-config --cflags libhs 2>/dev/null || pkg-config --cflags hyperscan 2>/dev/null; \
	fi \
)
HS_LIBS = $(shell \
	if command -v pkg-config >/dev/null 2>&1; then \
		pkg-config --libs libhs 2>/dev/null || pkg-config --libs hyperscan 2>/dev/null; \
	fi \
)
PCRE_CFLAGS = $(shell \
	if command -v pkg-config >/dev/null 2>&1; then \
		pkg-config --cflags libpcre2-8 2>/dev/null; \
	elif command -v pcre2-config >/dev/null 2>&1; then \
		pcre2-config --cflags 2>/dev/null; \
	elif command -v brew >/dev/null 2>&1; then \
		echo -I$$(brew --prefix pcre2 2>/dev/null)/include; \
	fi \
)
PCRE_LIBS = $(shell \
	if command -v pkg-config >/dev/null 2>&1; then \
		pkg-config --libs libpcre2-8 2>/dev/null; \
	elif command -v pcre2-config >/dev/null 2>&1; then \
		pcre2-config --libs8 2>/dev/null; \
	elif command -v brew >/dev/null 2>&1; then \
		echo -L$$(brew --prefix pcre2 2>/dev/null)/lib -lpcre2-8; \
	fi \
)
PCRE_CHECK_BIN := /tmp/ips_pcre2_check
AUTO_INSTALL_DEPS ?= 0

SRC_DIR := src
INC_DIR := include
TEST_DIR := tests
TEST_COMMON_DIR := $(TEST_DIR)/common
TEST_UNIT_DIR := $(TEST_DIR)/unit
TEST_INTEGRATION_DIR := $(TEST_DIR)/integration
TEST_BOUNDARY_DIR := $(TEST_DIR)/boundary
TEST_EVASION_DIR := $(TEST_DIR)/evasion
TEST_SCENARIO_DIR := $(TEST_DIR)/scenario
TEST_VALGRIND_DIR := $(TEST_DIR)/valgrind
BENCH_DIR := benchmark
BUILD_DIR := build
BIN_BUILD_DIR := $(BUILD_DIR)/bin
TEST_BUILD_DIR := $(BUILD_DIR)/test
UNIT_BUILD_DIR := $(BUILD_DIR)/units
BENCH_BUILD_DIR := $(BUILD_DIR)/benchmark
LOG_DIR := logs

MAIN_BIN := $(BIN_BUILD_DIR)/inline-ips
MAIN_HS_BIN := $(BIN_BUILD_DIR)/inline-ips-hs
SNIFFING_BIN := $(BIN_BUILD_DIR)/sniffing-ips
DETECT_ENGINE_BIN := $(BENCH_BUILD_DIR)/test_engine_detect
DETECT_PIPELINE_BIN := $(BENCH_BUILD_DIR)/test_detect_pipeline
NORMAL_BENCHMARK_BIN := $(BENCH_BUILD_DIR)/test_benchmark_normal
ATTACK_BENCHMARK_BIN := $(BENCH_BUILD_DIR)/test_benchmark_attack
REASM_PIPELINE_BIN := $(BENCH_BUILD_DIR)/test_reasm_pipeline
HTTP_STREAM_SEARCH_BENCH_BIN := $(BENCH_BUILD_DIR)/test_http_stream_search_bench

APP_PCRE2_SRCS := $(SRC_DIR)/inline/main_pcre2.c \
	$(SRC_DIR)/inline/mini_ips_pcre2.c \
	$(SRC_DIR)/inline/logging.c \
	$(SRC_DIR)/inline/tproxy.c \
	$(SRC_DIR)/inline/blocking.c \
	$(SRC_DIR)/inline/detect.c \
	$(SRC_DIR)/inline/engine_pcre2.c \
	$(SRC_DIR)/inline/http_parser.c \
	$(SRC_DIR)/inline/decoding.c \
	$(SRC_DIR)/inline/normalization.c \
	$(SRC_DIR)/inline/regex.c \
	$(SRC_DIR)/inline/ring.c

APP_HS_SRCS := $(SRC_DIR)/inline/main_hs.c \
	$(SRC_DIR)/inline/mini_ips_hs.c \
	$(SRC_DIR)/inline/logging.c \
	$(SRC_DIR)/inline/tproxy.c \
	$(SRC_DIR)/inline/blocking.c \
	$(SRC_DIR)/inline/detect.c \
	$(SRC_DIR)/inline/engine_hs.c \
	$(SRC_DIR)/inline/http_parser.c \
	$(SRC_DIR)/inline/decoding.c \
	$(SRC_DIR)/inline/normalization.c \
	$(SRC_DIR)/inline/regex.c \
	$(SRC_DIR)/inline/ring.c

SNIFFING_INCLUDE_DIR := $(SRC_DIR)/sniffing
SNIFFING_SRCS := $(SRC_DIR)/sniffing/main.c \
	$(SRC_DIR)/sniffing/httgw.c \
	$(SRC_DIR)/sniffing/packet_ring.c \
	$(SRC_DIR)/sniffing/reasm.c \
	$(SRC_DIR)/sniffing/runtime.c \
	$(SRC_DIR)/sniffing/detect.c \
	$(SRC_DIR)/sniffing/driver.c \
	$(SRC_DIR)/sniffing/engine.c \
	$(SRC_DIR)/sniffing/http_stream.c \
	$(SRC_DIR)/sniffing/logging.c \
	$(SRC_DIR)/sniffing/regex.c

INLINE_TEST_SRCS := $(wildcard $(TEST_UNIT_DIR)/test_*.c) $(wildcard $(TEST_INTEGRATION_DIR)/test_*.c) $(wildcard $(TEST_BOUNDARY_DIR)/test_*.c) $(wildcard $(TEST_EVASION_DIR)/test_*.c) $(wildcard $(TEST_SCENARIO_DIR)/test_*.c)
INLINE_TEST_NAMES := $(notdir $(basename $(INLINE_TEST_SRCS)))
INLINE_TEST_BINS := $(addprefix $(UNIT_BUILD_DIR)/,$(INLINE_TEST_NAMES))
VALGRIND_TEST_SRCS := $(wildcard $(TEST_VALGRIND_DIR)/test_*.c)
VALGRIND_TEST_NAMES := $(notdir $(basename $(VALGRIND_TEST_SRCS)))
VALGRIND_TEST_BINS := $(addprefix $(UNIT_BUILD_DIR)/,$(VALGRIND_TEST_NAMES))
INLINE_TEST_LOGS := $(addprefix $(LOG_DIR)/,$(addsuffix .log,$(INLINE_TEST_NAMES)))
INLINE_TEST_VG_LOGS := $(addprefix $(LOG_DIR)/,$(addsuffix .valgrind.log,$(INLINE_TEST_NAMES)))
BENCH_SRCS := $(wildcard $(BENCH_DIR)/test_*.c)
BENCH_NAMES := $(notdir $(basename $(BENCH_SRCS)))
PACKET_RING_BENCH_SRCS := $(wildcard $(BENCH_DIR)/test_packet_ring_*.c)
PACKET_RING_BENCH_NAMES := $(notdir $(basename $(PACKET_RING_BENCH_SRCS)))
PACKET_RING_BENCH_BINS := $(addprefix $(BENCH_BUILD_DIR)/,$(PACKET_RING_BENCH_NAMES))
BENCH_BINS := $(PACKET_RING_BENCH_BINS) $(DETECT_ENGINE_BIN) $(DETECT_PIPELINE_BIN) $(NORMAL_BENCHMARK_BIN) $(ATTACK_BENCHMARK_BIN) $(REASM_PIPELINE_BIN) $(HTTP_STREAM_SEARCH_BENCH_BIN)
BENCH_LOGS := $(addprefix $(LOG_DIR)/,$(addsuffix .log,$(BENCH_NAMES)))
MAIN_VG_LOG := $(LOG_DIR)/main.valgrind.log
FORMAT_DIRS := $(wildcard $(SRC_DIR) $(INC_DIR) $(TEST_DIR) $(BENCH_DIR))
FORMAT_SRCS := $(shell find $(FORMAT_DIRS) -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null)

.PHONY: all clean run tests units benchmark benchmarks run-benchmarks main main_pcre2 main_hs inline-ips inline-ips-hs sniffing check_pcre valgrind-units valgrind-main vg-main test-detect-engine format format-check valgrind-tests

all: main tests benchmark

main: $(MAIN_BIN)

main_pcre2: $(MAIN_BIN)

main_hs: $(MAIN_HS_BIN)

inline-ips: $(MAIN_BIN)

inline-ips-hs: $(MAIN_HS_BIN)

sniffing: $(SNIFFING_BIN)

tests: $(INLINE_TEST_BINS)

benchmark: $(BENCH_BINS)

$(BUILD_DIR) $(BIN_BUILD_DIR) $(TEST_BUILD_DIR) $(UNIT_BUILD_DIR) $(BENCH_BUILD_DIR) $(LOG_DIR):
	mkdir -p $@

$(MAIN_BIN): check_pcre $(APP_PCRE2_SRCS) $(SRC_DIR)/inline/tproxy.h $(SRC_DIR)/inline/mini_ips_pcre2.h | $(BIN_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) $(APP_PCRE2_SRCS) -o $@ $(LDFLAGS) $(PCRE_LIBS) -pthread $(LDLIBS)

$(MAIN_HS_BIN): $(APP_HS_SRCS) $(SRC_DIR)/inline/tproxy.h $(SRC_DIR)/inline/mini_ips_hs.h | $(BIN_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(HS_CFLAGS) $(CFLAGS) $(APP_HS_SRCS) -o $@ $(LDFLAGS) $(HS_LIBS) -pthread $(LDLIBS)

$(SNIFFING_BIN): check_pcre $(SNIFFING_SRCS) $(wildcard $(SNIFFING_INCLUDE_DIR)/*.h) | $(BIN_BUILD_DIR)
	$(CC) -D_DEFAULT_SOURCE -I$(SNIFFING_INCLUDE_DIR) \
		$(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) $(SNIFFING_SRCS) \
		-o $@ $(LDFLAGS) $(PCRE_LIBS) $(HS_LIBS) -lpcap -pthread $(LDLIBS)

$(DETECT_ENGINE_BIN): check_pcre $(BENCH_DIR)/test_engine_detect.c \
	$(SRC_DIR)/runtime.c $(SRC_DIR)/logging.c $(SRC_DIR)/detect.c \
	$(SRC_DIR)/engine.c $(SRC_DIR)/regex.c $(SRC_DIR)/html.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c \
	$(SRC_DIR)/http_stream.c | $(BENCH_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) \
		$(BENCH_DIR)/test_engine_detect.c $(SRC_DIR)/runtime.c \
		$(SRC_DIR)/logging.c $(SRC_DIR)/detect.c $(SRC_DIR)/engine.c \
		$(SRC_DIR)/html.c \
		$(SRC_DIR)/regex.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c \
		-o $@ $(LDFLAGS) -lpcap $(PCRE_LIBS) $(HS_LIBS) -pthread $(LDLIBS)

$(DETECT_PIPELINE_BIN): check_pcre $(BENCH_DIR)/test_detect_pipeline.c \
	$(SRC_DIR)/runtime.c $(SRC_DIR)/logging.c $(SRC_DIR)/detect.c \
	$(SRC_DIR)/engine.c $(SRC_DIR)/regex.c $(SRC_DIR)/html.c $(SRC_DIR)/packet_ring.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c \
	$(SRC_DIR)/http_stream.c | $(BENCH_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) \
		$(BENCH_DIR)/test_detect_pipeline.c $(SRC_DIR)/runtime.c \
		$(SRC_DIR)/logging.c $(SRC_DIR)/detect.c $(SRC_DIR)/engine.c \
		$(SRC_DIR)/html.c \
		$(SRC_DIR)/regex.c $(SRC_DIR)/packet_ring.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c \
		-o $@ $(LDFLAGS) -lpcap $(PCRE_LIBS) $(HS_LIBS) -pthread $(LDLIBS)

$(NORMAL_BENCHMARK_BIN): check_pcre $(BENCH_DIR)/test_benchmark_normal.c \
	$(BENCH_DIR)/configurable_detect_benchmark.c \
	$(SRC_DIR)/runtime.c $(SRC_DIR)/logging.c $(SRC_DIR)/detect.c \
	$(SRC_DIR)/engine.c $(SRC_DIR)/regex.c $(SRC_DIR)/html.c $(SRC_DIR)/packet_ring.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c \
	$(SRC_DIR)/http_stream.c | $(BENCH_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) \
		$(BENCH_DIR)/test_benchmark_normal.c \
		$(BENCH_DIR)/configurable_detect_benchmark.c $(SRC_DIR)/runtime.c \
		$(SRC_DIR)/logging.c $(SRC_DIR)/detect.c $(SRC_DIR)/engine.c \
		$(SRC_DIR)/html.c \
		$(SRC_DIR)/regex.c $(SRC_DIR)/packet_ring.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c \
		-o $@ $(LDFLAGS) -lpcap $(PCRE_LIBS) $(HS_LIBS) -pthread $(LDLIBS)

$(ATTACK_BENCHMARK_BIN): check_pcre $(BENCH_DIR)/test_benchmark_attack.c \
	$(BENCH_DIR)/configurable_detect_benchmark.c \
	$(SRC_DIR)/runtime.c $(SRC_DIR)/logging.c $(SRC_DIR)/detect.c \
	$(SRC_DIR)/engine.c $(SRC_DIR)/regex.c $(SRC_DIR)/html.c $(SRC_DIR)/packet_ring.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c \
	$(SRC_DIR)/http_stream.c | $(BENCH_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) \
		$(BENCH_DIR)/test_benchmark_attack.c \
		$(BENCH_DIR)/configurable_detect_benchmark.c $(SRC_DIR)/runtime.c \
		$(SRC_DIR)/logging.c $(SRC_DIR)/detect.c $(SRC_DIR)/engine.c \
		$(SRC_DIR)/html.c \
		$(SRC_DIR)/regex.c $(SRC_DIR)/packet_ring.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c \
		-o $@ $(LDFLAGS) -lpcap $(PCRE_LIBS) $(HS_LIBS) -pthread $(LDLIBS)

$(REASM_PIPELINE_BIN): $(BENCH_DIR)/test_reasm_pipeline.c \
	$(SRC_DIR)/packet_ring.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c | $(BENCH_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) \
		$(BENCH_DIR)/test_reasm_pipeline.c $(SRC_DIR)/packet_ring.c $(SRC_DIR)/reasm.c $(SRC_DIR)/httgw.c \
		$(SRC_DIR)/http_stream.c -o $@ $(LDFLAGS) -lpcap $(LDLIBS)

$(HTTP_STREAM_SEARCH_BENCH_BIN): $(BENCH_DIR)/test_http_stream_search_bench.c | $(BENCH_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

test-detect-engine: $(DETECT_ENGINE_BIN)
	./$(DETECT_ENGINE_BIN)

format:
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || (echo "clang-format not found: install clang-format and rerun 'make format'"; exit 1)
	$(CLANG_FORMAT) -i $(FORMAT_SRCS)

format-check:
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || (echo "clang-format not found: install clang-format and rerun 'make format-check'"; exit 1)
	@$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_SRCS)

run: all
	./$(MAIN_BIN)

units: $(INLINE_TEST_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(INLINE_TEST_BINS); do \
		echo "[units] running $$t"; \
		./$$t 2>&1 | tee $(LOG_DIR)/$$(basename $$t).log; \
	done
	@echo "units: all tests passed"

benchmarks: benchmark

run-benchmarks: benchmark | $(LOG_DIR)
	@set -e; \
	for t in $(BENCH_BINS); do \
		echo "[bench] running $$t"; \
		./$$t > $(LOG_DIR)/$$(basename $$t).log 2>&1; \
	done
	@echo "benchmarks: all benchmark binaries completed"

valgrind-units: $(INLINE_TEST_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(INLINE_TEST_BINS); do \
		echo "[valgrind] running $$t"; \
		$(VALGRIND) $(VALGRIND_FLAGS) --log-file=$(LOG_DIR)/$$(basename $$t).valgrind.log ./$$t; \
	done
	@echo "valgrind: all unit tests passed"

valgrind-main: $(MAIN_BIN) | $(LOG_DIR)
	$(VALGRIND) $(VALGRIND_FLAGS) --log-file=$(MAIN_VG_LOG) ./$(MAIN_BIN) $(RUN_ARGS)

vg-main: valgrind-main

valgrind-tests: $(VALGRIND_TEST_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(VALGRIND_TEST_BINS); do \
		echo "[valgrind-tests] running $$t"; \
		$(VALGRIND) $(VALGRIND_FLAGS) --log-file=$(LOG_DIR)/$$(basename $$t).valgrind.log ./$$t; \
	done
	@echo "valgrind-tests: all valgrind tests passed"

$(UNIT_BUILD_DIR)/test_decoding_functions: tests/unit/test_decoding_functions.c src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/decoding.c src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_decoding_pipeline: tests/integration/test_decoding_pipeline.c src/inline/decoding.c src/inline/decoding.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/decoding.c -o $@

$(UNIT_BUILD_DIR)/test_normalization_functions: tests/unit/test_normalization_functions.c src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_normalization_pipeline: tests/integration/test_normalization_pipeline.c src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/decoding.c src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_ring_functions: tests/unit/test_ring_functions.c src/inline/ring.c src/inline/ring.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/ring.c -o $@

$(UNIT_BUILD_DIR)/test_ring_pipeline: tests/integration/test_ring_pipeline.c src/inline/ring.c src/inline/ring.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/ring.c -o $@

$(UNIT_BUILD_DIR)/test_http_parser_functions: tests/unit/test_http_parser_functions.c src/inline/http_parser.c src/inline/http_parser.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/http_parser.c -o $@

$(UNIT_BUILD_DIR)/test_engine_functions: check_pcre tests/unit/test_engine_functions.c src/inline/engine.c src/inline/engine.h src/inline/regex.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/unit/test_engine_functions.c src/inline/engine.c src/inline/regex.c -o $@ $(LDFLAGS) $(PCRE_LIBS)

$(UNIT_BUILD_DIR)/test_detect_functions: check_pcre tests/unit/test_detect_functions.c src/inline/detect.c src/inline/detect.h src/inline/engine.c src/inline/engine.h src/inline/logging.c src/inline/logging.h src/inline/regex.h src/inline/http_parser.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/unit/test_detect_functions.c src/inline/detect.c src/inline/engine.c src/inline/logging.c -o $@ $(LDFLAGS) $(PCRE_LIBS)

$(UNIT_BUILD_DIR)/test_blocking_functions: tests/unit/test_blocking_functions.c src/inline/blocking.c src/inline/blocking.h src/inline/detect.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/blocking.c -o $@

$(UNIT_BUILD_DIR)/test_mini_ips_set_functions: check_pcre tests/unit/test_mini_ips_set_functions.c src/inline/mini_ips.c src/inline/mini_ips.h src/inline/logging.c src/inline/logging.h src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/unit/test_mini_ips_set_functions.c src/inline/mini_ips.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c -o $@ $(LDFLAGS) $(PCRE_LIBS) -pthread

$(UNIT_BUILD_DIR)/test_mini_ips_destroy_functions: check_pcre tests/unit/test_mini_ips_destroy_functions.c src/inline/mini_ips.c src/inline/mini_ips.h src/inline/logging.c src/inline/logging.h src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/unit/test_mini_ips_destroy_functions.c src/inline/mini_ips.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c -o $@ $(LDFLAGS) $(PCRE_LIBS) -pthread

$(UNIT_BUILD_DIR)/test_regex_loader_functions: tests/unit/test_regex_loader_functions.c src/inline/regex.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

$(UNIT_BUILD_DIR)/test_detect_pipeline: check_pcre tests/integration/test_detect_pipeline.c src/inline/detect.c src/inline/detect.h src/inline/engine.c src/inline/engine.h src/inline/logging.c src/inline/logging.h src/inline/http_parser.c src/inline/http_parser.h src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h src/inline/regex.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/integration/test_detect_pipeline.c src/inline/detect.c src/inline/engine.c src/inline/logging.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c -o $@ $(LDFLAGS) $(PCRE_LIBS)

$(UNIT_BUILD_DIR)/test_mini_ips_worker_pipeline: check_pcre tests/integration/test_mini_ips_worker_pipeline.c src/inline/mini_ips.c src/inline/mini_ips.h src/inline/logging.c src/inline/logging.h src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/integration/test_mini_ips_worker_pipeline.c src/inline/mini_ips.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c -o $@ $(LDFLAGS) $(PCRE_LIBS) -pthread

$(UNIT_BUILD_DIR)/test_mini_ips_tp_guards: check_pcre tests/integration/test_mini_ips_tp_guards.c src/inline/mini_ips.c src/inline/mini_ips.h src/inline/logging.c src/inline/logging.h src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/integration/test_mini_ips_tp_guards.c src/inline/mini_ips.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c -o $@ $(LDFLAGS) $(PCRE_LIBS) -pthread

$(UNIT_BUILD_DIR)/test_http_parser_pipeline: tests/integration/test_http_parser_pipeline.c src/inline/http_parser.c src/inline/http_parser.h src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_decoding_boundary: tests/boundary/test_decoding_boundary.c src/inline/decoding.c src/inline/decoding.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/decoding.c -o $@

$(UNIT_BUILD_DIR)/test_normalization_boundary: tests/boundary/test_normalization_boundary.c src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_ring_boundary: tests/boundary/test_ring_boundary.c src/inline/ring.c src/inline/ring.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/ring.c -o $@

$(UNIT_BUILD_DIR)/test_http_parser_boundary: tests/boundary/test_http_parser_boundary.c src/inline/http_parser.c src/inline/http_parser.h src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/http_parser.c src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_blocking_boundary: tests/boundary/test_blocking_boundary.c src/inline/blocking.c src/inline/blocking.h src/inline/detect.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/blocking.c -o $@

$(UNIT_BUILD_DIR)/test_large_input_boundary: tests/boundary/test_large_input_boundary.c src/inline/http_parser.c src/inline/http_parser.h src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_http_evasion_vectors: tests/evasion/test_http_evasion_vectors.c src/inline/http_parser.c src/inline/http_parser.h src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_parser_decode_normalize_scenario: tests/scenario/test_parser_decode_normalize_scenario.c src/inline/http_parser.c src/inline/http_parser.h src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_main_smoke: $(MAIN_BIN) tests/scenario/test_main_smoke.c $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/scenario/test_main_smoke.c -o $@

$(UNIT_BUILD_DIR)/test_main_pipeline: check_pcre tests/scenario/test_main_pipeline.c src/inline/mini_ips.c src/inline/mini_ips.h src/inline/logging.c src/inline/logging.h src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/scenario/test_main_pipeline.c src/inline/mini_ips.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c -o $@ $(LDFLAGS) $(PCRE_LIBS) -pthread

$(UNIT_BUILD_DIR)/test_detect_valgrind_smoke: check_pcre tests/valgrind/test_detect_valgrind_smoke.c src/inline/detect.c src/inline/detect.h src/inline/engine.c src/inline/engine.h src/inline/logging.c src/inline/logging.h src/inline/http_parser.c src/inline/http_parser.h src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h src/inline/regex.c src/inline/regex.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/valgrind/test_detect_valgrind_smoke.c src/inline/detect.c src/inline/engine.c src/inline/logging.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c -o $@ $(LDFLAGS) $(PCRE_LIBS)

$(UNIT_BUILD_DIR)/test_detect_valgrind_response: check_pcre tests/valgrind/test_detect_valgrind_response.c src/inline/detect.c src/inline/detect.h src/inline/engine.c src/inline/engine.h src/inline/logging.c src/inline/logging.h src/inline/http_parser.c src/inline/http_parser.h src/inline/decoding.c src/inline/decoding.h src/inline/normalization.c src/inline/normalization.h src/inline/regex.c src/inline/regex.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/valgrind/test_detect_valgrind_response.c src/inline/detect.c src/inline/engine.c src/inline/logging.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c -o $@ $(LDFLAGS) $(PCRE_LIBS)

$(UNIT_BUILD_DIR)/test_inline_blocking: tests/unit/test_inline_blocking.c src/inline/blocking.c src/inline/blocking.h src/inline/detect.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_inline_blocking.c src/inline/blocking.c -o $@

$(UNIT_BUILD_DIR)/test_inline_decoding: tests/unit/test_inline_decoding.c src/inline/decoding.c src/inline/decoding.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_inline_decoding.c src/inline/decoding.c -o $@

$(UNIT_BUILD_DIR)/test_inline_detect: check_pcre tests/unit/test_inline_detect.c src/inline/detect.c src/inline/engine_pcre2.c src/inline/regex.c src/inline/regex.h src/inline/http_parser.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/unit/test_inline_detect.c src/inline/detect.c src/inline/engine_pcre2.c src/inline/regex.c -o $@ $(LDFLAGS) $(PCRE_LIBS)

$(UNIT_BUILD_DIR)/test_inline_engine: check_pcre tests/unit/test_inline_engine.c src/inline/engine_pcre2.c src/inline/regex.c src/inline/http_parser.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/unit/test_inline_engine.c src/inline/engine_pcre2.c src/inline/regex.c -o $@ $(LDFLAGS) $(PCRE_LIBS)

$(UNIT_BUILD_DIR)/test_inline_http_parser: tests/unit/test_inline_http_parser.c src/inline/http_parser.c src/inline/http_parser.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_inline_http_parser.c src/inline/http_parser.c -o $@

$(UNIT_BUILD_DIR)/test_inline_logging: tests/unit/test_inline_logging.c src/inline/logging.c src/inline/logging.h src/inline/http_parser.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_inline_logging.c src/inline/logging.c -o $@

$(UNIT_BUILD_DIR)/test_inline_mini_ips_pcre2: check_pcre tests/unit/test_inline_mini_ips_pcre2.c src/inline/mini_ips_pcre2.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine_pcre2.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) tests/unit/test_inline_mini_ips_pcre2.c src/inline/mini_ips_pcre2.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine_pcre2.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c -o $@ $(LDFLAGS) $(PCRE_LIBS) -pthread

$(UNIT_BUILD_DIR)/test_inline_mini_ips_hs: tests/unit/test_inline_mini_ips_hs.c src/inline/mini_ips_hs.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine_hs.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(HS_CFLAGS) $(CFLAGS) tests/unit/test_inline_mini_ips_hs.c src/inline/mini_ips_hs.c src/inline/logging.c src/inline/tproxy.c src/inline/blocking.c src/inline/detect.c src/inline/engine_hs.c src/inline/http_parser.c src/inline/decoding.c src/inline/normalization.c src/inline/regex.c src/inline/ring.c -o $@ $(LDFLAGS) $(HS_LIBS) -pthread

$(UNIT_BUILD_DIR)/test_inline_normalization: tests/unit/test_inline_normalization.c src/inline/normalization.c src/inline/normalization.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_inline_normalization.c src/inline/normalization.c -o $@

$(UNIT_BUILD_DIR)/test_inline_regex: tests/unit/test_inline_regex.c src/inline/regex.c src/inline/regex.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_inline_regex.c src/inline/regex.c -o $@

$(UNIT_BUILD_DIR)/test_inline_ring: tests/unit/test_inline_ring.c src/inline/ring.c src/inline/ring.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_inline_ring.c src/inline/ring.c -o $@

$(UNIT_BUILD_DIR)/test_inline_tproxy: tests/unit/test_inline_tproxy.c src/inline/tproxy.c src/inline/tproxy.h $(TEST_COMMON_DIR)/unit_test.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit/test_inline_tproxy.c src/inline/tproxy.c -o $@

$(PACKET_RING_BENCH_BINS): $(BENCH_BUILD_DIR)/%: $(BENCH_DIR)/%.c $(SRC_DIR)/packet_ring.c $(INC_DIR)/packet_ring.h | $(BENCH_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(SRC_DIR)/packet_ring.c -o $@ $(LDFLAGS) -pthread $(LDLIBS)

check_pcre:
	@printf '#define PCRE2_CODE_UNIT_WIDTH 8\n#include <pcre2.h>\nint main(void){return 0;}\n' | \
		$(CC) -x c - $(CPPFLAGS) $(PCRE_CFLAGS) -o $(PCRE_CHECK_BIN) $(LDFLAGS) $(PCRE_LIBS) >/dev/null 2>&1 || \
		( \
			echo "pcre2.h not found."; \
			if [ "$(AUTO_INSTALL_DEPS)" = "1" ]; then \
				if command -v brew >/dev/null 2>&1; then \
					echo "Auto-installing with brew..."; \
					brew install pcre2; \
				elif command -v apt-get >/dev/null 2>&1; then \
					echo "Auto-installing with apt-get..."; \
					sudo apt-get update && sudo apt-get install -y libpcre2-dev; \
				else \
					echo "No supported package manager found. Install manually."; \
					exit 1; \
				fi; \
			else \
				echo "AUTO_INSTALL_DEPS=0, install manually."; \
				exit 1; \
			fi; \
			printf '#define PCRE2_CODE_UNIT_WIDTH 8\n#include <pcre2.h>\nint main(void){return 0;}\n' | \
				$(CC) -x c - $(CPPFLAGS) $(PCRE_CFLAGS) -o $(PCRE_CHECK_BIN) $(LDFLAGS) $(PCRE_LIBS) >/dev/null 2>&1 || \
				( echo "pcre2.h still not found after install attempt."; exit 1; ); \
		)
	@rm -f $(PCRE_CHECK_BIN)

clean:
	rm -rf $(BUILD_DIR) $(LOG_DIR)
