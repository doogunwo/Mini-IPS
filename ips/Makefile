CC := gcc
CFLAGS := -O2 -Wall -Wextra -std=c11
CPPFLAGS := -Iinclude
LDFLAGS :=
LDLIBS :=
VALGRIND ?= valgrind
VALGRIND_FLAGS ?= --leak-check=full --show-leak-kinds=all --track-origins=yes
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
BUILD_DIR := build
LOG_DIR := logs

MAIN_BIN := $(BUILD_DIR)/main
REGEX_COMPAT_BIN := $(BUILD_DIR)/test_regex_compat
DETECT_ENGINE_BIN := $(BUILD_DIR)/test_detect_engine
HTTP_LIVE_LIKE_REASM_BIN := $(BUILD_DIR)/test_http_live_like_reasm
BOT_URL_DETECT_BIN := $(BUILD_DIR)/test_bot_url_detect

APP_SRCS := $(SRC_DIR)/main.c \
	$(SRC_DIR)/logging.c \
	$(SRC_DIR)/runtime.c \
	$(SRC_DIR)/driver.c \
	$(SRC_DIR)/httgw.c \
	$(SRC_DIR)/http_stream.c \
	$(SRC_DIR)/engine.c \
	$(SRC_DIR)/detect.c \
	$(SRC_DIR)/regex.c

UNIT_SRCS := $(wildcard $(TEST_DIR)/test_*.c)
UNIT_NAMES := $(notdir $(basename $(UNIT_SRCS)))
UNIT_BINS := $(addprefix $(BUILD_DIR)/,$(UNIT_NAMES))
UNIT_LOGS := $(addprefix $(LOG_DIR)/,$(addsuffix .log,$(UNIT_NAMES)))
UNIT_VG_LOGS := $(addprefix $(LOG_DIR)/,$(addsuffix .valgrind.log,$(UNIT_NAMES)))
MAIN_VG_LOG := $(LOG_DIR)/main.valgrind.log

.PHONY: all clean run units main check_pcre valgrind-units valgrind-main regex-compat test-detect-engine test-http-live-like-reasm test-bot-url-detect

all: units $(MAIN_BIN)

main: $(MAIN_BIN)

regex-compat: $(REGEX_COMPAT_BIN)
	./$(REGEX_COMPAT_BIN)

$(BUILD_DIR) $(LOG_DIR):
	mkdir -p $@

$(MAIN_BIN): check_pcre $(APP_SRCS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) $(APP_SRCS) -o $@ $(LDFLAGS) -lpcap $(PCRE_LIBS) $(HS_LIBS) -pthread $(LDLIBS)

$(REGEX_COMPAT_BIN): $(TEST_DIR)/test_regex_compat.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) $(PCRE_LIBS) $(HS_LIBS) $(LDLIBS)

$(DETECT_ENGINE_BIN): check_pcre $(TEST_DIR)/test_detect_engine.c \
	$(SRC_DIR)/runtime.c $(SRC_DIR)/logging.c $(SRC_DIR)/detect.c \
	$(SRC_DIR)/engine.c $(SRC_DIR)/regex.c $(SRC_DIR)/httgw.c \
	$(SRC_DIR)/http_stream.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) \
		$(TEST_DIR)/test_detect_engine.c $(SRC_DIR)/runtime.c \
		$(SRC_DIR)/logging.c $(SRC_DIR)/detect.c $(SRC_DIR)/engine.c \
		$(SRC_DIR)/regex.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c \
		-o $@ $(LDFLAGS) -lpcap $(PCRE_LIBS) $(HS_LIBS) -pthread $(LDLIBS)

$(HTTP_LIVE_LIKE_REASM_BIN): $(TEST_DIR)/test_http_live_like_reasm.c \
	$(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) \
		$(TEST_DIR)/test_http_live_like_reasm.c $(SRC_DIR)/httgw.c \
		$(SRC_DIR)/http_stream.c -o $@ $(LDFLAGS) -lpcap $(LDLIBS)

$(BOT_URL_DETECT_BIN): check_pcre $(TEST_DIR)/test_bot_url_detect.c \
	$(SRC_DIR)/runtime.c $(SRC_DIR)/logging.c $(SRC_DIR)/detect.c \
	$(SRC_DIR)/engine.c $(SRC_DIR)/regex.c $(SRC_DIR)/httgw.c \
	$(SRC_DIR)/http_stream.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(HS_CFLAGS) $(CFLAGS) \
		$(TEST_DIR)/test_bot_url_detect.c $(SRC_DIR)/runtime.c \
		$(SRC_DIR)/logging.c $(SRC_DIR)/detect.c $(SRC_DIR)/engine.c \
		$(SRC_DIR)/regex.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c \
		-o $@ $(LDFLAGS) -lpcap $(PCRE_LIBS) $(HS_LIBS) -pthread $(LDLIBS)

test-detect-engine: $(DETECT_ENGINE_BIN)
	./$(DETECT_ENGINE_BIN)

test-http-live-like-reasm: $(HTTP_LIVE_LIKE_REASM_BIN)
	./$(HTTP_LIVE_LIKE_REASM_BIN)

test-bot-url-detect: $(BOT_URL_DETECT_BIN)
	./$(BOT_URL_DETECT_BIN)

run: all
	./$(MAIN_BIN)

units: $(UNIT_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(UNIT_BINS); do \
		echo "[units] running $$t"; \
		./$$t > $(LOG_DIR)/$$(basename $$t).log 2>&1; \
	done
	@echo "units: all tests passed"

valgrind-units: $(UNIT_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(UNIT_BINS); do \
		echo "[valgrind] running $$t"; \
		$(VALGRIND) $(VALGRIND_FLAGS) --log-file=$(LOG_DIR)/$$(basename $$t).valgrind.log ./$$t; \
	done
	@echo "valgrind: all unit tests passed"

valgrind-main: $(MAIN_BIN) | $(LOG_DIR)
	$(VALGRIND) $(VALGRIND_FLAGS) --log-file=$(MAIN_VG_LOG) ./$(MAIN_BIN) $(RUN_ARGS)

$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c $(INC_DIR)/httgw.h $(INC_DIR)/http_stream.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c -o $@ $(LDFLAGS) -lpcap $(LDLIBS)

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
