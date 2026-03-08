CC := gcc
CFLAGS := -O2 -Wall -Wextra -std=c11
CPPFLAGS := -Iinclude
LDFLAGS :=
LDLIBS :=
PCRE_CFLAGS = $(shell \
	if command -v pkg-config >/dev/null 2>&1; then \
		pkg-config --cflags libpcre 2>/dev/null; \
	elif command -v pcre-config >/dev/null 2>&1; then \
		pcre-config --cflags 2>/dev/null; \
	elif command -v brew >/dev/null 2>&1; then \
		echo -I$$(brew --prefix pcre 2>/dev/null)/include; \
	fi \
)
PCRE_LIBS = $(shell \
	if command -v pkg-config >/dev/null 2>&1; then \
		pkg-config --libs libpcre 2>/dev/null; \
	elif command -v pcre-config >/dev/null 2>&1; then \
		pcre-config --libs 2>/dev/null; \
	elif command -v brew >/dev/null 2>&1; then \
		echo -L$$(brew --prefix pcre 2>/dev/null)/lib -lpcre; \
	fi \
)
PCRE_CHECK_BIN := /tmp/ips_pcre_check
AUTO_INSTALL_DEPS ?= 0

SRC_DIR := src
INC_DIR := include
TEST_DIR := tests
BUILD_DIR := build
LOG_DIR := logs

MAIN_BIN := $(BUILD_DIR)/main

APP_SRCS := $(SRC_DIR)/main.c \
	$(SRC_DIR)/driver.c \
	$(SRC_DIR)/httgw.c \
	$(SRC_DIR)/http_stream.c \
	$(SRC_DIR)/detect.c \
	$(SRC_DIR)/regex.c

UNIT_SRCS := $(wildcard $(TEST_DIR)/test_*.c)
UNIT_NAMES := $(notdir $(basename $(UNIT_SRCS)))
UNIT_BINS := $(addprefix $(BUILD_DIR)/,$(UNIT_NAMES))
UNIT_LOGS := $(addprefix $(LOG_DIR)/,$(addsuffix .log,$(UNIT_NAMES)))

.PHONY: all clean run units main check_pcre

all: units $(MAIN_BIN)

main: $(MAIN_BIN)

$(BUILD_DIR) $(LOG_DIR):
	mkdir -p $@

$(MAIN_BIN): check_pcre $(APP_SRCS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(PCRE_CFLAGS) $(CFLAGS) $(APP_SRCS) -o $@ $(LDFLAGS) -lpcap $(PCRE_LIBS) -pthread $(LDLIBS)

run: all
	./$(MAIN_BIN)

units: $(UNIT_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(UNIT_BINS); do \
		echo "[units] running $$t"; \
		./$$t > $(LOG_DIR)/$$(basename $$t).log 2>&1; \
	done
	@echo "units: all tests passed"

$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c $(INC_DIR)/httgw.h $(INC_DIR)/http_stream.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(SRC_DIR)/httgw.c $(SRC_DIR)/http_stream.c -o $@ $(LDFLAGS) -lpcap $(LDLIBS)

check_pcre:
	@printf '#include <pcre.h>\nint main(void){return 0;}\n' | \
		$(CC) -x c - $(CPPFLAGS) $(PCRE_CFLAGS) -o $(PCRE_CHECK_BIN) $(LDFLAGS) $(PCRE_LIBS) >/dev/null 2>&1 || \
		( \
			echo "pcre.h not found."; \
			if [ "$(AUTO_INSTALL_DEPS)" = "1" ]; then \
				if command -v brew >/dev/null 2>&1; then \
					echo "Auto-installing with brew..."; \
					brew install pcre; \
				elif command -v apt-get >/dev/null 2>&1; then \
					echo "Auto-installing with apt-get..."; \
					sudo apt-get update && sudo apt-get install -y libpcre3-dev; \
				else \
					echo "No supported package manager found. Install manually."; \
					exit 1; \
				fi; \
			else \
				echo "AUTO_INSTALL_DEPS=0, install manually."; \
				exit 1; \
			fi; \
			printf '#include <pcre.h>\nint main(void){return 0;}\n' | \
				$(CC) -x c - $(CPPFLAGS) $(PCRE_CFLAGS) -o $(PCRE_CHECK_BIN) $(LDFLAGS) $(PCRE_LIBS) >/dev/null 2>&1 || \
				( echo "pcre.h still not found after install attempt."; exit 1; ); \
		)
	@rm -f $(PCRE_CHECK_BIN)

clean:
	rm -rf $(BUILD_DIR) $(LOG_DIR)
