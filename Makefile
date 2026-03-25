CC := gcc
CFLAGS := -O2 -Wall -Wextra -std=c11
CPPFLAGS := -I./ips/include
VALGRIND ?= valgrind
VALGRIND_FLAGS ?= --leak-check=full --show-leak-kinds=all --track-origins=yes

UNIT_SRCS := $(wildcard ips/units/*.c)
LIVE_UNIT_SRCS := $(filter %_live.c,$(UNIT_SRCS))
UNIT_SRCS := $(filter-out %_live.c,$(UNIT_SRCS))
UNIT_NAMES := $(notdir $(basename $(UNIT_SRCS)))
LIVE_UNIT_NAMES := $(notdir $(basename $(LIVE_UNIT_SRCS)))
BUILD_DIR := ips/build
UNIT_BUILD_DIR := $(BUILD_DIR)/units
LOG_DIR := ips/logs
UNIT_BINS := $(addprefix $(UNIT_BUILD_DIR)/,$(UNIT_NAMES))
LIVE_UNIT_BINS := $(addprefix $(UNIT_BUILD_DIR)/,$(LIVE_UNIT_NAMES))

.PHONY: all clean units valgrind-units tproxy-live-check

all: units

units: $(UNIT_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(UNIT_BINS); do \
		log="$(LOG_DIR)/$$(basename $$t).log"; \
		echo "[units] running $$t"; \
		./$$t > "$$log" 2>&1; \
	done
	@echo "units: all tests passed"

valgrind-units: $(UNIT_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(UNIT_BINS); do \
		echo "[valgrind] running $$t"; \
		$(VALGRIND) $(VALGRIND_FLAGS) --log-file="$(LOG_DIR)/$$(basename $$t).valgrind.log" ./$$t; \
	done
	@echo "valgrind: all tests passed"

tproxy-live-check: $(LIVE_UNIT_BINS) | $(LOG_DIR)
	@set -e; \
	for t in $(LIVE_UNIT_BINS); do \
		log="$(LOG_DIR)/$$(basename $$t).log"; \
		echo "[live] running $$t"; \
		./$$t > "$$log" 2>&1 || (cat "$$log"; exit 1); \
		cat "$$log"; \
	done

$(UNIT_BUILD_DIR) $(LOG_DIR):
	mkdir -p $@

$(UNIT_BUILD_DIR)/%: ips/units/%.c | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

$(UNIT_BUILD_DIR)/units_tproxy_create: ips/src/inline/tproxy.c ips/include/tproxy.h
$(UNIT_BUILD_DIR)/units_tproxy_create_live: ips/units/units_tproxy_create_live.c ips/src/inline/tproxy.c ips/include/tproxy.h | $(UNIT_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< ips/src/inline/tproxy.c -o $@

clean:
	rm -f $(UNIT_BINS) $(LIVE_UNIT_BINS)
	rm -f $(LOG_DIR)/units_*.log $(LOG_DIR)/units_*.valgrind.log
	rm -f ips/units/units_tproxy_create ips/units/units_tproxy_create_live
