CC := gcc
CFLAGS := -O2 -Wall -Wextra -std=c11
CPPFLAGS := -I./ips
VALGRIND ?= valgrind
VALGRIND_FLAGS ?= --leak-check=full --show-leak-kinds=all --track-origins=yes

TARGETS :=
UNIT_SRCS := $(wildcard units/test_*.c)
UNIT_BINS := $(patsubst units/%.c,units/%,$(UNIT_SRCS))
UNIT_LOGS := $(patsubst units/%.c,units/%.log,$(UNIT_SRCS))

.PHONY: all clean units valgrind-units

all: units

units: $(UNIT_LOGS)
	@echo "units: all tests passed"

valgrind-units: $(UNIT_BINS)
	@set -e; \
	for t in $(UNIT_BINS); do \
		echo "[valgrind] running $$t"; \
		$(VALGRIND) $(VALGRIND_FLAGS) --log-file=$$t.valgrind.log ./$$t; \
	done
	@echo "valgrind: all tests passed"

units/test_%: units/test_%.c ips/project_rst.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

units/test_%.log: units/test_%
	@echo "[units] running $<"
	@./$< > $@ 2>&1

clean:
	rm -f $(UNIT_BINS) $(UNIT_LOGS) units/*.valgrind.log
