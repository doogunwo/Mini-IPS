CC := gcc
CFLAGS := -O2 -Wall -Wextra -std=c11
CPPFLAGS := -I./ips

TARGETS :=
UNIT_SRCS := $(wildcard units/test_*.c)
UNIT_BINS := $(patsubst units/%.c,units/%,$(UNIT_SRCS))
UNIT_LOGS := $(patsubst units/%.c,units/%.log,$(UNIT_SRCS))

.PHONY: all clean units

all: units

units: $(UNIT_LOGS)
	@echo "units: all tests passed"

units/test_%: units/test_%.c ips/project_rst.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

units/test_%.log: units/test_%
	@echo "[units] running $<"
	@./$< > $@ 2>&1

clean:
	rm -f $(UNIT_BINS) $(UNIT_LOGS)
