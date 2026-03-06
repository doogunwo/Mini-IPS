CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
CFLAGS += -Itests

SRCS := bot.c $(wildcard tests/*.c)
OBJS := $(SRCS:.c=.o)
TARGET := bot

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
