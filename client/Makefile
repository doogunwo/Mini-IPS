CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

SRCS := benchmark.c
OBJS := $(SRCS:.c=.o)
TARGET := benchmark

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
