CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

SRCS := bot.c
OBJS := $(SRCS:.c=.o)
TARGET := bot

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
