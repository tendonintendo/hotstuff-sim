CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -g -MMD -MP
LDFLAGS =
LDLIBS  = -lcrypto

TARGET = hotstuff-sim
SRCS   = main.c block.c helpers.c chain.c
OBJS   = $(SRCS:%.c=bin/%.o)
DEPS   = $(OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
		$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

bin/%.o: %.c
		mkdir -p $(@D)
		$(CC) $(CFLAGS) -c $< -o $@

asan: clean
		$(MAKE) CFLAGS="$(CFLAGS) -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address"

clean:
		rm -rf bin/ $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)

.PHONY: all asan clean