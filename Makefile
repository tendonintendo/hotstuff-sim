CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -g -MMD -MP
LDFLAGS =
LDLIBS  = -lsodium
ASAN    = -fsanitize=address -fno-omit-frame-pointer

BUILD  = bin
TARGET = hotstuff-sim
SRCS   = main.c block.c helpers.c chain.c tx.c state.c merkle.c encode.c prng.c event.c sim.c node.c
OBJS   = $(SRCS:%.c=$(BUILD)/%.o)
TEST_SRCS = tests/test_main.c
TEST_OBJS = $(TEST_SRCS:%.c=$(BUILD)/%.o) $(filter-out $(BUILD)/main.o,$(OBJS))
TEST_BIN  = $(BUILD)/test_runner

DEPS   = $(OBJS:.o=.d) $(TEST_SRCS:%.c=$(BUILD)/%.d)

all: $(TARGET)

$(TARGET): $(OBJS)
		$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD)/%.o: %.c
		mkdir -p $(@D)
		$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_BIN)
		./$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJS)
		$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

asan:
		$(MAKE) BUILD=bin/asan TARGET=bin/asan/hotstuff-sim CFLAGS="$(CFLAGS) $(ASAN)" LDFLAGS="-fsanitize=address"

test-asan:
		$(MAKE) test BUILD=bin/asan CFLAGS="$(CFLAGS) $(ASAN)" LDFLAGS="-fsanitize=address"

clean:
		rm -rf bin/ $(TARGET)

-include $(DEPS)

.PHONY: all asan clean test test-asan
