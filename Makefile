CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -g -MMD -MP
LDFLAGS =
LDLIBS  = -lsodium
ASAN    = -fsanitize=address -fno-omit-frame-pointer
NVCC    = nvcc
NVFLAGS = -arch=sm_120 -O2
CUDA_HOME = /usr/local/cuda
CUDA_LIBS = -L$(CUDA_HOME)/lib64 -lcudart -lstdc++

BUILD  = bin
TARGET = hotstuff-sim
SRCS   = main.c block.c helpers.c chain.c tx.c state.c merkle.c encode.c prng.c event.c sim.c node.c
OBJS   = $(SRCS:%.c=$(BUILD)/%.o)
TEST_SRCS = tests/test_main.c
TEST_OBJS = $(TEST_SRCS:%.c=$(BUILD)/%.o) $(filter-out $(BUILD)/main.o,$(OBJS))
TEST_BIN  = $(BUILD)/test_runner
GPU_TEST_SRCS = cuda/test_gpu_hash.c
GPU_TEST_OBJS = $(GPU_TEST_SRCS:%.c=$(BUILD)/%.o) $(BUILD)/cuda/gpu_hash.o $(filter-out $(BUILD)/main.o,$(OBJS))
GPU_TEST_BIN  = $(BUILD)/test_gpu_hash

DEPS   = $(OBJS:.o=.d) $(TEST_SRCS:%.c=$(BUILD)/%.d) $(GPU_TEST_SRCS:%.c=$(BUILD)/%.d)

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

cuda: $(BUILD)/vecadd

$(BUILD)/vecadd: cuda/vecadd.cu
		mkdir -p $(@D)
		$(NVCC) $(NVFLAGS) $< -o $@

cuda-test: $(GPU_TEST_BIN)
		./$(GPU_TEST_BIN)

$(GPU_TEST_BIN): $(GPU_TEST_OBJS)
		$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS) $(CUDA_LIBS)

$(BUILD)/cuda/gpu_hash.o: cuda/gpu_hash.cu cuda/gpu_hash.h cuda/sha256.cuh
		mkdir -p $(@D)
		$(NVCC) $(NVFLAGS) -c $< -o $@

clean:
		rm -rf bin/ $(TARGET)

-include $(DEPS)

.PHONY: all asan clean cuda cuda-test test test-asan
