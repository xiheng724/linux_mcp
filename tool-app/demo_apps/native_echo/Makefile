BIN_DIR := bin
BIN := $(BIN_DIR)/native_echo
# Second build with a different embedded tag so the on-disk binary has
# a distinct SHA-256; the binary-replacement smoke test swaps this file
# in to reliably trigger the kernel TOFU mismatch guard.
BIN_SWAP := $(BIN_DIR)/native_echo_swap

CFLAGS ?= -O2 -Wall -Wextra -std=c11

.PHONY: all clean

all: $(BIN) $(BIN_SWAP)

$(BIN): main.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -DBUILD_TAG=\"v1\" -o $@ main.c

$(BIN_SWAP): main.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -DBUILD_TAG=\"v2-swap\" -o $@ main.c

$(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(BIN_DIR)
