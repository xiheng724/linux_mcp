CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror

UAPI_DIR := ../kernel-mcp/include/uapi
BIN_DIR := bin
TARGETS := genl_ping genl_register_capability genl_register_participant genl_capability_request genl_capability_complete
BINS := $(addprefix $(BIN_DIR)/,$(TARGETS))

.PHONY: all clean

all: $(BINS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/%: %.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(UAPI_DIR) -o $@ $<

clean:
	rm -f $(BINS)
	rmdir --ignore-fail-on-non-empty $(BIN_DIR) 2>/dev/null || true
