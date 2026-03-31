CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror

UAPI_DIR := ../kernel-mcp/include/uapi
BIN_DIR := bin
TARGETS := genl_register_tool genl_list_tools
BINS := $(addprefix $(BIN_DIR)/,$(TARGETS))

.PHONY: all clean

all: $(BINS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/%: %.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(UAPI_DIR) -o $@ $<

clean:
	rm -f $(BIN_DIR)/genl_*
	rmdir --ignore-fail-on-non-empty $(BIN_DIR)
