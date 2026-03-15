ifneq ($(KERNELRELEASE),)
obj-m += kernel_mcp.o
kernel_mcp-y := src/kernel_mcp_main.o

ccflags-y += -I$(src)/include/uapi
else
KDIR ?= /lib/modules/$(shell uname -r)/build
MODULE_DIR := $(CURDIR)
OUT_DIR ?= $(MODULE_DIR)/out
LEGACY_OUTPUTS := \
	$(MODULE_DIR)/Module.symvers \
	$(MODULE_DIR)/modules.order \
	$(MODULE_DIR)/kernel_mcp.ko \
	$(MODULE_DIR)/kernel_mcp.mod \
	$(MODULE_DIR)/kernel_mcp.mod.c \
	$(MODULE_DIR)/kernel_mcp.mod.o \
	$(MODULE_DIR)/kernel_mcp.o \
	$(MODULE_DIR)/.Module.symvers.cmd \
	$(MODULE_DIR)/.kernel_mcp.ko.cmd \
	$(MODULE_DIR)/.kernel_mcp.mod.cmd \
	$(MODULE_DIR)/.kernel_mcp.mod.o.cmd \
	$(MODULE_DIR)/.kernel_mcp.o.cmd \
	$(MODULE_DIR)/.modules.order.cmd \
	$(MODULE_DIR)/src/kernel_mcp_main.o \
	$(MODULE_DIR)/src/.kernel_mcp_main.o.cmd

.PHONY: all clean

all: $(OUT_DIR)
	$(MAKE) -C $(KDIR) M=$(MODULE_DIR) modules
	mkdir -p "$(OUT_DIR)/src"
	for output in $(LEGACY_OUTPUTS); do \
		if [ -e "$$output" ]; then mv "$$output" "$(OUT_DIR)$${output#$(MODULE_DIR)}"; fi; \
	done

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

clean:
	$(MAKE) -C $(KDIR) M=$(MODULE_DIR) clean
	rm -rf "$(OUT_DIR)"
	rm -f $(LEGACY_OUTPUTS)
endif
