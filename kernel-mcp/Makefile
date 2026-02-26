obj-m += kernel_mcp.o
kernel_mcp-y := src/kernel_mcp_main.o

ccflags-y += -I$(src)/include/uapi

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(CURDIR)

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

