INCLUDES = -I. -I$(KDIR)/include
MODULE := xhr
obj-m := $(MODULE).o
$(MODULE)-objs += module_entry.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

CFLAGS_module_entry.o = -I$(src)

.PHONY: all
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean


