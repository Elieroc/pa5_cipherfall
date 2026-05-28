obj-m += rootkit.o

KVER  ?= $(shell uname -r)
KDIR  ?= $(shell \
	for d in \
		/lib/modules/$(KVER)/build \
		/usr/src/linux-headers-$(KVER) \
		/usr/src/linux-$(KVER) \
		/usr/lib/modules/$(KVER)/build; do \
		[ -f "$$d/Makefile" ] && echo "$$d" && break; \
	done)
PWD   := $(shell pwd)

all:
	@test -n "$(KDIR)" || (echo "ERROR: kernel headers not found for $(KVER)" && exit 1)
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	@test -n "$(KDIR)" || (echo "ERROR: kernel headers not found for $(KVER)" && exit 1)
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod rootkit.ko

unload:
	sudo rmmod rootkit
