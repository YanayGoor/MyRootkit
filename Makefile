# Module name
ROOTKIT		    := rootkit

# Linux kernel files
MODULEDIR	    := /lib/modules/$(shell uname -r)
BUILDDIR	    := $(MODULEDIR)/build

# Module Headers
# HEADERS	        := src/headers
# ccflags-y	    := -I$(HEADERS)

# Module Sources
$(ROOTKIT)-y 	+= src/main.o
$(ROOTKIT)-y 	+= src/networking.o

# Module output
obj-m           := $(ROOTKIT).o

all:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) clean

watch:
	sudo dmesg -C
	dmesg -w

test:
	sudo dmesg -C
	sudo insmod ${ROOTKIT}.ko
	dmesg -w
