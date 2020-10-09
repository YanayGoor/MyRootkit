obj-m := src/main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(pwd) clean

watch:
	sudo dmesg -C
	dmesg -w

test:
	sudo dmesg -C
	sudo insmod src/main.ko
	dmesg -w
