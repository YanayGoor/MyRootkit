obj-m := src/main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(pwd) clean

test:
	sudo dmesg -C
	sudo insmod src/main.ko
	sudo rmmod main
	dmesg
