obj-m += asd.o 
 
KDIR := /lib/modules/3.13.0-117-generic/build
PWD ?= $(shell pwd)
 
 
all:
	make -C $(KDIR) M=$(PWD) modules
		
clean:
	rm -rf *.o

