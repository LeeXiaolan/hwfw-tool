ifneq ($(KERNELRELEASE),)
ifneq ($(KERNELRELEASE),2.6.34.10_sd5115v100_wr4.3)
  $(error "KERNELRELEASE" must be "2.6.34.10_sd5115v100_wr4.3")
endif
obj-m := hijack.o
else
ifeq ($(CROSS_COMPILE),)
	$(error Set CROSS_COMPILE env first)
endif
ifeq ($(KERNEL_DIR),)
	$(error Set KERNEL_DIR env first)
endif

PWD := $(shell pwd)

hijack:
	$(MAKE) ARCH=arm -C $(KERNEL_DIR) M=$(PWD)
endif
