TARGET := gdev_stub
$(TARGET)-y := gdev_drv.o gdev_fops.o gdev_ioctl.o gdev_proc.o gdev_api_stub.o gdev_device_stub.o
$(TARGET)-y += fh_kernel.o

obj-m := $(TARGET).o
ifneq ($(KERNELRELEASE),)
else
PWD	:= $(shell pwd)
VPATH := $(PWD) $(PWD)/../../common $(PWD)/../../util
endif

ifndef LINUX_DIR
LINUX_DIR	:= /lib/modules/$(shell uname -r)/build
endif

include $(PWD)/Driver.mk # export $(DRIVER_NAME)

SYSSRC = $(LINUX_DIR)

GDEVDIR = /usr/local/gdev
GDEVINC = $(GDEVDIR)/include
GDEVETC = $(GDEVDIR)/etc

ifeq ($(wildcard ($(SYSSRC)/drivers/gpu/drm/nouveau/gdev_interface.h)),)
	GDEV_INTERFACE = $(SYSSRC)/drivers/gpu/drm/nouveau
else
	GDEV_INTERFACE = $(GDEVDIR)/$(DRIVER_NAME)
	KBUILD_EXTRA_SYMBOLS = $(GDEV_INTERFACE)/Module.symvers
endif

EXTRA_CFLAGS = -Iinclude/drm -I$(GDEV_INTERFACE) -DGDEV_SCHED_DISABLED -Wno-unused-function  -Wno-declaration-after-statement -Wno-format  -I$(PWD) -I$(PWD)/../../common -I$(PWD)/../../util -Wno-unused-value
CFLAGS +=
all: headers
	$(MAKE) -C $(SYSSRC) M=$(PWD) modules ENABLE_WARN_DEPRECATED=1 modules

clean:
	rm ../../common/*.o || true
	+$(MAKE) -C $(SYSSRC) M=$(PWD) clean
	rm -f *~

headers:
	mkdir -p ../headers
	cp ../../common/gdev_api.h gdev_autogen.h \
  ../../common/gdev_ioctl_def.h ../../util/gdev_platform.h \
  ../../common/gdev_nvidia_def.h ../../common/gdev_list.h ../../common/gdev_time.h ./fh_def.h \
  ./gdev_ioctl_debug.h ../headers
