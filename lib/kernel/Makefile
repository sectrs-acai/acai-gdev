# Makefile

CC      ?= $(CROSS_COMPILE)gcc
TARGET	= libgdev
CFLAGS	+= -O3 -Wall
GDEVDIR	?= /usr/local/gdev
HEADERS	= ../../common/gdev_api.h ../../common/gdev_nvidia_def.h ../../common/gdev_list.h ../../common/gdev_time.h ../../common/gdev_ioctl_def.h
CFLAGS	+=

#OBJS 	= $(patsubst %.c,%.o,$(wildcard ./*.c))
OBJS 	= gdev_lib.o
ZOMBIE  = $(wildcard ./*~)

all: $(OBJS)
	$(CC) -shared -Wl,-soname,$(TARGET).so.1 -o ./$(TARGET).so.1.0.0 $(OBJS)
	$(AR) rcs $(TARGET).a $(OBJS)

%.o:%.c
	$(CC) -I./../../common -I./../../util -fPIC -c $^ -o $@
	echo $(CFLAGS)

install:
	@if test ! -d $(GDEVDIR) ; then mkdir -p $(GDEVDIR) ; fi ;
	@if test ! -d $(GDEVDIR)/lib64 ; then mkdir -p $(GDEVDIR)/lib64 ; fi ;
	@if test ! -d $(GDEVDIR)/include ; then mkdir -p $(GDEVDIR)/include ; fi ;
	cp -f ./$(TARGET).so.1.0.0 $(GDEVDIR)/lib64/
	cp -f ./$(TARGET).a $(GDEVDIR)/lib64/
	cd $(GDEVDIR)/lib64/ && ln -s --relative -sf $(TARGET).so.1.0.0 $(TARGET).so.1 || true
	cd $(GDEVDIR)/lib64/ && ln -s --relative -sf $(TARGET).so.1 $(TARGET).so || true
	cp -f $(HEADERS) $(GDEVDIR)/include
	@make echo

uninstall:
	rm -f $(GDEVDIR)/lib64/$(TARGET).*
	rm -f $(GDEVDIR)/include/gdev*.h

clean:
	rm -f $(TARGET).so.* $(OBJS) $(ZOMBIE) $(TARGET).a rm -f ../../common/*.o ../../util/*.o

echo:
	@echo ---------------------------------------------------------------
	@echo Gdev Library installation was completed! 
	@echo
	@echo *Please make sure your PATH includes /usr/local/gdev/bin
	@echo *Please make sure your LD_LIBRARY_PATH includes /usr/local/gdev/lib64
	@echo 
	@echo Please type follows commands':'
	@echo     export LD_LIBRARY_PATH='"'/usr/local/gdev/lib64:'$$'LD_LIBRARY_PATH'"'
	@echo     export PATH='"'/usr/local/gdev/bin:'$$'PATH'"'
	@echo 
	@echo If you are administrator, write to /etc/ld.so.conf and run ldconfig 
	@echo ---------------------------------------------------------------
