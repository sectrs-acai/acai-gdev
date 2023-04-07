# Makefile
TARGET	= user_test
CC=$(CROSS_COMPILE)gcc
NVCC	= nvcc -arch sm_20 -cubin

LIBS	+= -L$(STAGING_DIR)/usr/local/gdev/lib64/ -lucuda -lgdev
CFLAGS	+= -I$(STAGING_DIR)/usr/local/gdev/include


all: gcc

nvcc:
	$(NVCC) -o madd_gpu.cubin madd_gpu.cu
gcc:
	$(CC) -o $(TARGET) $(CFLAGS) main.c madd_host.c $(LIBS)

clean:
	rm -f $(TARGET) *.cubin ./*~
