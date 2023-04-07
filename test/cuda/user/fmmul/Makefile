# Makefile for fvp

TARGET	= user_test
CC=$(CROSS_COMPILE)gcc
NVCC	= nvcc -arch sm_20 -cubin
LIBS	+= -L$(STAGING_DIR)/usr/local/gdev/lib64/ -lucuda -lgdev
CFLAGS	+= -I$(STAGING_DIR)/usr/local/gdev/include


all: nvcc gcc

nvcc:
	$(NVCC) -o fmmul_gpu.cubin fmmul_gpu.cu

gcc:
	$(CC) -o $(TARGET) $(CFLAGS) main.c fmmul.c $(LIBS)

clean:
	rm -f $(TARGET) *.cubin ./*~
