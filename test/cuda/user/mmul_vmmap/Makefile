# Makefile
TARGET	= user_test
CC=$(CROSS_COMPILE)gcc
NVCC	= nvcc -arch sm_20 -cubin
LIBS	= -lucuda -lgdev
CFLAGS	= -L /usr/local/gdev/lib64 -I /usr/local/gdev/include

all:
	$(NVCC) -o mmul_gpu.cubin mmul_gpu.cu
	gcc -o $(TARGET) $(CFLAGS) main.c mmul_vmmap.c $(LIBS)

clean:
	rm -f $(TARGET) *.cubin ./*~
