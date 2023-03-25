# Makefile
TARGET	= user_test
CC=$(CROSS_COMPILE)gcc
NVCC	= nvcc -arch sm_20 -cubin
LIBS	= -lucuda -lgdev
CFLAGS	= -L /usr/local/gdev/lib64 -I /usr/local/gdev/include

nvcc:
	$(NVCC) -ccbin /usr/local/cuda/bin -o madd_gpu.cubin madd_gpu.cu
gcc:
	gcc -o $(TARGET) $(CFLAGS) main.c madd.c $(LIBS)
clean:
	rm -f $(TARGET) *.cubin ./*~
