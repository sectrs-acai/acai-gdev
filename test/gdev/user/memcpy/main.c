#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DATA_END 0x10000000 /* 256MB */
#define DATA_START DATA_END // 0x400000 /* 4MB */
#define CHUNK_END 0x2000000 /* 32MB */
#define CHUNK_START 0x10000 /* 64KB */
#define PIPELINE_END 4
#define PIPELINE_START 4

int gdev_test_memcpy(uint32_t *in, uint32_t *out, uint32_t size, 
					 uint32_t chunk_size, int pipeline_count);

int main(int argc, char *argv[])
{
	uint32_t *in, *out;
	uint32_t size = 0x10000000;
	uint32_t ch_size = 0x40000; /* 0x200000 is best */
	int pl = 2;
	int i, tmp;

	for (i = 1; i < argc; i++) {
		if (strncmp(argv[i], "--chunk", (tmp = strlen("--chunk"))) == 0) {
			if (argv[i][tmp] != '=') {
				printf("option \"%s\" is invalid.\n", argv[i]);
				exit(1);
			}
			sscanf(&argv[i][tmp+1], "%x", &ch_size);
		}
		else if (strncmp(argv[i], "--data", (tmp = strlen("--data"))) == 0) {
			if (argv[i][tmp] != '=') {
				printf("option \"%s\" is invalid.\n", argv[i]);
				exit(1);
			}
			sscanf(&argv[i][tmp+1], "%x", &size);
		}
		else if (strncmp(argv[i], "--pl", (tmp = strlen("--pl"))) == 0) {
			if (argv[i][tmp] != '=') {
				printf("option \"%s\" is invalid.\n", argv[i]);
				exit(1);
			}
			sscanf(&argv[i][tmp+1], "%d", &pl);
		}
	}

	in = (uint32_t *) malloc(size);
	out = (uint32_t *) malloc(size);
	for (i = 0; i < size / 4; i++) {
		in[i] = i+1;
		out[i] = 0;
	}
	
	gdev_test_memcpy(in, out, size, ch_size, pl);
	
	for (i = 0; i < size / 4; i++) {
		if (in[i] != out[i]) {
			printf("in[%d] = %lu, out[%d] = %lu\n",
				   i, in[i], i, out[i]);
			printf("Test failed.\n");
			goto end;
		}
	}
	free(in);
	free(out);

	return 0;

end:
	free(in);
	free(out);
	
	return 0;
}