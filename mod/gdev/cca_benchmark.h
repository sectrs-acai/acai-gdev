#ifndef GDEV_GUEST_MOD_GDEV_CCA_BENCHMARK_H_
#define GDEV_GUEST_MOD_GDEV_CCA_BENCHMARK_H_

#define STR(s) #s
#define CCA_MARKER(marker) __asm__ volatile("MOV XZR, " STR(marker))

#define CCA_MARKER_DMA_PAGE_READ(pages_nr) \
for(unsigned long i = 0; i < pages_nr; i ++) { \
CCA_MARKER(0x100); \
}

#define CCA_MARKER_DMA_PAGE_WRITE(pages_nr) \
for(unsigned long i = 0; i < pages_nr; i ++) { \
CCA_MARKER(0x101); \
}

#define CCA_MARKER_MMAP_PAGE(pages_nr) \
for(unsigned long i = 0; i < pages_nr; i ++) { \
CCA_MARKER(0x102); \
}

#define CCA_MARKER_DMA_PAGE_ALLOC(pages_nr) \
for(unsigned long i = 0; i < pages_nr; i ++) { \
CCA_MARKER(0x103); \
}

#endif
