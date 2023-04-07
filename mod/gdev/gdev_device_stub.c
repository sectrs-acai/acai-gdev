#include "gdev_api.h"
#include "gdev_device.h"
// #include "gdev_sched.h"
#include "gdev_system.h"
#include "gdev_conf.h"
#define GDEV_PERIOD_DEFAULT 30000 /* microseconds */

int gdev_count = 0; /* # of physical devices. */
int gdev_vcount = 0; /* # of virtual devices. */
struct gdev_device *gdevs = NULL; /* physical devices */
struct gdev_device *gdev_vds = NULL; /* virtual devices */

int VCOUNT_LIST[GDEV_PHYSICAL_DEVICE_MAX_COUNT] = {
        GDEV0_VIRTUAL_DEVICE_COUNT,
        GDEV1_VIRTUAL_DEVICE_COUNT,
        GDEV2_VIRTUAL_DEVICE_COUNT,
        GDEV3_VIRTUAL_DEVICE_COUNT,
        GDEV4_VIRTUAL_DEVICE_COUNT,
        GDEV5_VIRTUAL_DEVICE_COUNT,
        GDEV6_VIRTUAL_DEVICE_COUNT,
        GDEV7_VIRTUAL_DEVICE_COUNT,
};

void __gdev_init_device(struct gdev_device *gdev, int id)
{
}

/* initialize the physical device information. */
int gdev_init_device(struct gdev_device *gdev, int id, void *priv)
{
    return 0;
}

/* finalize the physical device. */
void gdev_exit_device(struct gdev_device *gdev)
{
}

/* initialize the virtual device information. */
int gdev_init_virtual_device(struct gdev_device *gdev, int id, uint32_t weight, struct gdev_device *phys)
{
    return 0;
}

/* finalize the virtual device. */
void gdev_exit_virtual_device(struct gdev_device *gdev)
{
}

/**
 * architecture-dependent compute functions.
 */
int gdev_compute_setup(struct gdev_device *gdev) {
    return 0;
}
uint32_t gdev_launch(gdev_ctx_t *ctx, struct gdev_kernel *kern) {
    return 0;
}
uint32_t gdev_memcpy(gdev_ctx_t *ctx, uint64_t dst_addr, uint64_t src_addr, uint32_t size) {
    return 0;
}
uint32_t gdev_memcpy_async(gdev_ctx_t *ctx, uint64_t dst_addr, uint64_t src_addr, uint32_t size) {
    return 0;
}
uint32_t gdev_read32(gdev_mem_t *mem, uint64_t addr) {
    return 0;
}
void gdev_write32(gdev_mem_t *mem, uint64_t addr, uint32_t val) {
}
int gdev_read(gdev_mem_t *mem, void *buf, uint64_t addr, uint32_t size) {
    return 0;
}
int gdev_write(gdev_mem_t *mem, uint64_t addr, const void *buf, uint32_t size) {
    return 0;
}
int gdev_poll(gdev_ctx_t *ctx, uint32_t seq, struct gdev_time *timeout) {
    return 0;
}
int gdev_barrier(struct gdev_ctx *ctx) {
    return 0;
}
int gdev_query(struct gdev_device *gdev, uint32_t type, uint64_t *result) {
    return 0;
}

/**
 * architecture-dependent resource management functions.
 */
struct gdev_device *gdev_dev_open(int minor) {
    return 0;
}
void gdev_dev_close(struct gdev_device *gdev) {

}
gdev_vas_t *gdev_vas_new(struct gdev_device *gdev, uint64_t size, void *handle) {
    return 0;
}
void gdev_vas_free(gdev_vas_t *vas) {

}
gdev_ctx_t *gdev_ctx_new(struct gdev_device *gdev, gdev_vas_t *vas) {
    return 0;
}
void gdev_ctx_free(gdev_ctx_t *ctx) {

}
int gdev_ctx_get_cid(gdev_ctx_t *ctx) {
    return 0;
}
void gdev_block_start(struct gdev_device *gdev) {

}
void gdev_block_end(struct gdev_device *gdev) {

}
void gdev_access_start(struct gdev_device *gdev) {

}
void gdev_access_end(struct gdev_device *gdev) {

}
void gdev_mem_lock(gdev_mem_t *mem) {

}
void gdev_mem_unlock(gdev_mem_t *mem) {

}
void gdev_mem_lock_all(gdev_vas_t *vas) {

}
void gdev_mem_unlock_all(gdev_vas_t *vas) {

}
gdev_mem_t *gdev_mem_alloc(gdev_vas_t *vas, uint64_t size, int type) {
    return 0;
}
gdev_mem_t *gdev_mem_share(gdev_vas_t *vas, uint64_t size) {
    return 0;
}
void gdev_mem_free(gdev_mem_t *mem) {

}
void gdev_mem_gc(gdev_vas_t *vas) {

}
void *gdev_mem_map(gdev_mem_t *mem, uint64_t offset, uint64_t size) {
    return 0;
}
void gdev_mem_unmap(gdev_mem_t *mem) {

}
gdev_mem_t *gdev_mem_lookup_by_addr(gdev_vas_t *vas, uint64_t addr, int type) {
    return 0;
}
gdev_mem_t *gdev_mem_lookup_by_buf(gdev_vas_t *vas, const void *buf, int type) {
return 0;
}
void *gdev_mem_getbuf(gdev_mem_t *mem) {
    return 0;
}
uint64_t gdev_mem_getaddr(gdev_mem_t *mem) {
    return 0;
}
uint64_t gdev_mem_getsize(gdev_mem_t *mem) {
    return 0;
}
uint64_t gdev_mem_phys_getaddr(gdev_mem_t *mem, uint64_t offset) {
    return 0;
}
int gdev_shm_create(struct gdev_device *gdev, gdev_vas_t *vas, int key, uint64_t size, int flags) {
    return 0;
}
int gdev_shm_destroy_mark(struct gdev_device *gdev, gdev_mem_t *owner) {
    return 0;
}
gdev_mem_t *gdev_shm_attach(gdev_vas_t *vas, gdev_mem_t *mem, uint64_t size) {
    return 0;
}
void gdev_shm_detach(gdev_mem_t *mem) {
}
gdev_mem_t *gdev_shm_lookup(struct gdev_device *gdev, int id) {
    return 0;
}
int gdev_shm_evict_conflict(gdev_ctx_t *ctx, gdev_mem_t *mem) {
    return 0;
}
int gdev_shm_retrieve_swap(gdev_ctx_t *ctx, gdev_mem_t *mem) {
    return 0;
}
int gdev_shm_retrieve_swap_all(gdev_ctx_t *ctx, gdev_vas_t *vas) {
    return 0;
}
int gdev_swap_create(struct gdev_device *gdev, uint32_t size) {
    return 0;
}
void gdev_swap_destroy(struct gdev_device *gdev) {
}