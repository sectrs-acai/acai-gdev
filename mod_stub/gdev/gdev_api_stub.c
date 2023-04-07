#include "gdev_api.h"
#include "fh_def.h"
#include "fh_kernel.h"


Ghandle gopen(int minor)
{
    FH_NOT_IMPL;
    return 0;
}

int gclose(Ghandle h)
{
    FH_NOT_IMPL;
    return 0;

}

uint64_t gmalloc(Ghandle h, uint64_t size)
{
    FH_NOT_IMPL;
    return 0;

}

uint64_t gfree(Ghandle h, uint64_t addr)
{
    FH_NOT_IMPL;
    return 0;

}

void *gmalloc_dma(Ghandle h, uint64_t size)
{
    FH_NOT_IMPL;
    return 0;

}

uint64_t gfree_dma(Ghandle h, void *buf)
{
    FH_NOT_IMPL;
    return 0;

}

void *gmap(Ghandle h, uint64_t addr, uint64_t size)
{
    FH_NOT_IMPL;
    return 0;

}

int gunmap(Ghandle h, void *buf)
{
    FH_NOT_IMPL;
    return 0;

}

int gmemcpy_to_device(Ghandle h, uint64_t dst_addr, const void *src_buf, uint64_t size)
{

    FH_NOT_IMPL;
    return 0;
}

int gmemcpy_to_device_async(Ghandle h,
                            uint64_t dst_addr,
                            const void *src_buf,
                            uint64_t size,
                            uint32_t *id)
{
    FH_NOT_IMPL;
    return 0;
}

int gmemcpy_user_to_device(Ghandle h, uint64_t dst_addr, const void *src_buf, uint64_t size)
{
    FH_NOT_IMPL;
    return 0;
}

int gmemcpy_user_to_device_async(Ghandle h,
                                 uint64_t dst_addr,
                                 const void *src_buf,
                                 uint64_t size,
                                 uint32_t *id)
{
    FH_NOT_IMPL;
    return 0;

}

int gmemcpy_from_device(Ghandle h, void *dst_buf, uint64_t src_addr, uint64_t size)
{
    FH_NOT_IMPL;
    return 0;
}

int gmemcpy_from_device_async(Ghandle h,
                              void *dst_buf,
                              uint64_t src_addr,
                              uint64_t size,
                              uint32_t *id)
{
    FH_NOT_IMPL;
    return 0;
}

int gmemcpy_user_from_device(Ghandle h, void *dst_buf, uint64_t src_addr, uint64_t size)
{
    FH_NOT_IMPL;
    return 0;
}

int gmemcpy_user_from_device_async(Ghandle h,
                                   void *dst_buf,
                                   uint64_t src_addr,
                                   uint64_t size,
                                   uint32_t *id)
{
    FH_NOT_IMPL;
    return 0;
}

int gmemcpy(Ghandle h, uint64_t dst_addr, uint64_t src_addr, uint64_t size)
{
    FH_NOT_IMPL;
    return 0;
}

int gmemcpy_async(Ghandle h, uint64_t dst_addr, uint64_t src_addr, uint64_t size, uint32_t *id)
{
    FH_NOT_IMPL;
    return 0;
}

int glaunch(Ghandle h, struct gdev_kernel *kernel, uint32_t *id)
{
    FH_NOT_IMPL;
    return 0;

}

int gsync(Ghandle h, uint32_t id, struct gdev_time *timeout)
{
    FH_NOT_IMPL;
    return 0;

}

int gbarrier(Ghandle h)
{
    FH_NOT_IMPL;
    return 0;

}

int gquery(Ghandle h, uint32_t type, uint64_t *result)
{
    FH_NOT_IMPL;
    return 0;
}

int gtune(Ghandle h, uint32_t type, uint32_t value)
{
    FH_NOT_IMPL;
    return 0;
}

int gshmget(Ghandle h, int key, uint64_t size, int flags)
{
    FH_NOT_IMPL;
    return 0;

}

uint64_t gshmat(Ghandle h, int id, uint64_t addr, int flags)
{
    FH_NOT_IMPL;
    return 0;
}

int gshmdt(Ghandle h, uint64_t addr)
{
    FH_NOT_IMPL;
    return 0;

}

int gshmctl(Ghandle h, int id, int cmd, void *buf)
{
    FH_NOT_IMPL;
    return 0;

}

uint64_t gref(Ghandle hmaster, uint64_t addr, uint64_t size, Ghandle hslave)
{
    FH_NOT_IMPL;
    return 0;
}

int gunref(Ghandle h, uint64_t addr)
{
    return 0;
    FH_NOT_IMPL;
}

uint64_t gphysget(Ghandle h, const void *p)
{
    FH_NOT_IMPL;
    return 0;
}

uint64_t gvirtget(Ghandle h, const void *p)
{
    FH_NOT_IMPL;
    return 0;

}

int gdevice_count(int *result)
{
    *result = 1;
    return 0;
}
