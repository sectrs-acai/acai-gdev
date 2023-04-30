/*
 * Copyright (C) Shinpei Kato
 *
 * University of California, Santa Cruz
 * Systems Research Lab.
 *
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/version.h>
#include "gdev_api.h"
#include "gdev_device.h"
#include "gdev_fops.h"
#include "gdev_ioctl.h"
#include "fh_kernel.h"
#include "gdev_ioctl_debug.h"

static int gdev_open(struct inode *inode, struct file *filp)
{
    int ret = 0;
    struct gdev_handle *h = vmalloc(sizeof(struct gdev_handle));
    CCA_MARKER_DRIVER_FOP_CALL /* benchmarking */

    if (h == NULL) {
        return -ENOMEM;
    }
    ret = fh_fop_open(fh_ctx, inode, filp, h);
    if (ret < 0) {
        fh_print("fh_fop_open failed: %d\n", ret);
    }
    INIT_LIST_HEAD(&(h->mmap_head));
    return ret;
}

static int gdev_release(struct inode *inode, struct file *filp)
{
    int ret;
    CCA_MARKER_DRIVER_FOP_CALL /* benchmarking */

    Ghandle handle = fh_fop_get_private_data(filp);
    if (handle == NULL) {
        fh_print("device not opened\n");
        return -ENOENT;
    }

    struct mmap_node *cursor, *temp;
    list_for_each_entry_safe(cursor, temp, &handle->mmap_head, list)
    {
        list_del(&cursor->list);
        kfree(cursor);
    }

    ret = fh_fop_close(fh_ctx, inode, filp);
    if (ret < 0) {
        fh_print("fh_fop_close failed: %d\n", ret);
    }
    vfree(handle);

    return ret;
}

static int do_gdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
#if 0
    GDEV_PRINT("Ioctl %ld %s.\n", cmd, debug_ioctl_cmd_name(cmd));
#endif
    CCA_MARKER_DRIVER_FOP_CALL /* benchmarking */

    Ghandle h = fh_fop_get_private_data(filp);
    if (h == NULL) {
        pr_info("No handled stored\n");
        return -EINVAL;
    }

    switch (cmd) {
        case GDEV_IOCTL_GTUNE: return gdev_ioctl_gtune(filp, h, arg);
        case GDEV_IOCTL_GQUERY: return gdev_ioctl_gquery(filp, h, arg);
        case GDEV_IOCTL_GMALLOC: return gdev_ioctl_gmalloc(filp, h, arg);
        case GDEV_IOCTL_GFREE: return gdev_ioctl_gfree(filp, h, arg);

        case GDEV_IOCTL_GSYNC: return gdev_ioctl_gsync(filp, h, arg);
        case GDEV_IOCTL_GBARRIER: return gdev_ioctl_gbarrier(filp, h, arg);

        case GDEV_IOCTL_GMEMCPY_TO_DEVICE: return gdev_ioctl_gmemcpy_to_device(filp, h, arg);
        case GDEV_IOCTL_GMEMCPY_FROM_DEVICE: return gdev_ioctl_gmemcpy_from_device(filp, h, arg);

        case GDEV_IOCTL_GLAUNCH: return gdev_ioctl_glaunch(filp, h, arg);

        case GDEV_IOCTL_GMALLOC_DMA: return gdev_ioctl_gmalloc_dma(filp, h, arg);
        case GDEV_IOCTL_GFREE_DMA: return gdev_ioctl_gfree_dma(filp, h, arg);
        case GDEV_IOCTL_GVIRTGET: return gdev_ioctl_gvirtget(filp, h, arg);
#if 0
            case GDEV_IOCTL_GET_HANDLE: return gdev_ioctl_get_handle(h, arg);
            case GDEV_IOCTL_GMAP: return gdev_ioctl_gmap(h, arg);
            case GDEV_IOCTL_GUNMAP: return gdev_ioctl_gunmap(h, arg);
            case GDEV_IOCTL_GMEMCPY_TO_DEVICE_ASYNC: return gdev_ioctl_gmemcpy_to_device_async(h, arg);
            case GDEV_IOCTL_GMEMCPY_FROM_DEVICE_ASYNC: return gdev_ioctl_gmemcpy_from_device_async(h, arg);
            case GDEV_IOCTL_GMEMCPY: return gdev_ioctl_gmemcpy(h, arg);
            case GDEV_IOCTL_GMEMCPY_ASYNC: return gdev_ioctl_gmemcpy_async(h, arg);
            case GDEV_IOCTL_GSHMGET: return gdev_ioctl_gshmget(h, arg);
            case GDEV_IOCTL_GSHMAT: return gdev_ioctl_gshmat(h, arg);
            case GDEV_IOCTL_GSHMDT: return gdev_ioctl_gshmdt(h, arg);
            case GDEV_IOCTL_GSHMCTL: return gdev_ioctl_gshmctl(h, arg);
            case GDEV_IOCTL_GREF: return gdev_ioctl_gref(h, arg);
            case GDEV_IOCTL_GUNREF: return gdev_ioctl_gunref(h, arg);
            case GDEV_IOCTL_GPHYSGET: return gdev_ioctl_gphysget(h, arg);
#endif
        default: {
            GDEV_PRINT("IOCTL command 0x%x is not supported: %s.\n",
                       cmd,
                       debug_ioctl_cmd_name(cmd));
            return -EINVAL;
        }
    }
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
static long gdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#else
static int gdev_ioctl(struct inode *inode,
                      struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
    int ret = do_gdev_ioctl(filp, cmd, arg);
    if (ret < 0) {
        pr_info("do_gdev_ioctl returned %d\n", ret);
    }
    return ret;
}

static int gdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    void *buf;
    int ret;
    uint32_t size = vma->vm_end - vma->vm_start;
    unsigned long start = vma->vm_start;
    CCA_MARKER_DRIVER_FOP_CALL /* benchmarking */

    if (vma->vm_pgoff == 0) {
        /*
         * int i = __get_minor(filp);
         * struct gdev_device *gdev = &gdevs[i];
         * buf = gdev->mmio_regs;
         */
        return -EINVAL; /* mmio mapping is no longer supported. */
    } else {
        buf = (void *) (vma->vm_pgoff << PAGE_SHIFT);
    }

    if (size > PAGE_SIZE) {
        char *vmalloc_area_ptr = (char *) buf;
        unsigned long pfn;
        int ret;
        /* loop over all pages, map it page individually */

        while (size > 0) {
            pfn = vmalloc_to_pfn(vmalloc_area_ptr);
            ret = remap_pfn_range(vma, start, pfn, PAGE_SIZE, PAGE_SHARED);

            if (ret < 0) {
                pr_info("remap_pfn_range failed with %d\n", ret);
                return ret;
            }

            start += PAGE_SIZE;
            vmalloc_area_ptr += PAGE_SIZE;
            size -= PAGE_SIZE;
        }
        return 0;
    } else {
        unsigned long pfn;
        if (virt_addr_valid(buf)) {
            pfn = virt_to_phys(buf) >> PAGE_SHIFT;
        } else {
            pfn = vmalloc_to_pfn(buf);
        }
        ret = remap_pfn_range(vma, start, pfn, size, PAGE_SHARED);
        if (ret < 0) {
            pr_info("remap_pfn_range failed with %d\n", ret);
        }
        return ret;
    }
}

struct file_operations gdev_fops = {
    .owner = THIS_MODULE,
    .open = gdev_open,
    .release = gdev_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
    .unlocked_ioctl = gdev_ioctl,
#else
    .ioctl = gdev_ioctl,
#endif
    .mmap = gdev_mmap,
};
