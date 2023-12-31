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

#ifndef __GDEV_IOCTL_H__
#define __GDEV_IOCTL_H__

#include "gdev_api.h"
#include "gdev_ioctl_def.h"
#include <linux/list.h>
struct gdev_handle {
    int escape_handle;
    struct list_head mmap_head;
};

struct mmap_node {
    struct list_head list;
    unsigned long k_buffer; /* kernel heap address that points to device mem */
    unsigned long usr_space_addr; /* userspace addr in 86 userspace manager */
};

int gdev_ioctl_gtune(struct file* f, Ghandle h, unsigned long arg);
int gdev_ioctl_gquery(struct file* f, Ghandle h, unsigned long arg);
int gdev_ioctl_gmalloc(struct file *f, Ghandle h, unsigned long arg);
int gdev_ioctl_gmemcpy_to_device(struct file *f, Ghandle h, unsigned long arg);
int gdev_ioctl_glaunch(struct file *f, Ghandle h, unsigned long arg);
int gdev_ioctl_gsync(struct file *f, Ghandle h, unsigned long arg);
int gdev_ioctl_gbarrier(struct file *f, Ghandle h, unsigned long arg);
int gdev_ioctl_gmemcpy_from_device(struct file *f, Ghandle h, unsigned long arg);
int gdev_ioctl_gfree(struct file *filp, Ghandle handle, unsigned long arg);
int gdev_ioctl_gmalloc_dma(struct file *filp, Ghandle h, unsigned long arg);
int gdev_ioctl_gfree_dma(struct file *filp, Ghandle h, unsigned long arg);
int gdev_ioctl_gphysget(struct file *filp, Ghandle h, unsigned long arg);
int gdev_ioctl_gvirtget(struct file *filp, Ghandle h, unsigned long arg);

int gdev_ioctl_get_handle(Ghandle handle, unsigned long arg);
int gdev_ioctl_gmap(Ghandle h, unsigned long arg);
int gdev_ioctl_gunmap(Ghandle h, unsigned long arg);
int gdev_ioctl_gmemcpy_to_device_async(Ghandle h, unsigned long arg);
int gdev_ioctl_gmemcpy_from_device_async(Ghandle h, unsigned long arg);
int gdev_ioctl_gmemcpy(Ghandle h, unsigned long arg);
int gdev_ioctl_gmemcpy_async(Ghandle h, unsigned long arg);
int gdev_ioctl_gshmget(Ghandle h, unsigned long arg);
int gdev_ioctl_gshmat(Ghandle h, unsigned long arg);
int gdev_ioctl_gshmdt(Ghandle h, unsigned long arg);
int gdev_ioctl_gshmctl(Ghandle h, unsigned long arg);
int gdev_ioctl_gref(Ghandle h, unsigned long arg);
int gdev_ioctl_gunref(Ghandle h, unsigned long arg);



#endif
