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

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/sched/types.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
struct sched_param {
    int sched_priority;
};
#define sched_setscheduler(a, b, c)

#endif

#define setup_timer_on_stack(timer, fn, data)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
#include <linux/sched/types.h>
#endif

#include "gdev_api.h"
#include "gdev_compiler.h"
#include "gdev_conf.h"
#include "gdev_device.h"
#include "gdev_drv.h"
#include "gdev_fops.h"
#include "gdev_interface.h"
#include "gdev_proc.h"
 #include "gdev_sched.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gdev Stub");

#define MODULE_NAME	"gdev"

/**
 * global variables.
 */
static dev_t dev;
static struct class *dev_class;
static int cdevs_registered = 0;
static struct cdev *cdevs; /* character devices for virtual devices */

/**
 * called for each minor physical device.
 */
int gdev_minor_init(int physid)
{
	int i, j;
	struct drm_device *drm;

	if (gdev_drv_getdrm(physid, &drm)) {
		GDEV_PRINT("Could not find device %d\n", physid);
		return -EINVAL;
	}

	/* initialize the physical device. */
	gdev_init_device(&gdevs[physid], physid, drm);

	j = 0;
	for (i = 0; i < physid; i++)
		j += VCOUNT_LIST[i];

	for (i = j; i < j + VCOUNT_LIST[physid]; i++) {
		/* initialize the virtual device. when Gdev first loaded, one-to-one
		   map physical and virtual device. */
		if (i == j) /* the first virtual device in a physical device */
			gdev_init_virtual_device(&gdev_vds[i], i, 100, &gdevs[physid]);
		else
			gdev_init_virtual_device(&gdev_vds[i], i, 0, &gdevs[physid]);

		/* initialize the local scheduler for each virtual device. */
#ifndef GDEV_SCHED_DISABLED
		gdev_init_scheduler(&gdev_vds[i]);
#endif
		/* create /proc/gdev/vd%d entries  */
		gdev_proc_minor_create(i);

		device_create(dev_class, NULL, MKDEV(MAJOR(dev), i), NULL,
			      MODULE_NAME"%d", i);
	}

	return 0;
}

/**
 * called for each minor physical device.
 */
int gdev_minor_exit(int physid)
{
	int i, j;

	if (!gdevs) {
		GDEV_PRINT("Failed to exit minor device %d, "
		           "major already exited\n", physid);
		return -EINVAL;
	}

	if (gdevs[physid].users) {
		GDEV_PRINT("Device %d has %d users\n", physid, gdevs[physid].users);
	}

	if (physid < gdev_count) {

		for (i = 0, j = 0; i < physid; i++)
			j += VCOUNT_LIST[i];

		for (i = 0; i < gdev_vcount; i++, j++) {

			device_destroy(dev_class, MKDEV(MAJOR(dev), j));

			if (gdev_vds[i].parent == &gdevs[physid]) {
#ifndef GDEV_SCHED_DISABLED
				gdev_exit_scheduler(&gdev_vds[i]);
#endif
				gdev_exit_virtual_device(&gdev_vds[i]);
			}
		}
		gdev_exit_device(&gdevs[physid]);
	}

	return 0;
}

int gdev_major_init(void)
{
	int i, major, ret;

	/* get the number of physical devices. */
	if (gdev_drv_getdevice(&gdev_count)) {
		GDEV_PRINT("Failed to get device count\n");
		ret = -EINVAL;
		goto fail_getdevice;
	}

	GDEV_PRINT("Found %d physical device(s).\n", gdev_count);

	/* get the number of virtual devices. */
	gdev_vcount = 0;
	for (i = 0; i < gdev_count; i++)
		gdev_vcount += VCOUNT_LIST[i];

	GDEV_PRINT("Configured %d virtual device(s).\n", gdev_vcount);

	/* allocate vdev_count character devices. */
	if ((ret = alloc_chrdev_region(&dev, 0, gdev_vcount, MODULE_NAME))) {
		GDEV_PRINT("Failed to allocate module.\n");
		goto fail_alloc_chrdev;
	}
	cdevs_registered = 1;

	/* allocate Gdev physical device objects. */
	if (!(gdevs = kzalloc(sizeof(*gdevs) * gdev_count, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto fail_alloc_gdevs;
	}
	/* allocate Gdev virtual device objects. */
	if (!(gdev_vds = kzalloc(sizeof(*gdev_vds) * gdev_vcount, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto fail_alloc_gdev_vds;
	}
	/* allocate character device objects. */
	if (!(cdevs = kzalloc(sizeof(*cdevs) * gdev_vcount, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto fail_alloc_cdevs;
	}

	/* register character devices. */
	major = MAJOR(dev);
	for (i = 0; i < gdev_vcount; i++) {
		cdev_init(&cdevs[i], &gdev_fops);
		cdevs[i].owner = THIS_MODULE;
		if ((ret = cdev_add(&cdevs[i], MKDEV(major, i), 1))){
			GDEV_PRINT("Failed to register virtual device %d\n", i);
			goto fail_cdevs_add;
		}
	}

	/* create /proc entries. */
	if ((ret = gdev_proc_create())) {
		GDEV_PRINT("Failed to create /proc entry\n");
		goto fail_proc_create;
	}

	dev_class = class_create(THIS_MODULE, MODULE_NAME);
	return 0;

fail_proc_create:
fail_cdevs_add:
	for (i = 0; i < gdev_vcount; i++) {
		cdev_del(&cdevs[i]);
	}
	kfree(cdevs);
	cdevs = NULL;
fail_alloc_cdevs:
	kfree(gdev_vds);
	gdev_vds = NULL;
fail_alloc_gdev_vds:
	kfree(gdevs);
	gdevs = NULL;
fail_alloc_gdevs:
	unregister_chrdev_region(dev, gdev_vcount);
	cdevs_registered = 0;
fail_alloc_chrdev:
fail_getdevice:
	return ret;
}

int gdev_major_exit(void)
{
	int i;

	 class_destroy(dev_class);

#ifndef GDEV_SCHED_DISABLED
	gdev_drv_unsetnotify(__gdev_notify_handler);
#endif

	gdev_proc_delete();

	if (!cdevs)
		goto end;
	for (i = 0; i < gdev_vcount; i++) {
		cdev_del(&cdevs[i]);
	}
	kfree(cdevs);
	cdevs = NULL;

	if (!gdev_vds)
		goto end;
	kfree(gdev_vds);
	gdev_vds = NULL;

	if (!gdevs)
		goto end;
	kfree(gdevs);
	gdevs = NULL;

	if (!cdevs_registered)
		goto end;
	unregister_chrdev_region(dev, gdev_vcount);
	cdevs_registered = 0;

end:
	return 0;
}

int gdev_getinfo_device_count(void)
{
	return gdev_vcount; /* return virtual device count. */
}

fh_ctx_t *fh_ctx;

static int __init gdev_module_init(void)
{
	int i;
    int ret;

	GDEV_PRINT("Loading module...\n");

	if (gdev_major_init()) {
		GDEV_PRINT("Failed to initialize major device(s)\n");
		goto end;
	}

	for (i = 0; i < gdev_count; i++) {
		if (gdev_minor_init(i)) {
			for (i = i - 1; i >= 0; i--)
				gdev_minor_exit(i);
			gdev_major_exit();
			goto end;
		}
	}

    ret = fh_init(&fh_ctx, fvp_escape_page, fvp_escape_size);
    if (ret < 0)
    {
        fh_print("fh_init failed: %d\n", ret);
    }

end:
	return 0;
}

static void __exit gdev_module_exit(void)
{
	int i;

	GDEV_PRINT("Unloading module...\n");
    fh_cleanup(fh_ctx);

	for (i = 0; i < gdev_count; i++) {
		gdev_minor_exit(i);
	}

	gdev_major_exit();
}

module_init(gdev_module_init);
module_exit(gdev_module_exit);
