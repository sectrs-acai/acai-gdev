#define pr_fmt(fmt)     KBUILD_MODNAME ":%s: " fmt, __func__

#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/highmem.h>
#include <linux/scatterlist.h>
#include <linux/pci.h>
#include <linux/dma-map-ops.h>

#include "fh_kernel.h"

#define HERE pr_info("%s/%s: %d\n", __FILE__, __FUNCTION__, __LINE__)

#if defined(__x86_64__) || defined(_M_X64)
#define fh_flush \
flush_cache_all()

#else
#define fh_flush \
asm volatile("dmb sy"); flush_cache_all()
#endif

struct fh_ctx fd_ctx;
DEFINE_SPINLOCK(faultdata_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_KALLSYMS_LOOKUP 1

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

static int (*_soft_offline_page)(unsigned long pfn, int flags);

static bool (*_take_page_off_buddy)(struct page *page) = NULL;

static bool (*_is_free_buddy_page)(struct page *page) = NULL;

static int setup_lookup(void)
{
    #ifdef KPROBE_KALLSYMS_LOOKUP
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    if (!unlikely(kallsyms_lookup_name)) {
        pr_alert("Could not retrieve kallsyms_lookup_name address\n");
        return -ENXIO;
    }
    #endif
    _soft_offline_page = (void *) kallsyms_lookup_name("soft_offline_page");
    if (_soft_offline_page == NULL) {
        pr_info("lookup failed soft_offline_page\n");
        return -ENXIO;
    }
    _take_page_off_buddy = (void *) kallsyms_lookup_name("take_page_off_buddy");
    if (_take_page_off_buddy == NULL) {
        pr_info("lookup failed _take_page_off_buddy\n");
        return -ENXIO;
    }
    _is_free_buddy_page = (void *) kallsyms_lookup_name("is_free_buddy_page");
    if (_is_free_buddy_page == NULL) {
        pr_info("lookup failed _is_free_buddy_page\n");
        return -ENXIO;
    }
    return 0;
}

int fh_do_escape(fh_ctx_t *fh_ctx, int action)
{
    unsigned long nonce = ++fd_ctx.fh_nonce;
    fh_ctx->fh_escape_data->turn = FH_TURN_HOST;
    fh_ctx->fh_escape_data->action = action;

    if (!spin_is_locked(&fh_ctx->fh_lock)) {
        pr_info("spin lock not held on escape!\n");
        BUG();
    }

    #if defined(__x86_64__) || defined(_M_X64)
    #else
    asm volatile("dmb sy");
    #endif
    /*
     * TODO: Optimization: put data not on same page as faulthook
     */
    fh_ctx->fh_escape_data->nonce = nonce; /* escape to other world */

    // and we are back
    if (fh_ctx->fh_escape_data->turn != FH_TURN_GUEST) {
        pr_err("Host did not reply to request. Nonce: 0x%lx. Is host listening?", nonce);
        return -ENXIO;
    }

    return 0;
}

int fh_init(fh_ctx_t **ret_fh_ctx,
            void *escape_ptr,
            unsigned long escape_size)
{
    int ret = 0;
    struct fh_action_setup *escape;
    fh_ctx_t *fh_ctx = kmalloc(sizeof(fh_ctx_t), GFP_KERNEL);
    if (fh_ctx == NULL) {
        return -ENOMEM;
    }
    memset(fh_ctx, 0, sizeof(fh_ctx_t));
    ret = setup_lookup();
    if (ret < 0) {
        kfree(fh_ctx);
        return ret;
    }
    fh_ctx->escape_ptr = escape_ptr;
    fh_ctx->escape_size = escape_size;
    fh_ctx->fh_escape_data = (struct faultdata_struct *) escape_ptr;
    fh_ctx->fh_lock = __SPIN_LOCK_UNLOCKED(fh_lock);
    *ret_fh_ctx = fh_ctx;

    memset(escape_ptr, 0, escape_size);
    pr_info("faulthook page: 0x%lx+0x%lx bytes, pfn=%lx\n",
            (unsigned long) escape_ptr, escape_size,
            page_to_pfn(virt_to_page((unsigned long) escape_ptr)));

    if (escape_size == 0) {
        pr_info("invalid escape_size: %ld\n", escape_size);
        return -EINVAL;
    }
    unsigned long pfn = page_to_pfn(virt_to_page(escape_ptr));
    struct page *epage = pfn_to_page(pfn);
    unsigned long *p = kmap(epage);
    pr_info("deref test %lx", (unsigned long) p);
    pr_info("%lx=%lx\n", (unsigned long) p, *p);

    fd_data_lock(fh_ctx);
    escape = (struct fh_action_setup *) &fh_ctx->fh_escape_data->data;
    memset(escape, 0, sizeof(struct fh_action_setup));
    fh_do_escape(fh_ctx, FH_ACTION_SETUP);
    if (escape->buffer_limit > 0) {
        pr_info("Escape Buffer Limit: %lx\n", escape->buffer_limit);
        fh_ctx->escape_size = escape->buffer_limit;
    }

    fd_data_unlock(fh_ctx);
    setup_lookup();

    return 0;
}

int fh_cleanup(fh_ctx_t *fh_ctx)
{
    fd_data_lock(fh_ctx);
    fh_do_escape(fh_ctx, FH_ACTION_TEARDOWN);
    memset(fh_ctx->escape_ptr, 0, fh_ctx->escape_size);
    fd_data_unlock(fh_ctx);
    kfree(fh_ctx);
    return 0;
}

int fh_fop_open(fh_ctx_t *fh_ctx,
                struct inode *inode,
                struct file *file,
                void *private_data)
{
    #define buf_size 120
    char buf[buf_size];
    char *dev_name;
    int ret;
    struct fh_fop_data *info = kmalloc(sizeof(struct fh_fop_data), GFP_KERNEL);
    struct fh_action_open *escape;
    if (info == NULL) {
        return -ENOMEM;
    }
    fd_data_lock(fh_ctx);
    escape = (struct fh_action_open *) &fh_ctx->fh_escape_data->data;
    info->private_data = private_data;
    file->private_data = info;
    dev_name = d_path(&file->f_path, buf, buf_size);
    strncpy(escape->device, dev_name, buf_size);
    escape->flags = file->f_flags;
    ret = fh_do_escape(fh_ctx, FH_ACTION_OPEN_DEVICE);
    if (ret < 0) {
        pr_info("fh_do_escape(FH_ACTION_OPEN_DEVICE) failed\n");
        goto clean_up;
    }
    if (escape->common.ret < 0) {
        ret = escape->common.err_no;
        pr_info("escape->common.ret < 0: %d\n", ret);
        goto clean_up;
    }
    /*
     * We use fd as key to query device on host
     */
    info->fd = escape->common.fd;
    ret = 0;
    clean_up:
    fd_data_unlock(fh_ctx);
    return ret;
}

/*
 * Called when the device goes from used to unused.
 */
int fh_fop_close(fh_ctx_t *fh_ctx,
                 struct inode *dev_node,
                 struct file *filep)
{
    int ret = 0;
    struct fh_fop_data *fop_data = filep->private_data;
    struct fh_action_open *escape = (struct fh_action_open *) fh_ctx->fh_escape_data->data;
    fd_data_lock(fh_ctx);
    escape->common.fd = fop_data->fd;
    ret = fh_do_escape(fh_ctx, FH_ACTION_CLOSE_DEVICE);
    if (ret < 0) {
        goto clean_up;
    }
    if (escape->common.ret < 0) {
        ret = escape->common.err_no;
        goto clean_up;
    }
    ret = 0;
    clean_up:
    fd_data_unlock(fh_ctx);
    kfree(filep->private_data);
    return ret;
}

int simulate_pci_dma_cleanup(void *data)
{
    struct sg_table * sgt = (struct sg_table*) data;
    #if 1
    {
        struct dma_map_ops dma_ops;
        struct pci_dev *dummy = kmalloc(sizeof(struct pci_dev), GFP_KERNEL);
        if (dummy == NULL) {
            return -ENOMEM;
        }
        memset(dummy, 0, sizeof(struct pci_dev));
        memset(&dma_ops, 0, sizeof(struct dma_map_ops));
        dummy->dev.dma_ops = &dma_ops;

        dma_unmap_sg(&dummy->dev, sgt->sgl, sgt->orig_nents,
                     0 /* bidirectional */);
        kfree(dummy);
    }
    #endif
    sg_free_table(sgt);
    kfree(sgt);

    return 0;
}

/*
 * XXX: This simulatse dma communcation because we dont have a device yet
 * in realm
 */
int simulate_pci_dma(unsigned long size,
                     unsigned long pages_nr,
                     unsigned long *pfns,
                     void **ret_sg_table)
{
    unsigned long i = 0;
    unsigned long offset, nbytes;
    unsigned long nbytes_left;
    struct sg_table *sgt;
    struct scatterlist *sg;
    struct page *page;

    pr_info("simulating pci dma access...\n");
    sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
    if (sgt == NULL) {
        pr_err("sgl OOM.\n");
        return -ENOMEM;
    }
    if (sg_alloc_table(sgt, pages_nr, GFP_KERNEL)) {
        pr_err("sgl OOM.\n");
        return -ENOMEM;
    }
    sg = sgt->sgl;
    nbytes_left = size;
    for (i = 0; i < pages_nr; i++, sg = sg_next(sg)) {
        pr_info("%d pfn: %lx\n", i, pfns[i]);
        page = pfn_to_page(pfns[i]);
        offset = 0;
        nbytes = min(PAGE_SIZE, nbytes_left);
        #if 0
        pr_info("sg_set_page(pages[%d], %x, %x\n", i, nbytes, offset);
        #endif
        sg_set_page(sg, page, nbytes, offset);
        nbytes_left -= PAGE_SIZE;
    }

    /*
     * XXX: We dont have a device, so the code below
     * initializes dummy code such that pci_map_sg returns with an error
     * without causing segfaults. This simulates pci_map_sg
     * and allows us to notify tfa about which regions to assign as devmem.
     */
    {
        struct dma_map_ops dma_ops;
        struct pci_dev *dummy = kmalloc(sizeof(struct pci_dev), GFP_KERNEL);
        if (dummy == NULL) {
            return -ENOMEM;
        }
        memset(dummy, 0, sizeof(struct pci_dev));
        memset(&dma_ops, 0, sizeof(struct dma_map_ops));
        dummy->dev.dma_ops = &dma_ops;

        // this access will lead to WARN_ON_ONCE which is expected
        /* dma_map_sg calls these functions: make sure they dont crash:
         *
         * const struct dma_map_ops *ops = get_dma_ops(dev);
         * if (WARN_ON_ONCE(!dev->dma_mask))
         *   return 0; // return here
         */
        dma_map_sg(&dummy->dev, sgt->sgl, sgt->orig_nents,
                   0 /* bidirectional */);

        kfree(dummy);
    }
    if (ret_sg_table) {
        *ret_sg_table = sgt;
    } else {
        simulate_pci_dma_cleanup(sgt);
    }
    return 0;
}

