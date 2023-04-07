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

    if (! unlikely(kallsyms_lookup_name))
    {
        pr_alert("Could not retrieve kallsyms_lookup_name address\n");
        return - ENXIO;
    }
    #endif
    _soft_offline_page = (void *) kallsyms_lookup_name("soft_offline_page");
    if (_soft_offline_page == NULL)
    {
        pr_info("lookup failed soft_offline_page\n");
        return - ENXIO;
    }
    _take_page_off_buddy = (void *) kallsyms_lookup_name("take_page_off_buddy");
    if (_take_page_off_buddy == NULL)
    {
        pr_info("lookup failed _take_page_off_buddy\n");
        return - ENXIO;
    }
    _is_free_buddy_page = (void *) kallsyms_lookup_name("is_free_buddy_page");
    if (_is_free_buddy_page == NULL)
    {
        pr_info("lookup failed _is_free_buddy_page\n");
        return - ENXIO;
    }
    return 0;
}

int fh_do_escape(fh_ctx_t *fh_ctx, int action)
{
    unsigned long nonce = ++ fd_ctx.fh_nonce;
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
    if (fh_ctx->fh_escape_data->turn != FH_TURN_GUEST)
    {
        pr_err("Host did not reply to request. Nonce: 0x%lx. Is host listening?", nonce);
        return - ENXIO;
    }

    // TODO: add return state here
    return 0;
}


int fh_init(fh_ctx_t **ret_fh_ctx,
            void *escape_ptr,
            unsigned long escape_size)
{
    int ret = 0;
    struct fh_action_setup *escape;
    fh_ctx_t *fh_ctx = kmalloc(sizeof(fh_ctx_t), GFP_KERNEL);
    if (fh_ctx == NULL)
    {
        return - ENOMEM;
    }
    memset(fh_ctx, 0, sizeof(fh_ctx_t));
    ret = setup_lookup();
    if (ret < 0)
    {
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
                    page_to_pfn(virt_to_page((unsigned long)escape_ptr)));


    if (escape_size == 0)
    {
        pr_info("invalid escape_size: %ld\n", escape_size);
        return - EINVAL;
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

    // TODO: BEAN
    // fh_verify_mapping
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
    char* dev_name;
    int ret;
    struct fh_fop_data *info = kmalloc(sizeof(struct fh_fop_data), GFP_KERNEL);
    struct fh_action_open *escape;
    if (info == NULL)
    {
        return - ENOMEM;
    }
    fd_data_lock(fh_ctx);
    escape = (struct fh_action_open *) &fh_ctx->fh_escape_data->data;
    info->private_data = private_data;
    file->private_data = info;
    dev_name = d_path(&file->f_path, buf, buf_size);
    strncpy(escape->device, dev_name, buf_size);
    escape->flags = file->f_flags;
    ret = fh_do_escape(fh_ctx, FH_ACTION_OPEN_DEVICE);
    if (ret < 0)
    {
        pr_info("fh_do_escape(FH_ACTION_OPEN_DEVICE) failed\n");
        goto clean_up;
    }
    if (escape->common.ret < 0)
    {
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
    if (ret < 0)
    {
        goto clean_up;
    }
    if (escape->common.ret < 0)
    {
        ret = escape->common.err_no;
        goto clean_up;
    }
    ret = 0;
    clean_up:
    fd_data_unlock(fh_ctx);
    kfree(filep->private_data);
    return ret;
}