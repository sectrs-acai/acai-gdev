#include <linux/shm.h>
#include <linux/mm.h>
#include "gdev_api.h"
#include "gdev_conf.h"
#include "gdev_ioctl.h"
#include "fh_def.h"

#include <linux/list.h>
#include "cca_benchmark.h"
#define pr_info_debug

static struct mmap_node *mmap_node_get_by_kaddr(Ghandle handle, unsigned long kaddr)
{
    struct list_head *list_entry = NULL;
    struct mmap_node *curr_node;

    list_for_each(list_entry, &handle->mmap_head) {
        curr_node = list_entry(list_entry,
                               struct mmap_node, list);
        if (kaddr == curr_node->k_buffer) {
            return curr_node;
        }
    }
    return NULL;
}

/* given a vmalloced buffer, get its underlaying pfns */
static int get_pfn_for_vmalloc_buf(char *buf,
                                   unsigned long buf_size,
                                   unsigned long **ret_pfn_buf,
                                   unsigned long *ret_pfn_buf_num)
{
    unsigned long i = 0;
    const unsigned long pfn_num = DIV_ROUND_UP(buf_size, PAGE_SIZE);
    const unsigned long pfn_alloc_size = pfn_num * sizeof(unsigned long);
    unsigned long *pfn_buf = vmalloc(pfn_alloc_size);
    if (pfn_buf == NULL) {
        return -ENOMEM;
    }

    for (i = 0; i < pfn_num; i += 1) {
        pfn_buf[i] = vmalloc_to_pfn(buf + i * PAGE_SIZE);
        pr_info_debug("%ld = %lx\n", i, pfn_buf[i]);
    }

    pr_info_debug("translated %d pfn (size: %d bytes on buffer)\n",
        pfn_num,
        pfn_num * sizeof(unsigned long));

    *ret_pfn_buf_num = pfn_num;
    *ret_pfn_buf = pfn_buf;
    return 0;
}

static int vmalloc_payload_for_pfn_escape(
    char *buf, //must be vmalloc
    unsigned long buf_size,
    unsigned long payload_header_size,
    unsigned long **ret_pfn_buf,
    unsigned long *ret_pfn_num,
    void **ret_payload,
    unsigned long *ret_payload_size
)
{
    unsigned long *pfn_buf = NULL;
    unsigned long pfn_num = 0;
    unsigned long pfn_size = 0;
    unsigned long payload_size;
    void *payload = NULL;
    int ret = 0;
    ret = get_pfn_for_vmalloc_buf(buf, buf_size, &pfn_buf, &pfn_num);

    if (ret < 0) {
        goto clean_up_buf;
    }

    if (pfn_buf == NULL) {
        ret = -EINVAL;
        goto clean_up_buf;
    }
    pfn_size = pfn_num * sizeof(unsigned long);
    payload_size = pfn_size + payload_header_size;


    pr_info_debug("payload_size: %d\n", payload_size);
    payload = vmalloc(payload_size);
    if (payload == NULL) {
        ret = -ENOMEM;
        goto clean_up_pfn_buf;
    }

    memset(payload, 0, payload_size);
    *ret_payload = payload;
    *ret_payload_size = payload_size;
    *ret_pfn_buf = pfn_buf;
    *ret_pfn_num = pfn_num;
    return 0;

    clean_up_pfn_buf:
    vfree(pfn_buf);

    clean_up_buf:
    vfree(buf);
    return ret;
}

static int signalize_sgl_map(unsigned long gdev_cmd,
                             char *payload,
                             unsigned long payload_size) {

    switch(gdev_cmd) {
        case GDEV_IOCTL_GMEMCPY_TO_DEVICE: {
            struct fh_ioctl_memcpy_to_device *p = (struct fh_ioctl_memcpy_to_device *) payload;
            unsigned long size = p->req.size;
            unsigned long pages_nr = p->src_buf_pfn_num;
            unsigned long *pfns = (unsigned long*) &p->src_buf_pfn;
            /*
             * benchmark marker
             * # of dma reads
             */
            CCA_MARKER_DMA_PAGE_READ(pages_nr);
            simulate_pci_dma(size, pages_nr, pfns, NULL);
            break;
        }
        case GDEV_IOCTL_GMEMCPY_FROM_DEVICE: {
            struct fh_ioctl_memcpy_from_device *p = (struct fh_ioctl_memcpy_from_device *) payload;
            unsigned long size = p->req.size;
            unsigned long pages_nr = p->dest_buf_pfn_num;
            unsigned long *pfns = (unsigned long*) &p->dest_buf_pfn;
            /*
             * benchmark marker
             * # of dma writes
             */
            CCA_MARKER_DMA_PAGE_WRITE(pages_nr);
            simulate_pci_dma(size, pages_nr, pfns, NULL);
            break;
        }
        case GDEV_IOCTL_GMALLOC_DMA: {
            struct fh_ioctl_gmalloc_dma *p = (struct fh_ioctl_gmalloc_dma *) payload;
            unsigned long size = p->req.size;
            unsigned long pages_nr = p->buf_pfn_num;
            unsigned long *pfns = (unsigned long*) &p->buf_pfn;
            /*
             * benchmark marker
             * # of pages allocated for mmap
             */
            CCA_MARKER_MMAP_PAGE(pages_nr);
            simulate_pci_dma(size, pages_nr, pfns, NULL);
            break;
        }
        case GDEV_IOCTL_GLAUNCH: {
            /*
             * We simulate glaunch as DMA too,
             * an implementation may rather use mmap instead.
             * We choose dma because kernel parameters can vary in size.
             */
            int ret = 0;
            unsigned long *pfns;
            unsigned long pages_nr;
            ret = get_pfn_for_vmalloc_buf(payload, payload_size, &pfns, &pages_nr);
            if (ret < 0) {
                pr_info("get_pfn_for_vmalloc_buf failed for "
                        "GDEV_IOCTL_GLAUNCH pci signalize\n");
                return ret;
            }
            unsigned long size = payload_size;
            /*
             * benchmark marker
             * # of dma page reads during launch
             */
            CCA_MARKER_DMA_PAGE_READ(pages_nr);
            simulate_pci_dma(size, pages_nr, pfns, NULL);
            vfree(pfns);
            break;
        }
        case GDEV_IOCTL_GMALLOC: {
            /*
             * XXX: this is not a scatter gather list
             *      but for benchmarking purpose we track number of pages allocated for dma
             */
            struct ioctl_malloc *p = (struct ioctl_malloc *) payload;
            unsigned long pages_nr = DIV_ROUND_UP(p->req.size, PAGE_SIZE);
            CCA_MARKER_DMA_PAGE_ALLOC(pages_nr);
            break;
        }
        default: {
        }
    }
    return 0;
}

static int fh_gdev_ioctl(
    struct file *filp,
    unsigned long gdev_cmd,
    char *payload,
    unsigned long payload_size)
{
    int ret = 0;
    struct fh_fop_data *fop_data = filp->private_data;
    struct fh_gdev_ioctl *escape = (struct fh_gdev_ioctl *) fh_ctx->fh_escape_data->data;

    /* signalize sgl dummy map */
    signalize_sgl_map(gdev_cmd, payload, payload_size);

    fd_data_lock(fh_ctx);
    escape->common.fd = fop_data->fd;
    escape->gdev_command = gdev_cmd;
    ret = fh_memcpy_escape_buf(fh_ctx, escape->payload, payload, payload_size,
                               sizeof(struct fh_action_common) + sizeof(unsigned long) /*ioctl */);
    if (ret < 0) {
        return ret;
    }

    ret = fh_do_escape(fh_ctx, FH_ACTION_IOCTL);
    if (ret < 0) {
        fh_print("fh_do_escape(gdev cmd: %ld) returned; %d\n", gdev_cmd, ret);
        goto clean_up;
    }
    if (escape->common.ret < 0) {
        ret = escape->common.err_no;
        fh_print("common.ret (gdev cmd: %ld) %d\n", gdev_cmd, ret);
        goto clean_up;
    }

    fh_memcpy_escape_buf(fh_ctx, payload, escape->payload, payload_size,
                         sizeof(struct fh_action_common) + sizeof(unsigned long));
    if (ret < 0) {
        return ret;
    }
    ret = 0;
    clean_up:
    fd_data_unlock(fh_ctx);
    return ret;
}

int gdev_ioctl_gtune(struct file *filp, Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_tune c;
    struct ioctl_tune payload = {0};
    if (copy_from_user(&c, (void __user *) arg, sizeof(c))) {
        return -EFAULT;
    }
    payload.req.type = c.type;
    payload.req.value = c.value;
    return fh_gdev_ioctl(filp, GDEV_IOCTL_GTUNE, (char *) &payload, sizeof(struct ioctl_tune));
}

int gdev_ioctl_gquery(struct file *filp, Ghandle handle, unsigned long arg)
{
    int ret;
    struct gdev_ioctl_query q;
    struct ioctl_query p = {0};

    if (copy_from_user(&q, (void __user *) arg, sizeof(q))) {
        return -EFAULT;
    }

    p.req.type = q.type;
    ret = fh_gdev_ioctl(filp, GDEV_IOCTL_GQUERY, (char *) &p, sizeof(struct ioctl_query));
    if (ret < 0) {
        return ret;
    }
    q.result = p.req.result;
    if (copy_to_user((void __user *) arg, &q, sizeof(q))) {
        return -EFAULT;
    }
    return 0;
}

int gdev_ioctl_gmalloc(struct file *filp, Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_mem m;
    int ret;
    struct ioctl_malloc p = {0};

    if (copy_from_user(&m, (void __user *) arg, sizeof(m))) {
        return -EFAULT;
    }
    p.req.size = m.size;
    ret = fh_gdev_ioctl(filp, GDEV_IOCTL_GMALLOC, (char *) &p, sizeof(struct ioctl_malloc));
    if (ret < 0) {
        return ret;
    }
    if (p.req.addr == 0) {
        return -ENOMEM;
    }
    m.addr = p.req.addr;

    pr_info_debug("done: 0x%lx=gmalloc(%d)\n", m.addr, p.req.size);
    if (copy_to_user((void __user *) arg, &m, sizeof(m))) {
        return -EFAULT;
    }
    return 0;
}

int gdev_ioctl_gmemcpy_to_device(struct file *filep, Ghandle handle, unsigned long arg)
{
    int ret = 0;
    struct gdev_ioctl_dma dma;
    void *buf_vmalloc; /* XXX: the rest of the code assumes this is vmalloced */

    unsigned long *pfn_buf = NULL;
    unsigned long pfn_num = 0;
    unsigned long pfn_size = 0;
    unsigned long payload_size;
    struct fh_ioctl_memcpy_to_device *payload;
    unsigned long *payload_pfn_buf;

    if (copy_from_user(&dma, (void __user *) arg, sizeof(dma))) {
        return -EFAULT;
    }
    buf_vmalloc = vmalloc(dma.size);
    if (!buf_vmalloc) {
        return -ENOMEM;
    }
    if (copy_from_user(buf_vmalloc, (void __user *) dma.src_buf, dma.size)) {
        ret = -EFAULT;
        goto free_buf_vmalloc;
    }

    ret = get_pfn_for_vmalloc_buf(buf_vmalloc, dma.size, &pfn_buf, &pfn_num);
    if (ret < 0 || pfn_buf == NULL) {
        ret = -ENOMEM;
        goto free_buf_vmalloc;
    }

    pfn_size = pfn_num * sizeof(unsigned long);
    payload_size = pfn_size + sizeof(struct fh_ioctl_memcpy_to_device);
    payload = vmalloc(payload_size);

    if (payload == NULL) {
        ret = -ENOMEM;
        goto free_pfn_buf;
    }
    payload->req.size = dma.size;
    payload->req.dst_addr = dma.dst_addr;
    payload->src_buf_pfn_num = pfn_num;

    payload_pfn_buf = (unsigned long *) &payload->src_buf_pfn;
    memcpy(payload_pfn_buf, pfn_buf, pfn_size);



    ret = fh_gdev_ioctl(filep,
                        GDEV_IOCTL_GMEMCPY_TO_DEVICE,
                        (char *) payload,
                        payload_size);

    if (ret < 0) {
        goto free_payload;
    }

    ret = 0;
    /* fall through */

    free_payload:
    vfree(payload);
    payload = NULL;

    free_pfn_buf:
    vfree(pfn_buf);
    pfn_buf = NULL;

    free_buf_vmalloc:
    vfree(buf_vmalloc);
    buf_vmalloc = NULL;

    return ret;
}

int gdev_ioctl_gmemcpy_from_device(struct file *filp, Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_dma dma;
    int ret;
    void *buf_vmalloc;

    unsigned long *pfn_buf = NULL;
    unsigned long pfn_num = 0;
    unsigned long pfn_size = 0;
    unsigned long payload_size;
    struct fh_ioctl_memcpy_from_device *payload;
    unsigned long *payload_pfn_buf;

    if (copy_from_user(&dma, (void __user *) arg, sizeof(dma))) {
        return -EFAULT;
    }
    buf_vmalloc = vmalloc(dma.size);
    if (!buf_vmalloc) {
        return -ENOMEM;
    }

    ret = get_pfn_for_vmalloc_buf(buf_vmalloc, dma.size, &pfn_buf, &pfn_num);
    if (ret < 0 || pfn_buf == NULL) {
        ret = -ENOMEM;
        goto free_buf_vmalloc;
    }

    pfn_size = pfn_num * sizeof(unsigned long);
    payload_size = pfn_size + sizeof(struct fh_ioctl_memcpy_from_device);

    payload = vmalloc(payload_size);
    if (payload == NULL) {
        ret = -ENOMEM;
        goto free_pfn_buf;
    }
    memset(payload, 0, payload_size);

    // user payload
    payload->req.size = dma.size;
    payload->req.src_addr = dma.src_addr;
    payload->dest_buf_pfn_num = pfn_num;

    payload_pfn_buf = (unsigned long *) &payload->dest_buf_pfn;
    memcpy(payload_pfn_buf, pfn_buf, pfn_size);

    ret = fh_gdev_ioctl(filp,
                        GDEV_IOCTL_GMEMCPY_FROM_DEVICE,
                        (char *) payload,
                        payload_size);

    if (ret) {
        goto free_payload;
    }
    if (copy_to_user((void __user *) dma.dst_buf, buf_vmalloc, dma.size)) {
        ret = -EFAULT;
        goto free_payload;
    }

    ret = 0;
    /* fall through */

    free_payload:
    vfree(payload);
    payload = NULL;

    free_pfn_buf:
    vfree(pfn_buf);
    pfn_buf = NULL;

    free_buf_vmalloc:
    vfree(buf_vmalloc);
    buf_vmalloc = NULL;

    return ret;
}

int gdev_ioctl_glaunch(struct file *filp, Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_launch launch;
    struct gdev_kernel kernel;
    uint32_t id;
    int ret = 0;

    unsigned long kernel_param_size;
    uint32_t * kernel_param_buf = NULL;
    unsigned long payload_size;

    if (copy_from_user(&launch, (void __user *) arg, sizeof(launch))) {
        return -EFAULT;
    }

    if (copy_from_user(&kernel, (void __user *) launch.kernel, sizeof(kernel))) {
        return -EFAULT;
    }

    kernel_param_size = kernel.param_size;
    payload_size = sizeof(struct fh_ioctl_glaunch) + kernel_param_size;

    struct fh_ioctl_glaunch *payload = vmalloc(payload_size);
    if (!payload) {
        return -ENOMEM;
    }
    memcpy(&payload->kernel, &kernel, sizeof(struct gdev_kernel));
    payload->kernel_param_size = kernel_param_size;
    kernel_param_buf = (uint32_t *) &payload->kernel_param;

    if (copy_from_user(kernel_param_buf,
                       (void __user *) kernel.param_buf,
                       kernel_param_size)) {
        ret = -EFAULT;
        goto free_payload;
    }
    ret = fh_gdev_ioctl(filp, GDEV_IOCTL_GLAUNCH, (char *) payload, payload_size);
    if (ret < 0) {
        goto free_payload;
    }
    id = payload->id;
    pr_info_debug("launch id: %d\n", id);

    if (copy_to_user((void __user *) launch.id, &id, sizeof(id))) {
        ret = -EFAULT;
        goto free_payload;
    }

    ret = 0;
    /* fall through */

    free_payload:
    vfree(payload);
    payload = NULL;
    return ret;
}

int gdev_ioctl_gsync(struct file *filp, Ghandle handle, unsigned long arg)
{
    int ret = 0;
    struct gdev_ioctl_sync sync;
    struct gdev_time timeout = {};
    uint8_t has_timeout = 0;
    struct fh_ioctl_gsync payload = {0};

    if (copy_from_user(&sync, (void __user *) arg, sizeof(sync))) {
        return -EFAULT;
    }
    if (sync.timeout) {
        if (copy_from_user(&timeout, (void __user *) sync.timeout, sizeof(timeout))) {
            return -EFAULT;
        }
        has_timeout = 1;
    }

    payload.has_timeout = has_timeout;
    payload.id = sync.id;
    if (has_timeout) {
        memcpy(&payload.timeout, &timeout, sizeof(timeout));
    }
    ret = fh_gdev_ioctl(filp,
                        GDEV_IOCTL_GSYNC,
                        (char *) &payload,
                        sizeof(struct fh_ioctl_gsync));
    if (ret < 0) {
        return ret;
    }

    return ret;
}

int gdev_ioctl_gbarrier(struct file *filp, Ghandle handle, unsigned long arg)
{
    char dummy[16] = "emacs";
    return fh_gdev_ioctl(filp, GDEV_IOCTL_GBARRIER, dummy, sizeof(dummy));
}

int gdev_ioctl_gfree(struct file *filp, Ghandle handle, unsigned long arg)
{
    int ret = 0;
    struct gdev_ioctl_mem m;
    struct fh_ioctl_gfree payload = {0};

    if (copy_from_user(&m, (void __user *) arg, sizeof(m))) {
        return -EFAULT;
    }

    payload.req.addr = m.addr;
    ret = fh_gdev_ioctl(filp,
                        GDEV_IOCTL_GFREE,
                        (char *) &payload,
                        sizeof(struct fh_ioctl_gfree));
    if (ret < 0) {
        return ret;
    }
    if (payload.req.size == 0) {
        return -ENOMEM;
    }
    m.size = payload.req.size;

    if (copy_to_user((void __user *) arg, &m, sizeof(m))) {
        return -EFAULT;
    }
    return 0;
}

int gdev_ioctl_gmalloc_dma(struct file *filp, Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_mem m;
    int ret;

    unsigned long *pfn_buf;
    unsigned long pfn_num;
    struct fh_ioctl_gmalloc_dma *payload;
    unsigned long payload_size;
    unsigned long pfn_size;
    unsigned long buf_vmalloc_size;

    if (copy_from_user(&m, (void __user *) arg, sizeof(m))) {
        return -EFAULT;
    }

    buf_vmalloc_size = DIV_ROUND_UP(m.size, PAGE_SIZE);
    pr_info_debug("m.size: %d\n", m.size);

    void *buf_vmalloc = vmalloc(buf_vmalloc_size);
    if (!buf_vmalloc) {
        return -ENOMEM;
    }

    // ensure no cow page on x86 host
    memset(buf_vmalloc, 0xFF, buf_vmalloc_size);

    ret = vmalloc_payload_for_pfn_escape(buf_vmalloc,
                                         m.size,
                                         sizeof(struct fh_ioctl_gmalloc_dma),
                                         &pfn_buf,
                                         &pfn_num,
                                         (void **) &payload,
                                         &payload_size

    );
    if (ret < 0) {
        pr_info("vmalloc_payload_for_pfn_escape failed: %d\n ", ret);
        goto free_buf_vmalloc;
    }

    pfn_size = sizeof(unsigned long) * pfn_num;
    if (payload_size != pfn_size + sizeof(struct fh_ioctl_gmalloc_dma)) {
        pr_info("inconsistent state!\n");
        ret = -EINVAL;
        goto free_pfn_escape;
    }

    memcpy(&payload->buf_pfn, pfn_buf, pfn_size);
    pr_info_debug("buf_num: %ld, size: %ld\n", pfn_num, m.size);
    payload->buf_pfn_num = pfn_num;
    payload->req.size = m.size;
    payload->req.addr = 0;

    ret = fh_gdev_ioctl(filp,
                        GDEV_IOCTL_GMALLOC_DMA,
                        (char *) payload,
                        payload_size);
    if (ret < 0) {
        goto free_pfn_escape;
    }
    if (payload->req.addr == 0) {
        ret = -ENOMEM;
        goto free_pfn_escape;
    }

    #if 1
    struct mmap_node *entry = kmalloc(sizeof(struct mmap_node), GFP_KERNEL);
    if (!entry) {
        ret = -ENOMEM;
        goto free_pfn_escape;
    }
    memset(entry, 0, sizeof(struct mmap_node));
    entry->k_buffer = (unsigned long) buf_vmalloc;
    entry->usr_space_addr = (unsigned long) payload->req.addr;
    INIT_LIST_HEAD(&entry->list);
    list_add(&(entry->list), &handle->mmap_head);
    #endif

    /*
     * mmap expects: (vma->vm_pgoff << PAGE_SHIFT);
     */
    m.addr = ((unsigned long) (buf_vmalloc));
    pr_info_debug("done: 0x%lx=gmalloc_dma(%d)\n", m.addr, m.size);

    if (copy_to_user((void __user *) arg, &m, sizeof(m))) {
        ret = -EFAULT;
        goto free_pfn_escape;
    }

    ret = 0;
    /* fall through */

    free_pfn_escape:
    vfree(pfn_buf);
    pfn_buf = NULL;
    vfree(payload);
    payload = NULL;

    free_buf_vmalloc:
    vfree(buf_vmalloc);
    buf_vmalloc = NULL;

    return ret;
}

int gdev_ioctl_gfree_dma(struct file *filp, Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_mem m;
    int ret = 0;
    struct fh_ioctl_gfree_dma payload = {0};

    if (copy_from_user(&m, (void __user *) arg, sizeof(m))) {
        return -EFAULT;
    }

    /*
     * "OS-space" buffer address
     * m->addr
     */
    struct mmap_node *target_node = mmap_node_get_by_kaddr(handle, m.addr);
    if (target_node == NULL) {
        pr_info("invalid state: cant find addr for requested addr: %lx\n", m.addr);
        return -EINVAL;
    }

    payload.req.addr = target_node->usr_space_addr;
    ret = fh_gdev_ioctl(filp,
                        GDEV_IOCTL_GFREE_DMA,
                        (char *) &payload,
                        sizeof(struct fh_ioctl_gfree_dma));
    if (ret < 0) {
        return ret;
    }
    if (payload.req.size == 0) {
        return -ENOMEM;
    }
    m.size = payload.req.size;

    list_del(&target_node->list);
    kfree(target_node);

    pr_info_debug("gdev_ioctl_gfree_dma: addr=%lx, size=%lx\n", m.addr, m.size);
    if (copy_to_user((void __user *) arg, &m, sizeof(m))) {
        return -EFAULT;
    }
    return 0;
}

/*
 * Passes back the device pointer pdptr corresponding to the mapped, pinned
 * host buffer p allocated by cuMemHostAlloc.
 * given an address in userspace, get the device memory address
 * I need to store a mapping: kernel pointer -> x86 userspace poitner
 */
int gdev_ioctl_gvirtget(struct file *filp, Ghandle handle, unsigned long arg)
{
    int ret = 0;
    struct gdev_ioctl_phys p;
    struct fh_ioctl_gvirtget payload = {0};

    if (copy_from_user(&p, (void __user *) arg, sizeof(p))) {
        return -EFAULT;
    }
    struct mmap_node *mmap_node = mmap_node_get_by_kaddr(handle, p.addr);
    if (mmap_node == NULL) {
        pr_info("mmap_node_get_by_kaddr no res for req: %lx\n", p.addr);
        return -EINVAL;
    }

    payload.req.addr = mmap_node->usr_space_addr;
    ret = fh_gdev_ioctl(filp,
                        GDEV_IOCTL_GVIRTGET,
                        (char *) &payload,
                        sizeof(struct fh_ioctl_gvirtget));
    if (ret < 0) {
        return ret;
    }
    p.phys = payload.req.phys;
    pr_info_debug("gvirtget: %lx -> %lx -> %lx\n", p.addr, payload.req.addr, p.phys);

    if (copy_to_user((void __user *) arg, &p, sizeof(p))) {
        return -EFAULT;
    }
    return 0;
}

int gdev_ioctl_gphysget(struct file *filp, Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_phys p;

    if (copy_from_user(&p, (void __user *) arg, sizeof(p)))
        return -EFAULT;

    if (!(p.phys = gphysget(handle, (void *) p.addr)))
        return -EINVAL;

    if (copy_to_user((void __user *) arg, &p, sizeof(p)))
        return -EFAULT;

    return 0;
}

int gdev_ioctl_get_handle(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_handle h;
    h.handle = (uint64_t) handle;
    if (copy_to_user((void __user *) arg, &h, sizeof(h)))
        return -EFAULT;

    return 0;
}

int gdev_ioctl_gmap(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_map m;

    if (copy_from_user(&m, (void __user *) arg, sizeof(m)))
        return -EFAULT;

    if (!(m.buf = (uint64_t) gmap(handle, m.addr, m.size)))
        return -ENOMEM;

    if (copy_to_user((void __user *) arg, &m, sizeof(m)))
        return -EFAULT;

    return 0;
}

int gdev_ioctl_gunmap(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_map m;

    if (copy_from_user(&m, (void __user *) arg, sizeof(m)))
        return -EFAULT;

    if (gunmap(handle, (void *) m.buf))
        return -ENOENT;

    return 0;
}

int gdev_ioctl_gmemcpy_to_device_async(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_dma dma;
    int ret;
    int id;
    void *buf;

    if (copy_from_user(&dma, (void __user *) arg, sizeof(dma)))
        return -EFAULT;

    buf = vmalloc(dma.size);
    if (!buf)
        return -ENOMEM;

    if (copy_from_user(buf, (void __user *) dma.src_buf, dma.size))
        return -EFAULT;

    ret = gmemcpy_to_device_async(handle, dma.dst_addr, buf, dma.size, &id);
    if (ret)
        return ret;

    vfree(buf);

    if (copy_to_user((void __user *) dma.id, &id, sizeof(id)))
        return -EFAULT;

    return 0;
}

int gdev_ioctl_gmemcpy_from_device_async(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_dma dma;
    int ret;
    int id;
    void *buf;

    if (copy_from_user(&dma, (void __user *) arg, sizeof(dma)))
        return -EFAULT;

    buf = vmalloc(dma.size);

    if (!buf)
        return -ENOMEM;

    ret = gmemcpy_from_device_async(handle, buf, dma.src_addr, dma.size, &id);
    if (ret)
        return ret;

    if (copy_to_user((void __user *) dma.dst_buf, buf, dma.size))
        return -EFAULT;

    vfree(buf);

    if (copy_to_user((void __user *) dma.id, &id, sizeof(id)))
        return -EFAULT;

    return 0;
}

int gdev_ioctl_gmemcpy(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_dma dma;

    if (copy_from_user(&dma, (void __user *) arg, sizeof(dma)))
        return -EFAULT;

    return gmemcpy(handle, dma.dst_addr, dma.src_addr, dma.size);
}

int gdev_ioctl_gmemcpy_async(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_dma dma;
    int id;
    int ret;

    if (copy_from_user(&dma, (void __user *) arg, sizeof(dma)))
        return -EFAULT;

    ret = gmemcpy_async(handle, dma.dst_addr, dma.src_addr, dma.size, &id);
    if (ret)
        return ret;

    if (copy_to_user((void __user *) dma.id, &id, sizeof(id)))
        return -EFAULT;

    return 0;
}

int gdev_ioctl_gshmget(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_shm s;

    if (copy_from_user(&s, (void __user *) arg, sizeof(s)))
        return -EFAULT;

    return gshmget(handle, s.key, s.size, s.flags);
}

int gdev_ioctl_gshmat(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_shm s;

    if (copy_from_user(&s, (void __user *) arg, sizeof(s)))
        return -EFAULT;

    return gshmat(handle, s.id, s.addr, s.flags);
}

int gdev_ioctl_gshmdt(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_shm s;

    if (copy_from_user(&s, (void __user *) arg, sizeof(s)))
        return -EFAULT;

    return gshmdt(handle, s.addr);
}

int gdev_ioctl_gshmctl(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_shm s;
    struct shmid_ds ds;

    if (copy_from_user(&s, (void __user *) arg, sizeof(s)))
        return -EFAULT;

    if (s.buf) {
        if (copy_from_user(&ds, (void __user *) s.buf, sizeof(ds)))
            return -EFAULT;
    } else {
        memset(&ds, 0, sizeof(ds));
    }

    return gshmctl(handle, s.id, s.cmd, (void *) &ds);
}

int gdev_ioctl_gref(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_ref r;

    if (copy_from_user(&r, (void __user *) arg, sizeof(r)))
        return -EFAULT;

    if (!(r.addr_slave = gref(handle, r.addr, r.size, (Ghandle) r.handle_slave)))
        return -EINVAL;

    if (copy_to_user((void __user *) arg, &r, sizeof(r)))
        return -EFAULT;

    return 0;
}

int gdev_ioctl_gunref(Ghandle handle, unsigned long arg)
{
    struct gdev_ioctl_unref r;

    if (copy_from_user(&r, (void __user *) arg, sizeof(r)))
        return -EFAULT;

    if (gunref(handle, r.addr))
        return -EINVAL;

    return 0;
}