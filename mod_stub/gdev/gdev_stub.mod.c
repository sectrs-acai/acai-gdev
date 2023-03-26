#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0xf6006e78, "__class_create" },
	{ 0xce6aea7b, "class_destroy" },
	{ 0xcf2a6966, "up" },
	{ 0x4829a47e, "memcpy" },
	{ 0xb0f4383b, "remap_pfn_range" },
	{ 0x37a0cba, "kfree" },
	{ 0x9a073853, "seq_lseek" },
	{ 0x81a26655, "proc_create_data" },
	{ 0x95acad87, "fvp_escape_page" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0x92997ed8, "_printk" },
	{ 0xbb95fb10, "__stack_chk_fail" },
	{ 0x6cbbfc54, "__arch_copy_to_user" },
	{ 0xda2a1bcc, "cdev_add" },
	{ 0xe41c478c, "device_create" },
	{ 0x6626afca, "down" },
	{ 0xe4bbc1dd, "kimage_voffset" },
	{ 0x9688de8b, "memstart_addr" },
	{ 0xbded96ed, "fvp_escape_size" },
	{ 0x9166fada, "strncpy" },
	{ 0xbcab6ee6, "sscanf" },
	{ 0x3744cf36, "vmalloc_to_pfn" },
	{ 0x3325190c, "proc_mkdir" },
	{ 0xdcb764ad, "memset" },
	{ 0x7559a826, "seq_read" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x6da467cb, "pfn_is_map_memory" },
	{ 0x999e8297, "vfree" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0xb60e2038, "device_destroy" },
	{ 0xf072e20b, "remove_proc_entry" },
	{ 0x1d1dd55b, "seq_printf" },
	{ 0x12a4e128, "__arch_copy_from_user" },
	{ 0x472cf3b, "register_kprobe" },
	{ 0x732bd232, "single_release" },
	{ 0xeb78b1ed, "unregister_kprobe" },
	{ 0xf24e4560, "kmalloc_trace" },
	{ 0xf50ca7e3, "single_open" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0xa5ccbd6a, "cdev_init" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x32092049, "kmalloc_caches" },
	{ 0x60853e6c, "cdev_del" },
	{ 0xde875201, "d_path" },
	{ 0x6c71e760, "module_layout" },
};

MODULE_INFO(depends, "");

