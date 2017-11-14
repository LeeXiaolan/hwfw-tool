#define DRV_NAME "hijack"
#define DRV_VERSION "0.1"
#define DRV_DESCRIPTION "Hijack ubifs follow_link."
#define DRV_COPYRIGHT "leexiaolan@gmail.com"

//#include <asm/cacheflush.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/vermagic.h>

#if 7 != __LINUX_ARM_ARCH__
#  error CPU Must be ARMv7.
#endif
#ifndef CONFIG_SMP
#  error Must enable SMP.
#endif


#define HIJACK_PATH "/dev/mtd2ro"
#define HIJACK_SYMBOL_NAME "ubifs_symlink_inode_operations"

typedef void* (*FollowLinkProc)(struct dentry*, struct nameidata*);
static FollowLinkProc followLink;

static void* hookedFollowLink(struct dentry* dentry, struct nameidata* nd){
  followLink(dentry, nd);
	if(strcmp(nd_get_link(nd), HIJACK_PATH)){
		return NULL;
	}else{
		return (void*)-ENOENT;
	}
}

static int hook(void* value){
  struct inode_operations* ops = (struct inode_operations*)kallsyms_lookup_name(HIJACK_SYMBOL_NAME);
  if(NULL == ops){
    printk(KERN_ERR DRV_NAME ": can not find " HIJACK_SYMBOL_NAME ".\n");
    return ENOENT;
  }
  followLink = ops->follow_link;
  printk(KERN_ERR DRV_NAME ": follow_link = %p\n", followLink);
  if(NULL != followLink){
    ops->follow_link = value;
    //clean_dcache_area(&ops->follow_link, 4);
		//__asm__ __volatile__ ("dsb" : : : "memory");
    printk(KERN_ERR DRV_NAME ": good luck %p!\n", value);
		return 0;
  }
	return ENOENT;
}

static int __init hijackInit(void)
{
	printk(KERN_ERR DRV_NAME ": loading...\n");
	return hook(&hookedFollowLink);
}
module_init(hijackInit);

static void hijackCleanup(void)
{
	hook(followLink);
}
module_exit(hijackCleanup);

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
