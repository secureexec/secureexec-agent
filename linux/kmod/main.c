// SPDX-License-Identifier: GPL-2.0-only
/*
 * main.c - secureexec_kmod kernel module
 *
 * Provides:
 *   - Character device /dev/secureexec_kmod
 *   - Exe-path verification on open() (only the agent binary may open the device)
 *   - ioctl dispatch to firewall subsystem
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/file.h>
#include <linux/sched/mm.h>

#include "firewall.h"
#include "compat.h"

#define DEVICE_NAME "secureexec_kmod"
#define CLASS_NAME  "secureexec"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SecureExec");
MODULE_DESCRIPTION("SecureExec kernel module: network isolation and host hardening");
MODULE_VERSION("0.0.0-dev");

/* -------------------------------------------------------------------------
 * Module parameters
 * ------------------------------------------------------------------------- */

static char *agent_exe_path = "/opt/secureexec/bin/secureexec-agent-linux";
module_param(agent_exe_path, charp, 0444);
MODULE_PARM_DESC(agent_exe_path,
    "Absolute path of the agent binary allowed to open /dev/" DEVICE_NAME);

/* -------------------------------------------------------------------------
 * Chardev state
 * ------------------------------------------------------------------------- */

static int      se_major;
static struct class  *se_class;
static struct cdev    se_cdev;
static struct device *se_device;

/* -------------------------------------------------------------------------
 * Exe path verification
 *
 * Resolves the caller's exe file via se_get_exe_file() + d_path() and
 * compares against agent_exe_path. Rejects with -EACCES on mismatch.
 * ------------------------------------------------------------------------- */

static int verify_caller_exe(void)
{
    struct file *exe_file;
    struct mm_struct *mm;
    char *buf, *path_str;
    int ret = -EACCES;

    mm = get_task_mm(current);
    if (!mm)
        return -EACCES;

    /* se_get_exe_file() acquires a reference via mmap_read_lock (compat shim). */
    exe_file = se_get_exe_file(mm);
    mmput(mm);

    if (!exe_file)
        return -EACCES;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        fput(exe_file);
        return -ENOMEM;
    }

    /* Safety: buf is kernel memory, exe_file->f_path is a valid kernel path. */
    path_str = d_path(&exe_file->f_path, buf, PATH_MAX);
    fput(exe_file);

    if (IS_ERR(path_str)) {
        pr_warn("secureexec_kmod: d_path failed: %ld\n", PTR_ERR(path_str));
        ret = -EACCES;
        goto out;
    }

    if (strcmp(path_str, agent_exe_path) == 0) {
        ret = 0;
    } else {
        pr_warn("secureexec_kmod: open() denied for '%s' (expected '%s')\n",
                path_str, agent_exe_path);
        ret = -EACCES;
    }

out:
    kfree(buf);
    return ret;
}

/* -------------------------------------------------------------------------
 * File operations
 * ------------------------------------------------------------------------- */

static int se_dev_open(struct inode *inode, struct file *filp)
{
    return verify_caller_exe();
}

static int se_dev_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static long se_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct se_fw_mode    mode_arg;
    struct se_fw_rule    rule_arg;
    struct se_fw_status  status_arg = {};
    int ret;

    if (_IOC_TYPE(cmd) != SE_KMOD_MAGIC)
        return -ENOTTY;

    switch (cmd) {
    case SE_KMOD_FW_SET_MODE:
        if (copy_from_user(&mode_arg, (void __user *)arg, sizeof(mode_arg)))
            return -EFAULT;
        ret = se_fw_set_mode(mode_arg.mode);
        if (ret == 0)
            pr_info("secureexec_kmod: firewall mode set to %u\n", mode_arg.mode);
        return ret;

    case SE_KMOD_FW_ADD_RULE:
        if (copy_from_user(&rule_arg, (void __user *)arg, sizeof(rule_arg)))
            return -EFAULT;
        return se_fw_add_rule(&rule_arg);

    case SE_KMOD_FW_DEL_RULE:
        if (copy_from_user(&rule_arg, (void __user *)arg, sizeof(rule_arg)))
            return -EFAULT;
        return se_fw_del_rule(&rule_arg);

    case SE_KMOD_FW_GET_STATUS:
        se_fw_get_status(&status_arg);
        if (copy_to_user((void __user *)arg, &status_arg, sizeof(status_arg)))
            return -EFAULT;
        return 0;

    case SE_KMOD_FW_CLEAR_RULES:
        return se_fw_clear_rules();

    case SE_KMOD_GET_ABI_VERSION: {
        __u32 ver = SE_KMOD_ABI_VERSION;
        if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
            return -EFAULT;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

static const struct file_operations se_fops = {
    .owner          = THIS_MODULE,
    .open           = se_dev_open,
    .release        = se_dev_release,
    .unlocked_ioctl = se_dev_ioctl,
};

/* -------------------------------------------------------------------------
 * Module init / exit
 * ------------------------------------------------------------------------- */

static int __init se_kmod_init(void)
{
    dev_t devno;
    int ret;

    /* Allocate a major number dynamically. */
    ret = alloc_chrdev_region(&devno, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("secureexec_kmod: alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }
    se_major = MAJOR(devno);

    cdev_init(&se_cdev, &se_fops);
    se_cdev.owner = THIS_MODULE;
    ret = cdev_add(&se_cdev, devno, 1);
    if (ret < 0) {
        pr_err("secureexec_kmod: cdev_add failed: %d\n", ret);
        goto err_unreg;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    se_class = class_create(CLASS_NAME);
#else
    se_class = class_create(THIS_MODULE, CLASS_NAME);
#endif
    if (IS_ERR(se_class)) {
        ret = PTR_ERR(se_class);
        pr_err("secureexec_kmod: class_create failed: %d\n", ret);
        goto err_cdev;
    }

    se_device = device_create(se_class, NULL, devno, NULL, DEVICE_NAME);
    if (IS_ERR(se_device)) {
        ret = PTR_ERR(se_device);
        pr_err("secureexec_kmod: device_create failed: %d\n", ret);
        goto err_class;
    }

    ret = se_fw_init();
    if (ret < 0) {
        pr_err("secureexec_kmod: se_fw_init failed: %d\n", ret);
        goto err_device;
    }

    pr_info("secureexec_kmod: loaded (major=%d, agent_exe=%s)\n",
            se_major, agent_exe_path);
    return 0;

err_device:
    device_destroy(se_class, devno);
err_class:
    class_destroy(se_class);
err_cdev:
    cdev_del(&se_cdev);
err_unreg:
    unregister_chrdev_region(devno, 1);
    return ret;
}

static void __exit se_kmod_exit(void)
{
    dev_t devno = MKDEV(se_major, 0);

    se_fw_exit();
    device_destroy(se_class, devno);
    class_destroy(se_class);
    cdev_del(&se_cdev);
    unregister_chrdev_region(devno, 1);

    pr_info("secureexec_kmod: unloaded\n");
}

module_init(se_kmod_init);
module_exit(se_kmod_exit);
