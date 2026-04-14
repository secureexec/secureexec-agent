/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * compat.h - kernel version compatibility shims for secureexec_kmod
 *
 * Supports Linux 5.4+ and 6.x.
 */
#ifndef SE_KMOD_COMPAT_H
#define SE_KMOD_COMPAT_H

#include <linux/version.h>

/*
 * nf_hook_ops.owner was removed in 6.0.
 * In 5.x it must be set to THIS_MODULE.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define SE_NF_HOOK_HAS_OWNER 1
#endif

/*
 * nf_register_net_hook() / nf_unregister_net_hook() return type changed
 * from int to void in 6.1.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define SE_NF_REGISTER_RET_VOID 1
#endif

/*
 * get_mm_exe_file() lost EXPORT_SYMBOL in Linux 6.x (still exists in the
 * kernel but is no longer accessible to loadable modules).
 *
 * On 5.x kernels the function is still exported — use it directly.
 * On 6.x we reimplement it using universally-exported primitives:
 *   mmap_read_lock / mmap_read_unlock  (available since 5.8)
 *   rcu_dereference_protected          (macro, no symbol needed)
 *   get_file()                         (always exported)
 *
 * Use se_get_exe_file() everywhere instead of get_mm_exe_file().
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)

/* 5.x: get_mm_exe_file() is still EXPORT_SYMBOL. */
static inline struct file *se_get_exe_file(struct mm_struct *mm)
{
    return get_mm_exe_file(mm);
}

#else /* >= 6.0 */

#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/rcupdate.h>
#include <linux/mmap_lock.h>

static inline struct file *se_get_exe_file(struct mm_struct *mm)
{
    struct file *exe_file;
    mmap_read_lock(mm);
    exe_file = rcu_dereference_protected(mm->exe_file,
                    lockdep_is_held(&mm->mmap_lock));
    if (exe_file)
        get_file(exe_file);
    mmap_read_unlock(mm);
    return exe_file;
}

#endif

#endif /* SE_KMOD_COMPAT_H */
