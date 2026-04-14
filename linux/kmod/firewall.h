/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * firewall.h - shared ioctl interface and data structures for secureexec_kmod
 *
 * This header is included by both the kernel module and the userspace agent
 * (via a copy under agent/linux/agent/src/kmod_uapi.h).
 */
#ifndef SE_KMOD_FIREWALL_H
#define SE_KMOD_FIREWALL_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* -------------------------------------------------------------------------
 * ioctl command codes
 * ------------------------------------------------------------------------- */

#define SE_KMOD_MAGIC 'S'

/* Set firewall mode (NORMAL or ISOLATED) */
#define SE_KMOD_FW_SET_MODE    _IOW(SE_KMOD_MAGIC, 1, struct se_fw_mode)
/* Add a whitelist rule (no-op if table is full) */
#define SE_KMOD_FW_ADD_RULE    _IOW(SE_KMOD_MAGIC, 2, struct se_fw_rule)
/* Remove a whitelist rule */
#define SE_KMOD_FW_DEL_RULE    _IOW(SE_KMOD_MAGIC, 3, struct se_fw_rule)
/* Query current status */
#define SE_KMOD_FW_GET_STATUS  _IOR(SE_KMOD_MAGIC, 4, struct se_fw_status)
/* Clear all whitelist rules */
#define SE_KMOD_FW_CLEAR_RULES _IO(SE_KMOD_MAGIC,  5)
/* Return the kmod ABI version as a __u32 (allows agent to detect incompatible kmod) */
#define SE_KMOD_GET_ABI_VERSION _IOR(SE_KMOD_MAGIC, 6, __u32)

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */

/* Bump this whenever the ioctl interface changes (new ioctls, struct layout
 * changes, semantic changes).  The agent checks this at open() time and
 * refuses to use a kmod with a mismatched ABI version. */
#define SE_KMOD_ABI_VERSION 1

#define SE_FW_MODE_NORMAL   0  /* pass all traffic */
#define SE_FW_MODE_ISOLATED 1  /* whitelist-only */

#define SE_FW_PROTO_TCP  6
#define SE_FW_PROTO_UDP  17
#define SE_FW_PROTO_ANY  0   /* match any protocol */

#define SE_FW_DIR_IN   1
#define SE_FW_DIR_OUT  2
#define SE_FW_DIR_ANY  0

#define SE_FW_MAX_RULES 64

/* -------------------------------------------------------------------------
 * Structures (must be ABI-stable; add new fields at the end only)
 * ------------------------------------------------------------------------- */

/*
 * SE_KMOD_FW_SET_MODE argument.
 * mode: SE_FW_MODE_NORMAL or SE_FW_MODE_ISOLATED.
 */
struct se_fw_mode {
    __u8  mode;
    __u8  _pad[7];
};

/*
 * SE_KMOD_FW_ADD_RULE / SE_KMOD_FW_DEL_RULE argument.
 *
 * ip: IPv4 address in network byte order (0 = match any).
 * port: TCP/UDP port in host byte order (0 = match any).
 * proto: SE_FW_PROTO_TCP, SE_FW_PROTO_UDP, or SE_FW_PROTO_ANY.
 * direction: SE_FW_DIR_IN, SE_FW_DIR_OUT, or SE_FW_DIR_ANY.
 */
struct se_fw_rule {
    __be32 ip;
    __u16  port;
    __u8   proto;
    __u8   direction;
};

/*
 * SE_KMOD_FW_GET_STATUS result.
 *
 * mode: current mode (SE_FW_MODE_*).
 * rule_count: number of active whitelist rules.
 */
struct se_fw_status {
    __u8  mode;
    __u8  _pad[3];
    __u32 rule_count;
};

/* -------------------------------------------------------------------------
 * Kernel-internal firewall API (not visible to userspace)
 * ------------------------------------------------------------------------- */
#ifdef __KERNEL__

int  se_fw_init(void);
void se_fw_exit(void);

int  se_fw_set_mode(__u8 mode);
int  se_fw_add_rule(const struct se_fw_rule *rule);
int  se_fw_del_rule(const struct se_fw_rule *rule);
int  se_fw_clear_rules(void);
void se_fw_get_status(struct se_fw_status *out);

#endif /* __KERNEL__ */

#endif /* SE_KMOD_FIREWALL_H */
