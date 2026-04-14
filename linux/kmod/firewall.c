// SPDX-License-Identifier: GPL-2.0-only
/*
 * firewall.c - netfilter packet filtering for secureexec_kmod
 *
 * Registers NF_INET_LOCAL_IN / LOCAL_OUT hooks for IPv4 and IPv6.
 * In ISOLATED mode only packets matching the whitelist are accepted.
 *
 * TCP: stateless SYN-only filtering — only pure SYN (syn=1, ack=0) is
 * checked against the whitelist.  All other TCP packets (SYN-ACK, ACK,
 * data, FIN, RST) pass through, because they cannot establish a new
 * connection.  This is the standard approach used by stateless firewalls
 * (Cisco ACL, AWS Security Groups) and requires no conntrack dependency.
 *
 * UDP: whitelist check on every packet.  Port matching uses dest port for
 * outbound ("which service am I talking to") and source port for inbound
 * ("which service sent this reply").  Agent adds rules in both directions.
 *
 * IPv6: all non-loopback traffic is dropped in ISOLATED mode (agent
 * communication uses IPv4).
 *
 * Uses RCU for the hot path (per-packet hook) so readers never block.
 * Writers (ioctl — process context) are serialized by fw_writer_lock,
 * clone-and-swap the state, and defer-free via kfree_rcu().
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/in.h>
#include <net/net_namespace.h>

#include "firewall.h"
#include "compat.h"

/* -------------------------------------------------------------------------
 * RCU-protected firewall state
 * ------------------------------------------------------------------------- */

struct fw_state {
    __u8               mode;
    unsigned int       rule_count;
    struct se_fw_rule  rules[SE_FW_MAX_RULES];
    struct rcu_head    rcu;
};

static struct fw_state __rcu *fw_current;

/* Serializes all writer operations (process context only). */
static DEFINE_SPINLOCK(fw_writer_lock);

/* -------------------------------------------------------------------------
 * Writer helpers (must be called with fw_writer_lock held)
 * ------------------------------------------------------------------------- */

static inline struct fw_state *fw_writer_deref(void)
{
    return rcu_dereference_protected(fw_current,
               lockdep_is_held(&fw_writer_lock));
}

static struct fw_state *fw_clone(void)
{
    struct fw_state *old = fw_writer_deref();
    /* GFP_ATOMIC: called under spinlock, cannot sleep. */
    struct fw_state *new = kmalloc(sizeof(*new), GFP_ATOMIC);
    if (new)
        memcpy(new, old, offsetof(struct fw_state, rcu));
    return new;
}

static void fw_publish(struct fw_state *new)
{
    struct fw_state *old = fw_writer_deref();
    rcu_assign_pointer(fw_current, new);
    kfree_rcu(old, rcu);
}

/* -------------------------------------------------------------------------
 * Rule matching helpers
 * ------------------------------------------------------------------------- */

static bool rule_matches(const struct se_fw_rule *r,
                         __be32 pkt_ip, __u16 pkt_port,
                         __u8 pkt_proto, __u8 direction)
{
    if (r->ip != 0 && r->ip != pkt_ip)
        return false;
    if (r->port != 0 && r->port != pkt_port)
        return false;
    if (r->proto != SE_FW_PROTO_ANY && r->proto != pkt_proto)
        return false;
    if (r->direction != SE_FW_DIR_ANY && r->direction != direction)
        return false;
    return true;
}

static bool fw_packet_allowed(const struct fw_state *st,
                               __be32 pkt_ip, __u16 pkt_port,
                               __u8 pkt_proto, __u8 direction)
{
    unsigned int i;

    for (i = 0; i < st->rule_count; i++) {
        if (rule_matches(&st->rules[i], pkt_ip, pkt_port, pkt_proto, direction))
            return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 * Extract packet fields from sk_buff
 *
 * TCP: always returns dest port (only called for pure SYN packets where
 *      dest port is the service port in both directions).
 * UDP: outbound → dest port ("which service"), inbound → source port
 *      ("which service sent this").
 * ------------------------------------------------------------------------- */

static bool extract_pkt_fields(struct sk_buff *skb, __u8 direction,
                                __be32 *out_ip, __u16 *out_port, __u8 *out_proto)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return false;

    iph = ip_hdr(skb);
    if (!iph)
        return false;

    *out_proto = iph->protocol;

    /* Use remote endpoint: src for inbound, dst for outbound. */
    if (direction == SE_FW_DIR_IN)
        *out_ip = iph->saddr;
    else
        *out_ip = iph->daddr;

    *out_port = 0;

    if (iph->ihl < 5)
        return false;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
            return false;
        iph = ip_hdr(skb);
        tcph = tcp_hdr(skb);
        if (!tcph)
            return false;
        /* Dest port = service port for SYN in both directions. */
        *out_port = ntohs(tcph->dest);
        break;
    case IPPROTO_UDP:
        if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
            return false;
        iph = ip_hdr(skb);
        udph = udp_hdr(skb);
        if (!udph)
            return false;
        /*
         * Outbound: dest port = "which service am I talking to" (e.g. 53).
         * Inbound:  source port = "which service sent this" (e.g. 53 for
         *           DNS response). This enables stateless bidirectional
         *           UDP matching without conntrack.
         */
        *out_port = (direction == SE_FW_DIR_IN)
                    ? ntohs(udph->source)
                    : ntohs(udph->dest);
        break;
    default:
        break;
    }

    return true;
}

/* -------------------------------------------------------------------------
 * IPv4 loopback check
 * ------------------------------------------------------------------------- */

static bool is_loopback(struct sk_buff *skb)
{
    struct iphdr *iph;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return false;
    iph = ip_hdr(skb);
    if (!iph)
        return false;
    /* 127.0.0.0/8 */
    return (ntohl(iph->saddr) >> 24) == 127 ||
           (ntohl(iph->daddr) >> 24) == 127;
}

/* -------------------------------------------------------------------------
 * Stateless TCP check: is this NOT a new connection attempt?
 *
 * Returns true for all TCP packets except pure SYN (syn=1, ack=0).
 * Pure SYN is the only packet that initiates a new TCP connection;
 * everything else (SYN-ACK, ACK, data, FIN, RST) is return or
 * continuation traffic that we allow unconditionally in ISOLATED mode.
 * ------------------------------------------------------------------------- */

static bool is_tcp_return(struct sk_buff *skb)
{
    const struct iphdr *iph;
    const struct tcphdr *th;
    unsigned int hlen;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return false;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP || iph->ihl < 5)
        return false;
    hlen = iph->ihl * 4;
    if (!pskb_may_pull(skb, hlen + sizeof(struct tcphdr)))
        return false;
    /* Refetch after possible pskb_may_pull reallocation. */
    iph = ip_hdr(skb);
    th = (const struct tcphdr *)((const unsigned char *)iph + hlen);

    /* Pure SYN (syn=1, ack=0) = new connection.  Everything else passes. */
    return !(th->syn && !th->ack);
}

/* -------------------------------------------------------------------------
 * IPv6 loopback check (::1)
 * ------------------------------------------------------------------------- */

static bool is_ipv6_loopback(struct sk_buff *skb)
{
    const struct ipv6hdr *ip6h;

    if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
        return false;
    ip6h = ipv6_hdr(skb);
    if (!ip6h)
        return false;

    return ipv6_addr_loopback(&ip6h->saddr) ||
           ipv6_addr_loopback(&ip6h->daddr);
}

/* -------------------------------------------------------------------------
 * IPv4 netfilter hook (softirq context — RCU read side)
 * ------------------------------------------------------------------------- */

static unsigned int se_fw_hook_fn(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    const struct fw_state *st;
    __be32 pkt_ip;
    __u16  pkt_port;
    __u8   pkt_proto;
    __u8   direction;
    unsigned int verdict;

    rcu_read_lock();
    st = rcu_dereference(fw_current);

    if (st->mode == SE_FW_MODE_NORMAL) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* Always pass loopback in isolated mode. */
    if (is_loopback(skb)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /*
     * Stateless TCP: allow all non-SYN packets (return / continuation
     * traffic).  Only pure SYN (new connection attempt) is checked
     * against the whitelist below.
     */
    if (is_tcp_return(skb)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    direction = (state->hook == NF_INET_LOCAL_IN)
                ? SE_FW_DIR_IN : SE_FW_DIR_OUT;

    if (!extract_pkt_fields(skb, direction, &pkt_ip, &pkt_port, &pkt_proto)) {
        rcu_read_unlock();
        return NF_DROP;
    }

    verdict = fw_packet_allowed(st, pkt_ip, pkt_port, pkt_proto, direction)
              ? NF_ACCEPT : NF_DROP;
    rcu_read_unlock();
    return verdict;
}

/* -------------------------------------------------------------------------
 * IPv6 netfilter hook
 *
 * In ISOLATED mode all IPv6 traffic is dropped except loopback (::1).
 * Agent communication uses IPv4 — no IPv6 whitelist rules needed.
 * ------------------------------------------------------------------------- */

static unsigned int se_fw_hook6_fn(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    const struct fw_state *st;

    rcu_read_lock();
    st = rcu_dereference(fw_current);

    if (st->mode == SE_FW_MODE_NORMAL) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    rcu_read_unlock();

    if (is_ipv6_loopback(skb))
        return NF_ACCEPT;

    return NF_DROP;
}

/* -------------------------------------------------------------------------
 * Hook registrations
 * ------------------------------------------------------------------------- */

static struct nf_hook_ops se_fw_ops[] = {
    /* IPv4 LOCAL_IN */
    {
        .hook     = se_fw_hook_fn,
        .pf       = PF_INET,
        .hooknum  = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
#ifdef SE_NF_HOOK_HAS_OWNER
        .owner    = THIS_MODULE,
#endif
    },
    /* IPv4 LOCAL_OUT */
    {
        .hook     = se_fw_hook_fn,
        .pf       = PF_INET,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
#ifdef SE_NF_HOOK_HAS_OWNER
        .owner    = THIS_MODULE,
#endif
    },
    /* IPv6 LOCAL_IN */
    {
        .hook     = se_fw_hook6_fn,
        .pf       = PF_INET6,
        .hooknum  = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
#ifdef SE_NF_HOOK_HAS_OWNER
        .owner    = THIS_MODULE,
#endif
    },
    /* IPv6 LOCAL_OUT */
    {
        .hook     = se_fw_hook6_fn,
        .pf       = PF_INET6,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
#ifdef SE_NF_HOOK_HAS_OWNER
        .owner    = THIS_MODULE,
#endif
    },
};

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

int se_fw_init(void)
{
    struct fw_state *st;
    int ret = 0;

    st = kzalloc(sizeof(*st), GFP_KERNEL);
    if (!st)
        return -ENOMEM;
    st->mode = SE_FW_MODE_NORMAL;
    rcu_assign_pointer(fw_current, st);

#ifdef SE_NF_REGISTER_RET_VOID
    nf_register_net_hooks(&init_net, se_fw_ops, ARRAY_SIZE(se_fw_ops));
#else
    ret = nf_register_net_hooks(&init_net, se_fw_ops, ARRAY_SIZE(se_fw_ops));
    if (ret < 0) {
        rcu_assign_pointer(fw_current, NULL);
        kfree(st);
    }
#endif
    return ret;
}

void se_fw_exit(void)
{
    struct fw_state *st;

    nf_unregister_net_hooks(&init_net, se_fw_ops, ARRAY_SIZE(se_fw_ops));
    /* No new hook calls after unregister; wait for in-flight readers. */
    synchronize_rcu();
    /* Drain any pending kfree_rcu callbacks from prior writer operations. */
    rcu_barrier();
    st = rcu_dereference_protected(fw_current, 1);
    kfree(st);
}

int se_fw_set_mode(__u8 mode)
{
    struct fw_state *new;

    if (mode != SE_FW_MODE_NORMAL && mode != SE_FW_MODE_ISOLATED)
        return -EINVAL;

    spin_lock_bh(&fw_writer_lock);
    new = fw_clone();
    if (!new) {
        spin_unlock_bh(&fw_writer_lock);
        return -ENOMEM;
    }
    new->mode = mode;
    fw_publish(new);
    spin_unlock_bh(&fw_writer_lock);
    return 0;
}

int se_fw_add_rule(const struct se_fw_rule *rule)
{
    struct fw_state *new;

    spin_lock_bh(&fw_writer_lock);
    if (fw_writer_deref()->rule_count >= SE_FW_MAX_RULES) {
        spin_unlock_bh(&fw_writer_lock);
        return -ENOSPC;
    }
    new = fw_clone();
    if (!new) {
        spin_unlock_bh(&fw_writer_lock);
        return -ENOMEM;
    }
    new->rules[new->rule_count++] = *rule;
    fw_publish(new);
    spin_unlock_bh(&fw_writer_lock);
    return 0;
}

int se_fw_del_rule(const struct se_fw_rule *rule)
{
    struct fw_state *old;
    struct fw_state *new;
    unsigned int i;
    int ret = -ENOENT;

    spin_lock_bh(&fw_writer_lock);
    old = fw_writer_deref();
    for (i = 0; i < old->rule_count; i++) {
        if (memcmp(&old->rules[i], rule, sizeof(*rule)) == 0) {
            new = fw_clone();
            if (!new) {
                spin_unlock_bh(&fw_writer_lock);
                return -ENOMEM;
            }
            memmove(&new->rules[i], &new->rules[i + 1],
                    (new->rule_count - i - 1) * sizeof(*rule));
            new->rule_count--;
            fw_publish(new);
            ret = 0;
            break;
        }
    }
    spin_unlock_bh(&fw_writer_lock);
    return ret;
}

int se_fw_clear_rules(void)
{
    struct fw_state *new;

    spin_lock_bh(&fw_writer_lock);
    new = fw_clone();
    if (!new) {
        spin_unlock_bh(&fw_writer_lock);
        return -ENOMEM;
    }
    new->rule_count = 0;
    fw_publish(new);
    spin_unlock_bh(&fw_writer_lock);
    return 0;
}

void se_fw_get_status(struct se_fw_status *out)
{
    const struct fw_state *st;

    rcu_read_lock();
    st = rcu_dereference(fw_current);
    out->mode       = st->mode;
    out->rule_count = st->rule_count;
    rcu_read_unlock();
}
