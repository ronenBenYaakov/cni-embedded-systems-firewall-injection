#ifndef NFTABLES_INJECT_H
#define NFTABLES_INJECT_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/*
 * Install one extra netlink-netfilter message inside the window owned by
 * (pid, fd), just before the caller's first sendto/sendmsg on that fd.
 *
 * The rule bytes are produced by nf_build_rule() and are a raw
 * NETLINK_NETFILTER payload (see linux/netfilter/nf_tables.h or
 * linux/netfilter/ip_tables.h). The tracer writes the bytes into the
 * tracee's memory, then rewrites the caller's sendto/sendmsg arg regs
 * to use them for one call. Afterwards the original args are restored
 * and the caller's own send proceeds unmodified.
 *
 * Returns true if the injection was armed. Injection fires on the next
 * sendto/sendmsg performed on `fd` by `pid`.
 */
bool nf_inject_arm_send(pid_t pid, int fd,
                        const void *msg, size_t msg_len);

/* Is there an injection pending for (pid, fd)? */
bool nf_inject_pending(pid_t pid, int fd);

/*
 * Called by the main tracer when a syscall-entry stop is seen for
 * (pid, sc) and the process has a netfilter window open on any fd.
 * Returns:
 *   0  = do nothing, let the syscall proceed normally
 *   1  = the syscall was rewritten to send the injected message;
 *        the caller's own call will be re-issued on the next syscall
 *        stop (see nf_inject_needs_reissue)
 *  -1  = on error
 */
int  nf_inject_on_send_entry(pid_t pid, long sc,
                             const unsigned long args[6]);

/* After a rewritten send returns, re-arm the original send. */
void nf_inject_on_send_exit(pid_t pid, long sc, unsigned long ret);

/* True if the next stop for (pid) is the caller's re-issued send. */
bool nf_inject_needs_reissue(pid_t pid);

/* Cleanup. */
void nf_inject_free(void);

/* Build a minimal but valid nftables "add rule" message you can pass
 * to nf_inject_arm_send(). You supply the table/chain and the rule
 * expression bytes; this wraps them in the correct headers. */
typedef struct {
    uint32_t table_family;   /* NFPROTO_INET, NFPROTO_IPV4, ... */
    const char *table_name;
    const char *chain_name;
    const void *expr;        /* raw NFTA_LIST_ELEM bytes, optional */
    size_t expr_len;
} nf_rule_spec_t;

/* Allocate and return a wire-format NFNL message; caller frees. */
void *nf_build_rule(const nf_rule_spec_t *spec, size_t *out_len);

#endif /* NFTABLES_INJECT_H */
