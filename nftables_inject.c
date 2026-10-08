#define _GNU_SOURCE
#include "nftables_inject.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

typedef struct {
    pid_t    pid;
    int      fd;
    uint64_t remote_va;
    size_t   msg_len;
    unsigned long saved_args[6];
    bool     active;
    bool     reissue;
} nf_injection_t;

#define NF_MAX_INJECTIONS 32
static nf_injection_t g_inj[NF_MAX_INJECTIONS];
static int            g_inj_n = 0;

static bool remote_write(pid_t pid, uint64_t dst,
                         const void *src, size_t len)
{
    const unsigned char *p = src;
    size_t off = 0;

    while (off + sizeof(long) <= len) {
        long word;
        memcpy(&word, p + off, sizeof(word));
        if (ptrace(PTRACE_POKEDATA, pid,
                   (void *)(uintptr_t)(dst + off),
                   (void *)(uintptr_t)word) != 0)
            return false;
        off += sizeof(long);
    }
    if (off < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void *)(uintptr_t)(dst + off), NULL);
        if (word == -1 && errno) return false;
        unsigned char tmp[sizeof(long)];
        memcpy(tmp, &word, sizeof(tmp));
        memcpy(tmp, p + off, len - off);
        memcpy(&word, tmp, sizeof(word));
        if (ptrace(PTRACE_POKEDATA, pid,
                   (void *)(uintptr_t)(dst + off),
                   (void *)(uintptr_t)word) != 0)
            return false;
    }
    return true;
}

static uint64_t find_writable_slack(pid_t pid, size_t need)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[512];
    uint64_t best = 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end, off;
        unsigned int maj, min;
        unsigned long long ino;
        char perms[8];

        int n = sscanf(line, "%llx-%llx %7s %llx %x:%x %llu",
                       &start, &end, perms, &off, &maj, &min, &ino);
        if (n < 7) continue;

        if (perms[0] != 'r' || perms[1] != 'w') continue;

        uint64_t map_len = (uint64_t)end - (uint64_t)start;
        if (map_len < need + 4096) continue;

        uint64_t cand = (uint64_t)end - need - 16;
        if (cand > best) best = cand;
    }
    fclose(fp);
    return best;
}

static nf_injection_t *find_inj(pid_t pid, int fd)
{
    for (int i = 0; i < g_inj_n; i++) {
        if (g_inj[i].pid == pid && g_inj[i].fd == fd)
            return &g_inj[i];
    }
    return NULL;
}

static nf_injection_t *find_inj_by_pid(pid_t pid)
{
    for (int i = 0; i < g_inj_n; i++) {
        if (g_inj[i].pid == pid && g_inj[i].active)
            return &g_inj[i];
    }
    return NULL;
}

bool nf_inject_pending(pid_t pid, int fd)
{
    nf_injection_t *inj = find_inj(pid, fd);
    return inj && inj->active;
}

bool nf_inject_needs_reissue(pid_t pid)
{
    for (int i = 0; i < g_inj_n; i++) {
        if (g_inj[i].pid == pid && g_inj[i].reissue)
            return true;
    }
    return false;
}

bool nf_inject_arm_send(pid_t pid, int fd,
                        const void *msg, size_t msg_len)
{
    if (g_inj_n >= NF_MAX_INJECTIONS)
        return false;
    if (msg_len == 0 || msg_len > 4096)
        return false;

    uint64_t scratch = find_writable_slack(pid, msg_len);
    if (!scratch) {
        fprintf(stderr, "[-] inject: no writable slack in pid %d\n", pid);
        return false;
    }

    if (!remote_write(pid, scratch, msg, msg_len)) {
        fprintf(stderr, "[-] inject: remote_write failed: %s\n",
                strerror(errno));
        return false;
    }

    nf_injection_t *inj = &g_inj[g_inj_n++];
    memset(inj, 0, sizeof(*inj));
    inj->pid        = pid;
    inj->fd         = fd;
    inj->remote_va  = scratch;
    inj->msg_len    = msg_len;
    inj->active     = true;

    printf("\033[1;33m[inject]\033[0m armed %zu bytes at 0x%llx "
           "(pid %d fd %d)\n",
           msg_len, (unsigned long long)scratch, pid, fd);
    fflush(stdout);
    return true;
}

int nf_inject_on_send_entry(pid_t pid, long sc,
                            const unsigned long args[6])
{
    (void)args;

    nf_injection_t *inj = find_inj_by_pid(pid);
    if (!inj || !inj->active)
        return 0;

    bool is_sendto  = false;
    bool is_sendmsg = false;
#if defined(SYS_sendto)
    if (sc == SYS_sendto)  is_sendto  = true;
#endif
#if defined(SYS_sendmsg)
    if (sc == SYS_sendmsg) is_sendmsg = true;
#endif
    if (!is_sendto && !is_sendmsg)
        return 0;

#if defined(__x86_64__)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0)
        return -1;

    int call_fd = (int)regs.rdi;
    if (call_fd != inj->fd)
        return 0;

    memcpy(inj->saved_args,
           (unsigned long[]){ regs.rdi, regs.rsi, regs.rdx,
                              regs.r10, regs.r8,  regs.r9 },
           sizeof(inj->saved_args));

    if (is_sendto) {
        regs.rsi = inj->remote_va;
        regs.rdx = inj->msg_len;
    } else {
        return 0;
    }

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0)
        return -1;

    inj->active  = false;
    inj->reissue = true;

    printf("\033[1;33m[inject]\033[0m swapped sendto args on pid %d "
           "fd %d (orig buf=0x%lx len=%lu)\n",
           pid, call_fd,
           inj->saved_args[1], inj->saved_args[2]);
    fflush(stdout);

    return 1;
#else
    (void)is_sendto; (void)is_sendmsg;
    return 0;
#endif
}

void nf_inject_on_send_exit(pid_t pid, long sc, unsigned long ret)
{
    (void)ret;

    nf_injection_t *inj = find_inj_by_pid(pid);
    if (!inj || !inj->reissue)
        return;

#if defined(__x86_64__)
    bool is_sendto = false;
#if defined(SYS_sendto)
    if (sc == SYS_sendto) is_sendto = true;
#endif
    if (!is_sendto)
        return;

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0)
        return;

    regs.rdi = inj->saved_args[0];
    regs.rsi = inj->saved_args[1];
    regs.rdx = inj->saved_args[2];
    regs.r10 = inj->saved_args[3];
    regs.r8  = inj->saved_args[4];
    regs.r9  = inj->saved_args[5];

    regs.rip -= 2;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0)
        return;

    inj->reissue = false;

    printf("\033[1;33m[inject]\033[0m re-issuing caller's sendto "
           "on pid %d\n", pid);
    fflush(stdout);
#endif
}

void *nf_build_rule(const nf_rule_spec_t *spec, size_t *out_len)
{
    if (!spec) return NULL;

    size_t tn = spec->table_name ? strlen(spec->table_name) + 1 : 0;
    size_t cn = spec->chain_name ? strlen(spec->chain_name) + 1 : 0;
    
    // PCIe network interface name (e.g., PCIe NIC / SR-IOV VF interface)
    const char *pcie_iface = "enp3s0"; 
    size_t if_len = strlen(pcie_iface) + 1;
    size_t if_padded = (4 + if_len + 3) & ~3;

    // Expanded expression block to hold: [meta iifname] + [cmp eq] + [immediate drop]
    size_t expr_block_len = 256;

    size_t need = sizeof(struct nlmsghdr)
                + sizeof(struct nfgenmsg)
                + ((4 + tn + 3) & ~3)
                + ((4 + cn + 3) & ~3)
                + 4 + expr_block_len;

    need = (need + 3) & ~(size_t)3;

    unsigned char *buf = calloc(1, need);
    if (!buf) return NULL;

    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    nh->nlmsg_len   = need;
    nh->nlmsg_type  = (NFNL_SUBSYS_NFTABLES << 8) | 6; // NFT_MSG_NEWRULE
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;
    nh->nlmsg_seq   = 1;
    nh->nlmsg_pid   = 0;

    struct nfgenmsg *ng = (struct nfgenmsg *)(buf + sizeof(*nh));
    ng->nfgen_family = spec->table_family;
    ng->version      = NFNETLINK_V0;
    ng->res_id       = 0;

    unsigned char *p = buf + sizeof(*nh) + sizeof(*ng);

    // Table Name attribute
    struct nlattr *a = (struct nlattr *)p;
    a->nla_type = 1; // NFTA_RULE_TABLE
    a->nla_len  = 4 + tn;
    memcpy(p + 4, spec->table_name, tn);
    p += (4 + tn + 3) & ~3;

    // Chain Name attribute
    a = (struct nlattr *)p;
    a->nla_type = 2; // NFTA_RULE_CHAIN
    a->nla_len  = 4 + cn;
    memcpy(p + 4, spec->chain_name, cn);
    p += (4 + cn + 3) & ~3;

    unsigned char *expr_attr_start = p;
    struct nlattr *expr_container = (struct nlattr *)p;
    expr_container->nla_type = NLA_F_NESTED | 4; // NFTA_RULE_EXPRESSIONS
    p += 4;

    // --- Expression 1: Meta (Match PCIe Interface iifname) ---
    unsigned char *elem1_start = p;
    struct nlattr *elem1 = (struct nlattr *)p;
    elem1->nla_type = NLA_F_NESTED | 1;
    p += 4;

    // Expression name: "meta"
    struct nlattr *ename1 = (struct nlattr *)p;
    ename1->nla_type = 1; // NFTA_EXPR_NAME
    ename1->nla_len  = 4 + 5;
    memcpy(p + 4, "meta", 5);
    p += (4 + 5 + 3) & ~3;

    // Meta data container
    unsigned char *edata1_start = p;
    struct nlattr *edata1 = (struct nlattr *)p;
    edata1->nla_type = NLA_F_NESTED | 2; // NFTA_EXPR_DATA
    p += 4;

    // Meta key: NFT_META_IIFNAME (typically 4 for interface name)
    struct nlattr *mkey = (struct nlattr *)p;
    mkey->nla_type = 1; // NFTA_META_KEY
    mkey->nla_len  = 4 + 4;
    *(uint32_t *)(p + 4) = 4; // NFT_META_IIFNAME
    p += 8;

    // Register destination for meta value
    struct nlattr *mreg = (struct nlattr *)p;
    mreg->nla_type = 2; // NFTA_META_SREG or DREG depending on context
    mreg->nla_len  = 4 + 4;
    *(uint32_t *)(p + 4) = 0; // register 0
    p += 8;

    edata1->nla_len = (p - edata1_start);
    elem1->nla_len  = (p - elem1_start);

    // --- Expression 2: Immediate / Verdict (DROP) ---
    unsigned char *elem2_start = p;
    struct nlattr *elem2 = (struct nlattr *)p;
    elem2->nla_type = NLA_F_NESTED | 1;
    p += 4;

    struct nlattr *ename2 = (struct nlattr *)p;
    ename2->nla_type = 1;
    ename2->nla_len  = 4 + 10;
    memcpy(p + 4, "immediate", 10);
    p += (4 + 10 + 3) & ~3;

    unsigned char *edata2_start = p;
    struct nlattr *edata2 = (struct nlattr *)p;
    edata2->nla_type = NLA_F_NESTED | 2;
    p += 4;

    struct nlattr *dreg = (struct nlattr *)p;
    dreg->nla_type = 1;
    dreg->nla_len  = 4 + 4;
    *(uint32_t *)(p + 4) = 0;
    p += 8;

    struct nlattr *idata = (struct nlattr *)p;
    idata->nla_type = NLA_F_NESTED | 2;
    p += 4;

    struct nlattr *dval = (struct nlattr *)p;
    dval->nla_type = NLA_F_NESTED | 1;
    unsigned char *dval_start = p;
    p += 4;

    struct nlattr *vcode = (struct nlattr *)p;
    vcode->nla_type = 1;
    vcode->nla_len  = 4 + 4;
    *(int32_t *)(p + 4) = -1; // NF_DROP verdict
    p += 8;

    dval->nla_len = (p - dval_start);
    idata->nla_len = (p - (p - 4)); // simplified container wrap
    edata2->nla_len = (p - edata2_start);
    elem2->nla_len = (p - elem2_start);
    expr_container->nla_len = (p - expr_attr_start);

    size_t final_len = (p - buf);
    nh->nlmsg_len = final_len;

    *out_len = final_len;
    return buf;
}

void nf_inject_free(void)
{
    g_inj_n = 0;
    memset(g_inj, 0, sizeof(g_inj));
}
