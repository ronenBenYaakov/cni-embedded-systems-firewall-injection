#define _GNU_SOURCE
#include "nftables_netlink.h"
#include "nftables_symbols.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#define NF_MAX_EVENTS  512

typedef struct {
    const char *fn;
    const char *sys;
    uint64_t    t_ms;
} nf_event_t;

typedef struct {
    pid_t       pid;
    int         fd;
    uint64_t    start_ms;
    bool        open;

    nf_event_t *events;
    int         event_n;
    int         event_cap;
} nf_window_t;

static nf_window_t g_windows[NF_MAX_WINDOWS];
static int         g_window_n = 0;

static long g_patterns_started = 0;
static long g_patterns_ended   = 0;

#define NF_STRPOOL 4096
static char g_strpool[NF_STRPOOL][96];
static int  g_strpool_n = 0;

static const char *intern(const char *s)
{
    if (g_strpool_n >= NF_STRPOOL) return s;
    snprintf(g_strpool[g_strpool_n], sizeof(g_strpool[0]), "%s", s);
    return g_strpool[g_strpool_n++];
}

static const char *sc_name(long sc)
{
#if defined(SYS_socket)
    if (sc == SYS_socket)         return "socket";
#endif
#if defined(SYS_bind)
    if (sc == SYS_bind)           return "bind";
#endif
#if defined(SYS_sendmsg)
    if (sc == SYS_sendmsg)        return "sendmsg";
#endif
#if defined(SYS_recvmsg)
    if (sc == SYS_recvmsg)        return "recvmsg";
#endif
#if defined(SYS_sendto)
    if (sc == SYS_sendto)         return "sendto";
#endif
#if defined(SYS_recvfrom)
    if (sc == SYS_recvfrom)       return "recvfrom";
#endif
#if defined(SYS_setsockopt)
    if (sc == SYS_setsockopt)     return "setsockopt";
#endif
#if defined(SYS_getsockname)
    if (sc == SYS_getsockname)    return "getsockname";
#endif
#if defined(SYS_getpeername)
    if (sc == SYS_getpeername)    return "getpeername";
#endif
#if defined(SYS_close)
    if (sc == SYS_close)          return "close";
#endif
#if defined(SYS_openat)
    if (sc == SYS_openat)         return "openat";
#endif
#if defined(SYS_read)
    if (sc == SYS_read)           return "read";
#endif
#if defined(SYS_write)
    if (sc == SYS_write)          return "write";
#endif
#if defined(SYS_mmap)
    if (sc == SYS_mmap)           return "mmap";
#endif
#if defined(SYS_munmap)
    if (sc == SYS_munmap)         return "munmap";
#endif
#if defined(SYS_mprotect)
    if (sc == SYS_mprotect)       return "mprotect";
#endif
#if defined(SYS_brk)
    if (sc == SYS_brk)            return "brk";
#endif
#if defined(SYS_pselect6)
    if (sc == SYS_pselect6)       return "pselect6";
#endif
#if defined(SYS_poll)
    if (sc == SYS_poll)           return "poll";
#endif
#if defined(SYS_ioctl)
    if (sc == SYS_ioctl)          return "ioctl";
#endif
#if defined(SYS_fcntl)
    if (sc == SYS_fcntl)          return "fcntl";
#endif
#if defined(SYS_clone)
    if (sc == SYS_clone)          return "clone";
#endif
#if defined(SYS_execve)
    if (sc == SYS_execve)         return "execve";
#endif
#if defined(SYS_exit_group)
    if (sc == SYS_exit_group)     return "exit_group";
#endif
    (void)sc;
    return NULL;
}

static nf_window_t *find_window(pid_t pid, int fd)
{
    for (int i = g_window_n - 1; i >= 0; i--) {
        if (g_windows[i].open &&
            g_windows[i].pid == pid &&
            g_windows[i].fd  == fd)
            return &g_windows[i];
    }
    return NULL;
}

static nf_window_t *any_open_window_for_pid(pid_t pid)
{
    for (int i = g_window_n - 1; i >= 0; i--) {
        if (g_windows[i].open && g_windows[i].pid == pid)
            return &g_windows[i];
    }
    return NULL;
}

void nf_hook_pattern_start(pid_t pid, int fd, uint64_t t)
{
    if (g_window_n >= NF_MAX_WINDOWS) {
        int victim = -1;
        for (int i = 0; i < g_window_n; i++) {
            if (!g_windows[i].open) { victim = i; break; }
        }
        if (victim < 0) return;
        free(g_windows[victim].events);
        memset(&g_windows[victim], 0, sizeof(g_windows[victim]));
        g_window_n = victim + 1;
    }

    nf_window_t *w = &g_windows[g_window_n++];
    memset(w, 0, sizeof(*w));
    w->pid      = pid;
    w->fd       = fd;
    w->start_ms = t;
    w->open     = true;

    g_patterns_started++;

    printf("\033[1;35mpattern start:\033[0m %lu  (pid %d fd %d)\n",
           (unsigned long)t, pid, fd);
    fflush(stdout);
}

void nf_hook_pattern_end(pid_t pid, int fd, uint64_t t)
{
    nf_window_t *w = find_window(pid, fd);
    if (!w) return;

    w->open = false;
    g_patterns_ended++;

    printf("\033[1;36mpattern ended:\033[0m %lu  (pid %d fd %d)"
           "  duration=%lu ms, events=%d\n",
           (unsigned long)t, pid, fd,
           (unsigned long)(t - w->start_ms), w->event_n);

    if (w->event_n == 0) {
        printf("    (no user functions observed)\n");
    } else {
        printf("    functions invoked (in call order):\n");
        for (int i = 0; i < w->event_n; i++) {
            nf_event_t *e = &w->events[i];
            printf("      %-40s  ->  %s\n", e->fn, e->sys);
        }
    }
    fflush(stdout);

    free(w->events);
    w->events = NULL;
    w->event_n = w->event_cap = 0;
}

void nf_hook_syscall(pid_t pid, long sc,
                     const unsigned long args[6],
                     unsigned long ret, bool entering)
{
    (void)args;
    (void)ret;

    if (!entering) return;

    nf_window_t *w = any_open_window_for_pid(pid);
    if (!w) return;

    const char *sys = sc_name(sc);
    if (!sys) {
        static char pool[64][32];
        static int  pool_n = 0;
        if (pool_n < 64) {
            snprintf(pool[pool_n], sizeof(pool[0]),
                     "syscall_%ld", sc);
            sys = pool[pool_n++];
        } else {
            sys = "syscall_?";
        }
    }

    char fnbuf[96] = {0};
    uint64_t rip = 0;
#if defined(__x86_64__)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0)
        rip = regs.rip;
#elif defined(__aarch64__)
    struct user_pt_regs regs;
    struct iovec iov = { &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == 0)
        rip = regs.pc;
#endif

    if (rip && nf_resolve_addr(pid, rip, fnbuf, sizeof(fnbuf))) {
    } else {
        snprintf(fnbuf, sizeof(fnbuf), "0x%llx",
                 (unsigned long long)rip);
    }

    if (w->event_n >= w->event_cap) {
        int ncap = w->event_cap ? w->event_cap * 2 : 32;
        nf_event_t *ne = realloc(w->events, ncap * sizeof(*ne));
        if (!ne) return;
        w->events    = ne;
        w->event_cap = ncap;
    }

    w->events[w->event_n].fn   = intern(fnbuf);
    w->events[w->event_n].sys  = intern(sys);
    w->events[w->event_n].t_ms = 0;
    w->event_n++;
}

void nf_hook_summary(void)
{
    printf("\n=== Hook summary ===\n");
    printf("  patterns started : %ld\n", g_patterns_started);
    printf("  patterns ended   : %ld\n", g_patterns_ended);
    if (g_patterns_started != g_patterns_ended)
        printf("  [!] started != ended\n");
    nf_symbols_free();
}
