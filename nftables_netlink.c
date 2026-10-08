#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#include "nftables_netlink.h"
#include "nftables_inject.h"

#define DEFAULT_CNI_BIN_DIR "/opt/cni/bin"
#define DEFAULT_TEST_NETNS  "cni-scan-ns"
#define DEFAULT_TEST_IFNAME "veth-scan"
#define NETNS_DIR           "/var/run/netns"
#define MAX_TRACKED_PIDS    256
#define MAX_PATH            512
#define MAX_CFG             (64 * 1024)
#define MAX_NF_FDS          64

typedef struct {
    pid_t    pid;
    uint64_t start_time;
    bool     in_syscall;

    int      nf_fds[MAX_NF_FDS];
    int      nf_fd_count;

    bool     socket_pending;
    int      pending_domain;
    int      pending_protocol;
} tracked_proc_t;

static char g_cni_bin_dir[MAX_PATH] = DEFAULT_CNI_BIN_DIR;
static char g_test_netns[64]        = DEFAULT_TEST_NETNS;
static char g_test_ifname[64]       = DEFAULT_TEST_IFNAME;
static char g_container_id[64]      = {0};
static char g_netns_path[MAX_PATH]  = {0};
static int  g_auto_prevresult       = 1;

/* Injection control */
static int  g_enable_inject = 0;   /* set by ENABLE_INJECT=1 */

static volatile sig_atomic_t g_stop = 0;

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static uint64_t get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void on_sig(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int is_executable(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) && (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));
}

static int ensure_netns(const char *name)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s", NETNS_DIR, name);

    if (access(path, F_OK) == 0)
        return 0;

    mkdir(NETNS_DIR, 0755);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip netns add %s >/dev/null 2>&1", name);
    if (system(cmd) != 0) {
        fprintf(stderr, "[-] Failed to create netns %s\n", name);
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Config augmentation                                                        */
/* -------------------------------------------------------------------------- */

static int cfg_has_prevresult(const char *cfg)
{
    return cfg && strstr(cfg, "\"prevResult\"") != NULL;
}

static char *inject_prevresult(const char *cfg, const char *netns, const char *ifname)
{
    const char *snippet =
        ",\"prevResult\":{"
          "\"cniVersion\":\"1.0.0\","
          "\"interfaces\":["
            "{\"name\":\"%s\",\"sandbox\":\"%s\"}"
          "],"
          "\"ips\":["
            "{\"version\":\"4\",\"address\":\"10.99.0.2/24\","
             "\"gateway\":\"10.99.0.1\",\"interface\":0}"
          "],"
          "\"routes\":[{\"dst\":\"0.0.0.0/0\",\"gw\":\"10.99.0.1\"}],"
          "\"dns\":{}"
        "}";

    char augmented[1024];
    snprintf(augmented, sizeof(augmented), snippet,
             ifname ? ifname : "veth-scan",
             netns  ? netns  : "");

    if (!cfg || !*cfg) {
        size_t need = strlen(augmented) + 64;
        char *out = malloc(need);
        if (!out) return NULL;
        snprintf(out, need, "{%s}", augmented + 1);
        return out;
    }

    size_t clen = strlen(cfg);
    if (clen + strlen(augmented) + 4 > MAX_CFG) {
        fprintf(stderr, "[-] Config too large to augment\n");
        return NULL;
    }

    const char *last = strrchr(cfg, '}');
    if (!last) {
        size_t need = clen + strlen(augmented) + 1;
        char *out = malloc(need);
        if (!out) return NULL;
        snprintf(out, need, "%s%s", cfg, augmented);
        return out;
    }

    size_t head_len = (size_t)(last - cfg);
    size_t need     = head_len + strlen(augmented) + 2;
    char *out = malloc(need);
    if (!out) return NULL;
    memcpy(out, cfg, head_len);
    strcpy(out + head_len, augmented);
    out[head_len + strlen(augmented)]     = '}';
    out[head_len + strlen(augmented) + 1] = '\0';
    return out;
}

/* -------------------------------------------------------------------------- */
/* Per-process netlink-nf fd tracking                                         */
/* -------------------------------------------------------------------------- */

static bool nf_fd_remove(tracked_proc_t *tp, int fd)
{
    for (int i = 0; i < tp->nf_fd_count; i++) {
        if (tp->nf_fds[i] == fd) {
            tp->nf_fds[i] = tp->nf_fds[--tp->nf_fd_count];
            return true;
        }
    }
    return false;
}

static void nf_fd_add(tracked_proc_t *tp, int fd)
{
    if (tp->nf_fd_count < MAX_NF_FDS)
        tp->nf_fds[tp->nf_fd_count++] = fd;
}

/* -------------------------------------------------------------------------- */
/* Injection helper                                                           */
/* -------------------------------------------------------------------------- */

/*
 * Called right after a netlink-nf window is opened for (pid, fd).
 * Builds a rule of our own and arms it to be sent on the next
 * sendto()/sendmsg() the plugin issues on that fd.
 *
 * The rule here is a placeholder — edit nf_build_rule()'s caller to
 * shape the message you actually want to install. By default we do
 * nothing unless ENABLE_INJECT=1 is set in the environment.
 */
static void maybe_arm_injection(pid_t pid, int fd)
{
    if (!g_enable_inject)
        return;

    nf_rule_spec_t spec = {
        .table_family = 2,      /* NFPROTO_IPV4 */
        .table_name   = "filter",
        .chain_name   = "INPUT",
        .expr         = NULL,
        .expr_len     = 0,
    };

    size_t len = 0;
    void *msg = nf_build_rule(&spec, &len);
    if (!msg) {
        fprintf(stderr, "[-] inject: nf_build_rule failed\n");
        return;
    }

    if (!nf_inject_arm_send(pid, fd, msg, len))
        fprintf(stderr, "[-] inject: arm failed for pid %d fd %d\n",
                pid, fd);

    free(msg);
}

/* -------------------------------------------------------------------------- */
/* Syscall inspection                                                         */
/* -------------------------------------------------------------------------- */

static void check_syscall(pid_t pid, tracked_proc_t *tp, bool entering)
{
#if defined(__x86_64__)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0)
        return;

    long sc = (long)regs.orig_rax;
    unsigned long args[6] = {
        regs.rdi, regs.rsi, regs.rdx,
        regs.r10, regs.r8,  regs.r9
    };

    nf_hook_syscall(pid, sc, args, regs.rax, entering);

    if (entering) {
        /* If a window is armed for this pid, let the injector rewrite
         * the sendto/sendmsg args before the kernel sees them. */
        nf_inject_on_send_entry(pid, sc, args);

        if (sc == SYS_socket) {
            int domain   = (int)regs.rdi;
            int protocol = (int)regs.rdx;
            if (domain == AF_NETLINK && protocol == NETLINK_NETFILTER) {
                tp->socket_pending   = true;
                tp->pending_domain   = domain;
                tp->pending_protocol = protocol;
            }
        } else if (sc == SYS_close) {
            int fd = (int)regs.rdi;
            if (nf_fd_remove(tp, fd)) {
                nf_hook_pattern_end(pid, fd, get_time_ms());
            }
        }
    } else {
        /* On exit, if we just sent our injected message, restore the
         * caller's args and rewind RIP so the caller's own send runs
         * next. */
        nf_inject_on_send_exit(pid, sc, regs.rax);

        if (tp->socket_pending && sc == SYS_socket) {
            tp->socket_pending = false;
            long ret = (long)regs.rax;
            if (ret >= 0) {
                int fd = (int)ret;
                nf_fd_add(tp, fd);
                nf_hook_pattern_start(pid, fd, get_time_ms());
                maybe_arm_injection(pid, fd);
            }
        }
    }
#elif defined(__aarch64__)
    struct user_pt_regs regs;
    struct iovec iov = { &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0)
        return;

    long sc = (long)regs.regs[8];
    unsigned long args[6] = {
        regs.regs[0], regs.regs[1], regs.regs[2],
        regs.regs[3], regs.regs[4], regs.regs[5]
    };

    nf_hook_syscall(pid, sc, args, regs.regs[0], entering);

    if (entering) {
        nf_inject_on_send_entry(pid, sc, args);

        if (sc == SYS_socket) {
            int domain   = (int)regs.regs[0];
            int protocol = (int)regs.regs[2];
            if (domain == AF_NETLINK && protocol == NETLINK_NETFILTER) {
                tp->socket_pending   = true;
                tp->pending_domain   = domain;
                tp->pending_protocol = protocol;
            }
        } else if (sc == SYS_close) {
            int fd = (int)regs.regs[0];
            if (nf_fd_remove(tp, fd))
                nf_hook_pattern_end(pid, fd, get_time_ms());
        }
    } else {
        nf_inject_on_send_exit(pid, sc, regs.regs[0]);

        if (tp->socket_pending && sc == SYS_socket) {
            tp->socket_pending = false;
            long ret = (long)regs.regs[0];
            if (ret >= 0) {
                int fd = (int)ret;
                nf_fd_add(tp, fd);
                nf_hook_pattern_start(pid, fd, get_time_ms());
                maybe_arm_injection(pid, fd);
            }
        }
    }
#else
    (void)pid; (void)tp; (void)entering;
#endif
}

static void close_all_patterns(pid_t pid, tracked_proc_t *tp)
{
    uint64_t t = get_time_ms();
    while (tp->nf_fd_count > 0) {
        int fd = tp->nf_fds[--tp->nf_fd_count];
        nf_hook_pattern_end(pid, fd, t);
    }
}

/* -------------------------------------------------------------------------- */
/* ptrace                                                                     */
/* -------------------------------------------------------------------------- */

static const unsigned long PTRACE_OPTS =
    PTRACE_O_TRACESYSGOOD |
    PTRACE_O_TRACEFORK    |
    PTRACE_O_TRACEVFORK   |
    PTRACE_O_TRACECLONE   |
    PTRACE_O_TRACEEXEC    |
    PTRACE_O_EXITKILL;

static void trace_loop(tracked_proc_t *tracked, int *count)
{
    while (*count > 0 && !g_stop) {
        int status;
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            perror("waitpid");
            break;
        }

        int slot = -1;
        for (int i = 0; i < *count; i++) {
            if (tracked[i].pid == pid) { slot = i; break; }
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (slot >= 0) {
                close_all_patterns(pid, &tracked[slot]);
                tracked[slot] = tracked[*count - 1];
                (*count)--;
            }
            continue;
        }

        if (!WIFSTOPPED(status))
            continue;

        int sig = WSTOPSIG(status);
        unsigned long event = (unsigned long)status >> 16;

        if (slot < 0) {
            if (*count < MAX_TRACKED_PIDS) {
                if (ptrace(PTRACE_SETOPTIONS, pid, NULL,
                           (void *)PTRACE_OPTS) != 0) {
                    ptrace(PTRACE_DETACH, pid, NULL, NULL);
                    continue;
                }
                memset(&tracked[*count], 0, sizeof(tracked[*count]));
                tracked[*count].pid        = pid;
                tracked[*count].start_time = get_time_ms();
                tracked[*count].in_syscall = false;
                (*count)++;
            }
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        if (sig == SIGTRAP && event != 0) {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        if (sig == (SIGTRAP | 0x80)) {
            bool entering = !tracked[slot].in_syscall;
            tracked[slot].in_syscall = entering;
            check_syscall(pid, &tracked[slot], entering);
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        if (sig == SIGTRAP) {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)sig);
    }
}

/* -------------------------------------------------------------------------- */
/* CNI invocation                                                             */
/* -------------------------------------------------------------------------- */

static int run_cni(const char *plugin, const char *cmd,
                   const char *cfg, const char *netns, const char *ifname)
{
    char plugin_path[MAX_PATH + 64];
    snprintf(plugin_path, sizeof(plugin_path), "%s/%s", g_cni_bin_dir, plugin);

    if (!is_executable(plugin_path)) {
        fprintf(stderr, "[-] %s missing or not executable\n", plugin_path);
        return 1;
    }

    int cfgpipe[2];
    if (pipe(cfgpipe) < 0) {
        perror("pipe");
        return 1;
    }

    printf("[*] Running %s (CNI_COMMAND=%s)\n", plugin_path, cmd);
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(cfgpipe[0]);
        close(cfgpipe[1]);
        return 1;
    }

    if (pid == 0) {
        close(cfgpipe[1]);
        if (dup2(cfgpipe[0], STDIN_FILENO) < 0) {
            perror("dup2");
            _exit(127);
        }
        close(cfgpipe[0]);

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            perror("PTRACE_TRACEME");
            _exit(127);
        }
        raise(SIGSTOP);

        setenv("CNI_COMMAND",     cmd, 1);
        setenv("CNI_CONTAINERID", g_container_id, 1);
        setenv("CNI_NETNS",       netns  ? netns  : "", 1);
        setenv("CNI_IFNAME",      ifname ? ifname : "", 1);
        setenv("CNI_PATH",        g_cni_bin_dir, 1);

        execl(plugin_path, plugin_path, (char *)NULL);
        perror("execl");
        _exit(127);
    }

    close(cfgpipe[0]);
    if (cfg && *cfg) {
        size_t len = strlen(cfg);
        const char *p = cfg;
        while (len > 0) {
            ssize_t w = write(cfgpipe[1], p, len);
            if (w < 0) {
                if (errno == EINTR) continue;
                perror("write(cfg)");
                break;
            }
            p   += w;
            len -= (size_t)w;
        }
    }
    close(cfgpipe[1]);

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid(initial)");
        return 1;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        fprintf(stderr, "[-] Child did not stop for ptrace (status=0x%x)\n", status);
        return 1;
    }

    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)PTRACE_OPTS) != 0) {
        perror("PTRACE_SETOPTIONS");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    tracked_proc_t tracked[MAX_TRACKED_PIDS];
    memset(tracked, 0, sizeof(tracked));
    int tracked_count = 0;

    tracked[tracked_count].pid        = pid;
    tracked[tracked_count].start_time = get_time_ms();
    tracked_count++;

    printf("[+] Tracing PID %d\n", pid);
    fflush(stdout);

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        perror("PTRACE_SYSCALL");
        return 1;
    }

    trace_loop(tracked, &tracked_count);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s <plugin> <CNI_COMMAND> [config-json]\n"
        "\n"
        "  plugin        CNI plugin inside CNI_BIN_DIR (e.g. firewall, bridge)\n"
        "  CNI_COMMAND   ADD | DEL | CHECK | VERSION\n"
        "  config-json   optional; read from stdin if omitted\n"
        "\n"
        "Env:\n"
        "  CNI_BIN_DIR         default %s\n"
        "  CNI_NETNS           default /var/run/netns/<TEST_NETNS_NAME>\n"
        "  CNI_IFNAME          default $TEST_IFNAME\n"
        "  TEST_NETNS_NAME     default %s\n"
        "  TEST_IFNAME         default %s\n"
        "  NO_AUTO_PREVRESULT  if 1, do not auto-inject prevResult\n"
        "  ENABLE_INJECT       if 1, inject our own rule into each\n"
        "                      netlink-nf window (default off)\n"
        "\n"
        "Output:\n"
        "  pattern start: <ms>  (pid N fd M)\n"
        "  pattern ended: <ms>  (pid N fd M)  duration=... syscalls=...\n"
        "      functions invoked:\n"
        "        <name>  x<count>\n",
        argv0, DEFAULT_CNI_BIN_DIR, DEFAULT_TEST_NETNS, DEFAULT_TEST_IFNAME);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (getuid() != 0) {
        fprintf(stderr, "[-] Must be run as root (ptrace + netns).\n");
        return 1;
    }

    const char *plugin = argv[1];
    const char *cmd    = argv[2];

    char *cfg = NULL;
    if (argc >= 4) {
        cfg = strdup(argv[3]);
    } else {
        size_t cap = 4096, len = 0;
        cfg = malloc(cap);
        if (!cfg) { perror("malloc"); return 1; }
        ssize_t n;
        while ((n = read(STDIN_FILENO, cfg + len, cap - len - 1)) > 0) {
            len += (size_t)n;
            if (len + 1 >= cap) {
                cap *= 2;
                char *tmp = realloc(cfg, cap);
                if (!tmp) { free(cfg); perror("realloc"); return 1; }
                cfg = tmp;
            }
        }
        cfg[len] = '\0';
    }
    if (!cfg) return 1;

    const char *v;
    if ((v = getenv("CNI_BIN_DIR")) && *v)
        snprintf(g_cni_bin_dir, sizeof(g_cni_bin_dir), "%s", v);
    if ((v = getenv("TEST_NETNS_NAME")) && *v)
        snprintf(g_test_netns, sizeof(g_test_netns), "%s", v);
    if ((v = getenv("TEST_IFNAME")) && *v)
        snprintf(g_test_ifname, sizeof(g_test_ifname), "%s", v);
    if ((v = getenv("NO_AUTO_PREVRESULT")) && strcmp(v, "1") == 0)
        g_auto_prevresult = 0;
    if ((v = getenv("ENABLE_INJECT")) && strcmp(v, "1") == 0)
        g_enable_inject = 1;

    snprintf(g_container_id, sizeof(g_container_id), "cni-scan-%d", (int)getpid());

    const char *netns = getenv("CNI_NETNS");
    if (!netns || !*netns) {
        if (ensure_netns(g_test_netns) != 0)
            return 1;
        snprintf(g_netns_path, sizeof(g_netns_path),
                 "%s/%s", NETNS_DIR, g_test_netns);
        netns = g_netns_path;
    }

    const char *ifname = getenv("CNI_IFNAME");
    if (!ifname || !*ifname)
        ifname = g_test_ifname;

    if (g_auto_prevresult && !cfg_has_prevresult(cfg)) {
        char *aug = inject_prevresult(cfg, netns, ifname);
        if (aug) {
            free(cfg);
            cfg = aug;
            printf("[*] Injected synthetic prevResult into config\n");
        }
    }

    signal(SIGINT,  on_sig);
    signal(SIGTERM, on_sig);

    printf("[*] CNI bin dir : %s\n", g_cni_bin_dir);
    printf("[*] Netns       : %s\n", netns);
    printf("[*] Ifname      : %s\n", ifname);
    printf("[*] Injection   : %s\n",
           g_enable_inject ? "ENABLED" : "disabled");
    printf("[*] Watching for NETLINK_NETFILTER socket patterns...\n\n");
    fflush(stdout);

    int rc = run_cni(plugin, cmd, cfg, netns, ifname);

    nf_hook_summary();
    nf_inject_free();

    free(cfg);
    return rc;
}
