#ifndef NFTABLES_NETLINK_H
#define NFTABLES_NETLINK_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>


void nf_hook_pattern_start(pid_t pid, int fd, uint64_t t);
void nf_hook_pattern_end(pid_t pid, int fd, uint64_t t);
void nf_hook_syscall(pid_t pid, long sc,
                     const unsigned long args[6],
                     unsigned long ret, bool entering);
void nf_hook_summary(void);


#define NF_MAX_WINDOWS    512
#define NF_MAX_FUNCS       64

#endif /* NFTABLES_NETLINK_H */
