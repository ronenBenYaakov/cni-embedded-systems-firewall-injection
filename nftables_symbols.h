#ifndef NFTABLES_SYMBOLS_H
#define NFTABLES_SYMBOLS_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/sysmacros.h>

bool nf_resolve_addr(pid_t pid, uint64_t addr, char *out, size_t outlen);
void nf_symbols_free(void);

#endif /* NFTABLES_SYMBOLS_H */
