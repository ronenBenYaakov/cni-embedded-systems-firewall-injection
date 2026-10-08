#define _GNU_SOURCE
#include "nftables_symbols.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef struct {
    char     name[128];
    uint64_t value;
    uint64_t size;
    uint8_t  type;
} nf_sym_t;

typedef struct {
    dev_t     dev;
    ino_t     ino;
    off_t     size;
    time_t    mtime;

    nf_sym_t *syms;
    size_t    n;
} nf_symtab_t;

#define NF_SYMCACHE 8
static nf_symtab_t g_cache[NF_SYMCACHE];
static int         g_cache_n = 0;

static void free_symtab(nf_symtab_t *t)
{
    if (!t) return;
    free(t->syms);
    t->syms = NULL;
    t->n    = 0;
}

static int sym_cmp(const void *a, const void *b)
{
    const nf_sym_t *x = a, *y = b;
    if (x->value < y->value) return -1;
    if (x->value > y->value) return  1;
    if (x->size  > y->size)  return -1;
    if (x->size  < y->size)  return  1;
    return 0;
}

static size_t read_syms(const uint8_t *elf, size_t elflen,
                        const Elf64_Shdr *shdrs, size_t shnum,
                        int want_type, nf_sym_t **out)
{
    const Elf64_Shdr *symsh = NULL;
    const Elf64_Shdr *strsh = NULL;

    for (size_t i = 0; i < shnum; i++) {
        if (shdrs[i].sh_type == (uint32_t)want_type) {
            symsh = &shdrs[i];
            if (symsh->sh_link < shnum)
                strsh = &shdrs[symsh->sh_link];
            break;
        }
    }
    if (!symsh || !strsh) return 0;

    if (symsh->sh_offset + symsh->sh_size > elflen) return 0;
    if (strsh->sh_offset + strsh->sh_size > elflen) return 0;

    const Elf64_Sym *syms = (const Elf64_Sym *)(elf + symsh->sh_offset);
    const char      *strs = (const char *)(elf + strsh->sh_offset);
    size_t nsyms = symsh->sh_size / sizeof(Elf64_Sym);

    nf_sym_t *arr = calloc(nsyms, sizeof(*arr));
    if (!arr) return 0;

    size_t n = 0;
    for (size_t i = 0; i < nsyms; i++) {
        const Elf64_Sym *s = &syms[i];
        if (s->st_name == 0 || s->st_value == 0)
            continue;
        uint8_t type = ELF64_ST_TYPE(s->st_info);
        if (type != STT_FUNC && type != STT_GNU_IFUNC)
            continue;
        if (strsh->sh_offset + s->st_name >= strsh->sh_offset + strsh->sh_size)
            continue;
        const char *nm = strs + s->st_name;
        if (!*nm) continue;

        snprintf(arr[n].name, sizeof(arr[n].name), "%s", nm);
        arr[n].value = s->st_value;
        arr[n].size  = s->st_size;
        arr[n].type  = type;
        n++;
    }

    if (n == 0) {
        free(arr);
        return 0;
    }
    qsort(arr, n, sizeof(*arr), sym_cmp);
    *out = arr;
    return n;
}

static size_t load_symtab(const char *path, nf_sym_t **out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 0; }
    long sz = ftell(fp);
    if (sz <= 0 || sz > (long)(256 * 1024 * 1024)) { fclose(fp); return 0; }
    rewind(fp);

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(fp); return 0; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return 0;
    }
    fclose(fp);

    if (sz < (long)sizeof(Elf64_Ehdr) ||
        memcmp(buf, ELFMAG, SELFMAG) != 0) {
        free(buf);
        return 0;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)buf;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) {
        free(buf);
        return 0;
    }
    if (eh->e_shoff == 0 || eh->e_shnum == 0) {
        free(buf);
        return 0;
    }

    size_t shoff = (size_t)eh->e_shoff;
    size_t shnum = eh->e_shnum;
    size_t shsz  = sizeof(Elf64_Shdr);
    if (shoff + shnum * shsz > (size_t)sz) {
        free(buf);
        return 0;
    }
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(buf + shoff);

    nf_sym_t *arr = NULL;
    size_t n = read_syms(buf, (size_t)sz, shdrs, shnum, SHT_SYMTAB, &arr);
    if (n == 0)
        n = read_syms(buf, (size_t)sz, shdrs, shnum, SHT_DYNSYM, &arr);

    free(buf);
    if (n == 0) return 0;
    *out = arr;
    return n;
}

static nf_symtab_t *cache_lookup(dev_t dev, ino_t ino)
{
    for (int i = 0; i < g_cache_n; i++) {
        if (g_cache[i].dev == dev && g_cache[i].ino == ino)
            return &g_cache[i];
    }
    return NULL;
}

static nf_symtab_t *cache_insert(dev_t dev, ino_t ino,
                                 off_t size, time_t mtime,
                                 nf_sym_t *syms, size_t n)
{
    if (g_cache_n >= NF_SYMCACHE) {
        free_symtab(&g_cache[0]);
        memmove(&g_cache[0], &g_cache[1],
                sizeof(g_cache[0]) * (NF_SYMCACHE - 1));
        g_cache_n = NF_SYMCACHE - 1;
    }
    nf_symtab_t *t = &g_cache[g_cache_n++];
    memset(t, 0, sizeof(*t));
    t->dev = dev; t->ino = ino;
    t->size = size; t->mtime = mtime;
    t->syms = syms;
    t->n    = n;
    return t;
}

static uint64_t load_bias_for(pid_t pid, dev_t dev, ino_t ino)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[512];
    uint64_t bias = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end, off;
        unsigned int d_maj, d_min;
        unsigned long long inode;
        char perms[8];
        int n = sscanf(line, "%llx-%llx %7s %llx %x:%x %llu",
                       &start, &end, perms, &off,
                       &d_maj, &d_min, &inode);
        if (n < 7) continue;

        dev_t d = makedev(d_maj, d_min);
        if (d == dev && (ino_t)inode == ino) {
            bias = (uint64_t)start - (uint64_t)off;
            break;
        }
    }
    fclose(fp);
    return bias;
}

bool nf_resolve_addr(pid_t pid, uint64_t addr, char *out, size_t outlen)
{
    if (!out || outlen < 8) return false;

    char exe[64];
    snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);

    struct stat st;
    if (stat(exe, &st) != 0) {
        snprintf(out, outlen, "0x%llx",
                 (unsigned long long)addr);
        return false;
    }

    nf_symtab_t *t = cache_lookup(st.st_dev, st.st_ino);
    if (!t) {
        char real[512];
        ssize_t r = readlink(exe, real, sizeof(real) - 1);
        if (r <= 0) {
            snprintf(out, outlen, "0x%llx",
                     (unsigned long long)addr);
            return false;
        }
        real[r] = '\0';

        nf_sym_t *syms = NULL;
        size_t n = load_symtab(real, &syms);
        t = cache_insert(st.st_dev, st.st_ino,
                         st.st_size, st.st_mtime, syms, n);
    }

    if (!t || t->n == 0) {
        snprintf(out, outlen, "0x%llx",
                 (unsigned long long)addr);
        return false;
    }

    uint64_t bias = load_bias_for(pid, t->dev, t->ino);
    if (addr < bias) {
        snprintf(out, outlen, "0x%llx",
                 (unsigned long long)addr);
        return false;
    }
    uint64_t rel = addr - bias;

    size_t lo = 0, hi = t->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (t->syms[mid].value <= rel) lo = mid + 1;
        else                           hi = mid;
    }
    if (lo == 0) {
        snprintf(out, outlen, "0x%llx",
                 (unsigned long long)addr);
        return false;
    }
    const nf_sym_t *s = &t->syms[lo - 1];

    if (s->size && rel >= s->value + s->size) {
        snprintf(out, outlen, "0x%llx",
                 (unsigned long long)addr);
        return false;
    }

    snprintf(out, outlen, "%s+0x%llx", s->name,
             (unsigned long long)(rel - s->value));
    return true;
}

void nf_symbols_free(void)
{
    for (int i = 0; i < g_cache_n; i++)
        free_symtab(&g_cache[i]);
    g_cache_n = 0;
}
