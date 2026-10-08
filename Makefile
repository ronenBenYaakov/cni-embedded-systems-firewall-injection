CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_GNU_SOURCE
SRCS    = nftables_netlink.c nftables_hooks.c nftables_symbols.c  nftables_inject.c
HDRS    = nftables_netlink.h nftables_symbols.h nftables_inject.h
TARGET  = nftables_netlink

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f $(TARGET) *.o

.PHONY: clean
