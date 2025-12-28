CC = gcc
CFLAGS = -g -O3 -Idns -Inet -Iutils
TARGET = ordereye-dnsmap
SRCS = ordereye-dnsmap.c \
       dns/dns_mapping.c dns/dns_resolver.c dns/dns_protocol.c \
       net/net_defs.c net/network.c \
       utils/cli.c utils/memory.c

install:
	$(CC) $(CFLAGS) $(SRCS) -o /usr/bin/$(TARGET)

uninstall:
	rm -f /usr/bin/$(TARGET)

.PHONY: install uninstall
