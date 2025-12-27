CC = gcc
CFLAGS = -g -O3 -Wall -Wextra
TARGET = ordereye-dnsmap
SRCS = ordereye-dnsmap.c cli.c dns_protocol.c dns_resolver.c memory.c net_defs.c network.c dns_mapping.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)

install:
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
