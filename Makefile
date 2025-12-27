CC = gcc
CFLAGS = -g -O3 -Wall -Wextra
TARGET = ordereye-dnsmap
SRCS = ordereye-dnsmap.c cli.c dns_protocol.c dns_resolver.c memory.c net_defs.c network.c dns_mapping.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install:
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
EOF
