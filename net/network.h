#include "cli.h"
#include "net_defs.h"
#include "memory.h"

void checkaddr (char *addr, options_t *options);
int init_sock (sock_t *sock, int port, int transport_protocol, options_t *options);
void validate_address (sock_t *sock, char *addr, options_t *options, pool_t *pool);
int server_comm (sock_t *sock, int transport_protocol, int port, destinfo_t *dest, options_t *options);
int udp_comm (sock_t *sock, destinfo_t *dest, dns_buffer_t *dnsbuff, options_t options, comm_type udp_type);
int tcp_comm (sock_t *sock, dns_buffer_t *dnsbuff, options_t options, comm_type tcp_type);
