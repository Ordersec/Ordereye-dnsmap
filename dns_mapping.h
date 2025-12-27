#include "net_defs.h"
#include "memory.h"
#include "cli.h"

int scan_web_ports (sock_t *sock, int port, int transport_protocol, options_t options);
char *readline (FILE *file, char *line, size_t line_size);
int subdomain_conn (sock_t *sock, FILE *file, char *line, size_t line_size, options_t options);
void brute_force (sock_t *sock, dns_buffer_t *dns_buff, dns_query_t **query, FILE *file, options_t *options, pool_t *pool);
