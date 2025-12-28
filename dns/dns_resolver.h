#include "net_defs.h"
#include "cli.h"
#include "options.h"
#include "memory.h"

int dns_query (sock_t *sock, dns_buffer_t *dns_buff, dns_query_t **query, dns_query_t **cursor, int qtype, options_t *options, pool_t *pool);
dns_query_t *create_query (uint16_t qtype, pool_t *pool);
dns_query_t *send_query (sock_t *sock, dns_buffer_t *dns_buff, dns_query_t **query, dns_query_t **cursor, int qtype, options_t *options, pool_t *pool);
void dns_request (sock_t *sock, dns_buffer_t *dnsbuff, dns_query_t **query, int qtype, options_t *options, int layer, pool_t *pool);
void dns_resolve(dns_query_t **query, sock_t *sock, int transport_protocol, dns_buffer_t *dnsbuff, options_t *options, pool_t *pool);
void axfr_query (sock_t *sock, dns_buffer_t *dnsbuff, options_t *options, pool_t *pool);
void dns_send_queries (sock_t *sock, dns_buffer_t *dnsbuff, const uint16_t *domain_qtypes, dns_query_t **root_query, options_t *options, pool_t *pool);
