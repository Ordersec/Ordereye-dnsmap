#include "net_defs.h"
#include "memory.h"

header_t dns_header ();
uint8_t *write_question_name (char *domain, int *qname_len, pool_t *pool);
void dns_buffer (dns_buffer_t *dnsbuff, char *domain, int type, pool_t *pool);
const char *get_strqtype (int qtype);
const char *get_strqclass (int qclass);
void reserve_buff (uint8_t *buff, size_t bufflen);
void bufftorevdns (uint8_t *buff, size_t bufflen, char *str);
void revdns_address(char *ip_addr, char *revdns);
int dns_parse (sock_t **sock, dns_buffer_t *response, dns_query_t **query, int qtype, dns_query_t **cursor, pool_t *pool);
