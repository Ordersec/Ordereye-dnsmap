#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <arpa/inet.h>
#include <stdint.h>

#define DNS_BUFF 512
#define DATA_BUFF 512

#define ADDR 256
#define DNS_PORT 53

typedef struct 
{
  struct sockaddr_in ipv4;
  struct sockaddr_in6 ipv6;
  char   ip[INET6_ADDRSTRLEN];
  char   domain[ADDR];
  char   req_source[ADDR];
  int    port;
  int    family;
  int    sockfd;
  int    transport_protocol;
  int    connection_stats;
} sock_t;

typedef struct 
{
  struct sockaddr *addr;
  socklen_t socklen;
}destinfo_t;

typedef struct 
{
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} header_t;

typedef struct
{
  uint8_t buffer[DNS_BUFF];
  uint8_t *rdata;
  int rdlength;
  int offset;
  int length;
  int pos;
  int ptr;
}dns_buffer_t;

typedef struct
{
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  char     target[ADDR];
} srv_t;

typedef struct 
{
  char     mname[ADDR];
  char     rname[ADDR];
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minimum;
} soa_t;

typedef enum
{
  SEND,
  RECV
}comm_type;

enum web_service
{
  NONE  = 0,
  HTTP  = 1,
  HTTPS = 2,
  BOTH  = 3,
};

typedef struct data 
{
  uint16_t qtype;
  uint16_t qclass;
  uint32_t ttl;
  char     answer[DATA_BUFF];
  srv_t    srv;
  soa_t    soa;
} data_t;

typedef struct dns_tree
{
  data_t answer;
  uint16_t qtype;
  char   req_source[ADDR];
  struct dns_tree *child;
  struct dns_tree *next;
}dns_query_t;

enum dns_qtype_t 
{
  DNS_A     = 1,
  DNS_NS    = 2,
  DNS_CNAME = 5,
  DNS_SOA   = 6,
  DNS_PTR   = 12,
  DNS_MX    = 15,
  DNS_TXT   = 16,
  DNS_AAAA  = 28,
  DNS_AXFR  = 252,
};

enum dns_qclass_t 
{
  DNS_IN = 1,
  DNS_CS = 2,
  DNS_CH = 3,
  DNS_HS = 4,
  DNS_ANY = 255,
};

// Extern Declarations
extern const int      protocols[];
extern const char     *dns_servers[];
extern const uint16_t domain_qtypes[];
extern const uint16_t subdomain_qtypes[];
extern const uint16_t test_qtypes[];

#endif

// VOU TER QUE CRIAR UMA STRUCT GENERALISTA QUE APONTA PARA HEAD E TAIL DE CADA LISTA ENCADEADA EM CADA LAYER DA ÁRVORE, ASSIM PODENDO ME GUIAR MELHOR
