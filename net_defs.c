#include "net_defs.h"
#include <stddef.h>

const char *dns_servers[] = 
{
  "1.1.1.1",
  "1.0.0.1",
  "208.67.222.222",
  "208.67.220.220",
  "8.8.8.8",
  "8.8.4.4",
  "94.140.14.14",
  "94.140.15.15",
  NULL,
};

const int protocols[] = 
{ 
  443, 
  80, 
  0 
};

const uint16_t domain_qtypes[] = 
{
  DNS_A,
  DNS_AAAA,
  DNS_NS,
  DNS_CNAME,
  DNS_MX,
  DNS_SOA,
  DNS_TXT,
  0
};

const uint16_t subdomain_qtypes[] = 
{
  DNS_A,
  DNS_AAAA,
  DNS_MX,
  DNS_CNAME,
  DNS_TXT,
  0
};

const uint16_t test_qtypes[] = 
{
  DNS_TXT,
  0
};
