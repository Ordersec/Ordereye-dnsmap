#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "network.h"
#include "cli.h"
#include "colors.h"
#include "net_defs.h"
#include "dns_protocol.h"
#include "dns_resolver.h"
#include "memory.h"

int scan_web_ports(sock_t *sock, int port, int transport_protocol, options_t options)
{
	// ANALISAR COMPORTAMENTO DO HTTP PARA CHECAR A UMA CONCLUSÃO DE COMO VALIDAR WILCARD DNS ATRAVÉS DELE
	int open_https = 0, open_http = 0, web_status;
	for(int protocol = 0; protocols[protocol] != 0; protocol++)
	{
		init_sock(sock, protocols[protocol], transport_protocol, &options);
		if(sock->sockfd >= 0)
		{
			if(protocols[protocol] == 443) open_https = 1;
			if(protocols[protocol] == 80) open_http = 1;
			close(sock->sockfd);
		}
	}

	if(!open_https && !open_http) web_status = NONE;
	if(open_https && !open_http) web_status  = HTTPS;
	if(!open_https && open_http) web_status  = HTTP;
	if(open_https && open_http) web_status   = BOTH;

	return web_status;
}

char *readline (FILE *file, char *line, size_t line_size)
{
	if (!(fgets(line, line_size, file))) return NULL;

	line[strcspn(line, "\n")] = 0; // CASO EU CONSIGA OTIMIZAR READLINE, SUBSTITUINDO STRCSPN POR OUTRA COISA, FAREI.
	return line;
}

void brute_force (sock_t *sock, dns_buffer_t *dns_buff, dns_query_t **query, FILE *file, options_t *options, pool_t *pool)
{
    size_t line_size = 101;
    char *fileline = (char *)POOL_ALLOC(pool, line_size);
    char *domain = (char *)POOL_ALLOC(pool, ADDR);
    copystr(sock->domain, domain);
    
    while((fileline = readline(file, fileline, line_size)))		
    {
        *query = NULL;
        snprintf(sock->domain, ADDR, "%s.%s", fileline, domain);
        
        dns_send_queries(sock, dns_buff, subdomain_qtypes, query, options, pool);
    }
    line("✦ ✧ ", 25, LILAC);
}

