#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "net_defs.h"
#include "network.h"
#include "dns_protocol.h"
#include "colors.h"
#include "memory.h"

int dns_query (sock_t *sock, dns_buffer_t *dns_buff, dns_query_t **query, dns_query_t **cursor, int qtype, options_t *options, pool_t *pool)
{
	destinfo_t dest;
	int send_stats, received, parse_stats;

	// ATUALIZAR ESTE PEDAÇO PARA UTILIZAR /etc/resolv.conf AO INVÉS DE UM ARRAY CONSTANTE
	for(const char **ptr = dns_servers;*ptr;ptr++)
	{
		int comm_stats;
		checkaddr((char *)*ptr, options);
		copystr((char *)*ptr, sock->ip);
		if((comm_stats = server_comm(sock, sock->transport_protocol, 53, &dest, options)) >= 0) break;
	}

	// COMPORTAMENTO TCP
	if (sock->transport_protocol == SOCK_STREAM)
	{
		dns_query_t *ns_cursor = NULL;
		
		if((send_stats = tcp_comm(sock, dns_buff, *options, SEND)) < 0)
		{
			perror("Buffer send failed"); // RETIRAR TODOS OS PERRORS
			exit(EXIT_FAILURE);
		}

		while(1)
		{
			if((received = tcp_comm(sock, dns_buff, *options, RECV)) < 0)
			{
				perror("Buffer receivement failed\n");
			}

			if((parse_stats = dns_parse(&sock, dns_buff, query, qtype, cursor, pool)) == -1) return -1;
		}



	}

	// COMPORTAMENTO UDP
	if (sock->transport_protocol == SOCK_DGRAM)
	{
		if((send_stats = udp_comm(sock, &dest, dns_buff, *options, SEND)) < 0)
		{
			perror("Buffer send failed"); // RETIRAR TODOS OS PERRORS
			exit(EXIT_FAILURE);
		}

		if((received = udp_comm(sock, &dest, dns_buff, *options, RECV)) < 0)
		{
			perror("Buffer receivement failed\n");
		}
		dns_buff->length = received;

		if((parse_stats = dns_parse(&sock, dns_buff, query, qtype, cursor, pool)) == -1) return -1;
	}

	//printf("[ DEBUG ] QUERY OF QTYPE %s IN %s\n", get_strqtype(qtype), sock->domain);

	/*
	if (recv_stats > 0) // DESCOMENTAR QUANDO PRECISAR DE DEBUGAR BUFFER DNS
	{
		printf("\n\n");
		int c = 0;
		do
		{
			printf("%02X ", dns_buff->buffer[c++]);
		} while (c < recv_stats);
		printf("\n\n");
	}

	if((parse_stats = dns_parse(&sock, dns_buff, query, qtype, cursor, pool)) == -1)
	{
		// SEGMENTATION FAULT AQUI POR CONTA DA TENTATIVA DE ACESSO DE SOCK->DOMAIN OU (*QUERY)->ANSWER.QTYPE
		printf("%s%s does not have a %s register%s\n", RED, sock->req_source, get_strqtype(qtype), RESET);
		//printf("%s\n\n[ DEBUG ] DNS PARSE ERROR\n\n%s", RED, RESET);
		return -1;
	}
	*/

	return 0;

}

dns_query_t *create_query (uint16_t qtype, pool_t *pool)
{
	dns_query_t *query = (dns_query_t *)POOL_ALLOC(pool, sizeof(dns_query_t));
	query->next = NULL;
	query->child = NULL;
	query->qtype = qtype;
	return query;
}

dns_query_t *send_query (sock_t *sock, dns_buffer_t *dns_buff, dns_query_t **query, dns_query_t **cursor, int qtype, options_t *options, pool_t *pool)
{
	dns_buff->offset = 0;
	dns_buffer(dns_buff, sock->req_source, qtype, pool);
	dns_query(sock, dns_buff, &(*query)->child, cursor, qtype, options, pool);

	return *cursor;
}

void dns_request (sock_t *sock, dns_buffer_t *dns_buff, dns_query_t **query, int qtype, options_t *options, int layer, pool_t *pool) // DIMINUIR A QUANTIDADE DE PARÂMETROS, OS ENCAPSULANDO EM STRUCTS
{
	dns_query_t *cursor = NULL;
	if (options->hierarquic)
	{		
		// IREI DEFINIR O QTYPE COMO PARÂMETRO NA RECURSIVIDADE
		if(layer == 0) return;

		else if ( layer == 1 ) qtype = DNS_PTR;

		switch (layer)
		{
			case 2:
				send_query(sock, dns_buff, query, &cursor, DNS_A, options, pool);
				send_query(sock, dns_buff, query, &cursor, DNS_AAAA, options, pool);
				break;
			default:
				send_query(sock, dns_buff, query, &cursor, qtype, options, pool);
				break;
		}

		cursor = (*query)->child;

		for (;cursor; cursor = cursor->next)
		{
			memset(sock->req_source, 0, ADDR);
			copystr(cursor->req_source, sock->req_source);
			dns_request(sock, dns_buff, &cursor, cursor->answer.qtype, options, layer - 1, pool);
		}

	} else 
	{
		send_query(sock, dns_buff, query, &cursor, qtype, options, pool);
	}

// NO CASO DE AAAA e A, A DIFERENÇA É QUE TERÁ QUE SER CHECADO SE É AAAA OU A PARA TRANSFORMAR O ENDEREÇO IPV4 OU IPV6 EM ALGO QUE POSSA SER MANDADO NA QUERY PTR
// INDEPENDENTE DE SER UTILIZADO O NS, AAAA, A OU QUALQUER OUTRO, A STRING query->source SEMPRE DEVE SER UTILIZADA. A ÚNICA DIFERENÇA ENTRE AAAA E A E OUTRAS É QUE AS 2 FICAM EM 1 LISTA SÓ, JUNTAS
}

// Ainda falta implementar o comportamento TCP e o parsing da resposta
void dns_resolve (dns_query_t **query, sock_t *sock, int transport_protocol, dns_buffer_t *dns_buff, options_t *options, pool_t *pool)
{
	sock->transport_protocol = transport_protocol;
        options->hierarquic = false;
	int layer;
	switch ((*query)->qtype)
	{
		case DNS_NS:
		case DNS_MX:
		case DNS_CNAME:
			if(!options->axfr)
			{
				options->hierarquic = true;
				layer = 3;
			}
			break;
		default:
			layer = 1;
			break;
	}
	copystr(sock->domain, sock->req_source);
	dns_request(sock, dns_buff, &(*query), (*query)->qtype, options, layer, pool);
}

void axfr_query (sock_t *sock, dns_buffer_t *dns_buff, options_t *options, pool_t *pool)
{



	dns_query_t *query = create_query(DNS_NS, pool);
	dns_resolve(&query, sock, SOCK_DGRAM, dns_buff, options, pool);

	// AQUI EU TEREI QUE FAZER UM LOOP, PASSANDO POR QUERY E PEGANDO TODOS OS IPs NECESSÁRIOS

	options->axfr = true;
	printf("\n%s\n", sock->domain);
	dns_resolve(&query->next, sock, SOCK_STREAM, dns_buff, options, pool);

	options->axfr = false;

}

void dns_send_queries (sock_t *sock, dns_buffer_t *dns_buff, const uint16_t *domain_qtypes, dns_query_t **root_query, options_t *options, pool_t *pool)
{
	dns_query_t *cursor = NULL;
	for(const uint16_t *pointer = domain_qtypes; *pointer != 0; pointer++)
	{
		dns_query_t *new_root_query = create_query(*pointer, pool); // AQUI LIDAREMOS COM A PRIMEIRA HIERARQUIA DE QUERIES, A DO ROOT, ONDE FICAM OS DADOS PARA "ADMINISTRAR" AS QUERIES
		char domain[ADDR];
		copystr(sock->domain, domain);
		options->hierarquic = false;
		copystr(sock->domain, new_root_query->req_source);
		if(*pointer == DNS_NS || *pointer == DNS_MX || *pointer == DNS_CNAME) options->hierarquic = true;

		if (*pointer == DNS_AXFR) dns_resolve(&new_root_query, sock, SOCK_STREAM, dns_buff, options, pool);

		else dns_resolve(&new_root_query, sock, SOCK_DGRAM, dns_buff, options, pool);


		memset(dns_buff, 0, sizeof(dns_buffer_t));
		if(!*root_query) *root_query = cursor = new_root_query;
		else
		{
			cursor->next = new_root_query;
			cursor = new_root_query;
		}
		if(new_root_query->child) results_print(domain, new_root_query->child, options->hierarquic);
	}
	pool_reset(pool);
}

// AXFR provávelmente terá de ter um tratamento especial, já que ele, diferente de outras queries, irá enviar diversos pacotes com qtypes variados. Tentar reaproveitar ao máximo a estrutura criada préviamente.
