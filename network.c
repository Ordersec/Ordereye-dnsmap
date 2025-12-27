#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "net_defs.h"
#include "dns_protocol.h"
#include "dns_resolver.h"
#include "cli.h"
#include "colors.h"
#include "memory.h"
void checkaddr(char *addr, options_t *options)
{
	uint8_t buf[sizeof(struct in6_addr)];
	if(inet_pton(AF_INET6, addr, buf) == 1) options->ipv6 = true;

	else if(inet_pton(AF_INET, addr, buf) == 1) options->ipv4 = true;

	else options->is_domain = true;
}

int init_sock(sock_t *sock, int port, int transport_protocol, options_t *options)
{
	sock->port = port;
	sock->transport_protocol = transport_protocol;

	if (options->ipv6)
	{
		sock->family = AF_INET6;
		sock->ipv6.sin6_family = sock->family;
		sock->ipv6.sin6_port = htons(port);
		inet_pton(sock->family, sock->ip, &sock->ipv6.sin6_addr);
	} else if (options->ipv4)
	{
		sock->family = AF_INET;
		sock->ipv4.sin_family = sock->family;
		sock->ipv4.sin_port = htons(port);
		inet_pton(sock->family, sock->ip, &sock->ipv4.sin_addr);
	}

	if(sock->sockfd <= 0) sock->sockfd = socket(sock->family, transport_protocol, 0);

	return sock->sockfd;
}

void validate_address (sock_t *sock, char *addr, options_t *options, pool_t *pool)
{
	checkaddr(addr, options);
	if (!options->is_domain)
	{
		dns_query_t *query = create_query(DNS_PTR, pool);
		dns_buffer_t dnsbuff = {0};
		copystr(addr, sock->ip);
		revdns_address(sock->ip, sock->domain);
		copystr(sock->domain, sock->req_source);
		dns_resolve(&query, sock, SOCK_DGRAM, &dnsbuff, options, pool); // OLHAR SOBRE COLOCAR A QUERY ALI, JÁ QUE NÃO PRECISA NESSE CASO.
		copystr(query->child->answer.answer, sock->domain);
		close(sock->sockfd);
	} else copystr(addr, sock->domain);
	pool_reset(pool);
}

int server_comm (sock_t *sock, int transport_protocol, int port, destinfo_t *dest, options_t *options) // ANALISAR SE ESTA FUNÇÃO É NECESSÁRIA
{
	if ((sock->sockfd = init_sock(sock, port, transport_protocol, options)) < 0) return -1;

	if (sock->family == AF_INET6)
	{
		dest->addr = (struct sockaddr *)&sock->ipv6;
		dest->socklen = sizeof(struct sockaddr_in6);
	} else if (sock->family == AF_INET)
	{
		dest->addr = (struct sockaddr *)&sock->ipv4;
		dest->socklen = sizeof(struct sockaddr_in);
	}

	if (transport_protocol == SOCK_STREAM)
		if((sock->connection_stats = connect(sock->sockfd, dest->addr, dest->socklen)) < 0) return -1;

	return (transport_protocol == SOCK_DGRAM) ? sock->sockfd : sock->connection_stats;
}

int udp_comm (sock_t *sock, destinfo_t *dest, dns_buffer_t *dnsbuff, options_t options, comm_type udp_type)
{
	int comm_stats;

	//printf("[ DEBUG ] Socket fd: %d\n", sock->sockfd);
	if (sock->sockfd < 0) {
		fprintf(stderr, "Invalid socket fd!\n");
		return -1;
	}
	if (udp_type == SEND) comm_stats = sendto(sock->sockfd, dnsbuff->buffer, DNS_BUFF, 0, dest->addr, dest->socklen);
	else if(udp_type == RECV) comm_stats = recvfrom(sock->sockfd, dnsbuff->buffer, DNS_BUFF, 0, dest->addr, &dest->socklen);

	return comm_stats;
}

int tcp_comm (sock_t *sock, dns_buffer_t *dns_buff, options_t *options, comm_type tcp_type)
{
	int comm_stats;

	if (tcp_type == SEND) comm_stats = send(sock->sockfd, dns_buff->buffer, DNS_BUFF, 0);
	else if (tcp_type == RECV) comm_stats = recv(sock->sockfd, dns_buff->buffer, DNS_BUFF, 0);

	return comm_stats;
}
