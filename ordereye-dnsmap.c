#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include "dns_protocol.h"
#include "dns_resolver.h"
#include "colors.h"
#include "network.h"
#include "cli.h"
#include "net_defs.h"
#include "dns_mapping.h"
#include "memory.h"


#define POOL_SIZE 100 * 1024 * 1024
// REMOVER #INCLUDE <ERRNO.H> ASSIM QUE TERMINAR O SCRIPT

int main (int argc, char **argv)
{
	print_logo();

	printf("%s", RESET);

	if (argc < 3) error("\nInsufficient arguments provided");

	struct option long_options[] =
	{
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	pool_t pool = pool_create(POOL_SIZE);

	shell_t shell;
	memset(&shell, 0, sizeof(shell_t));
	arg_check(argc, argv, &shell, long_options);

	options_t options;
	memset(&options, 0, sizeof(options_t));
	options.axfr = false;
	// CRIAR A ESTRUTURA DA QUERY AQUI EM ORDEREYE-DNSMAP.C E JOGAR O RESULTADO DA CONSULTA PTR DENTRO DE QUERY
	sock_t sock;
	memset(&sock, 0, sizeof(sock_t));
	validate_address(&sock, shell.arguments[0], &options, &pool);

	if (options.is_domain)
	{

		dns_buffer_t dns_buff = {0};

		// CRIAR UMA FUNÇÃO DNS_QUERIES OU ALGO ASSIM
		dns_query_t *query = NULL;

		//axfr_query(&sock, &dnsbuff, &query, &options, &pool);
		// NESTA PARTE EU AINDA IREI ENCAPSULAR ELA EM UMA FUNÇÃO PARA BRUTE FORCE
		dns_send_queries(&sock, &dns_buff, domain_qtypes, &query, &options, &pool);

		brute_force(&sock, &dns_buff, &query, shell.file, &options, &pool);
		if(shell.file) fclose(shell.file);
		close(sock.sockfd);
	}
}

// ADICIONAR TRATAMENTO DE ERROS AO INSERIR UM DOMÍNIO OU ENDEREÇO IP INVÁLIDO
// PERMITIR QUE SEJA INSERIDO COMO ARGUMENTO ENDEREÇOS IP AO INVÉS DE DOMÍNIOS
