#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include "colors.h"
#include "cli.h"
#include "dns_resolver.h"
#include "dns_protocol.h"
#include "memory.h"

void help ()
{
	line("✦ ✧ ", 25, LILAC);
	printf("%sUsage: %sordereye-dnsmap <wordlist> <domain> [ options ]\n\n", SKYBLUE, YELLOW);
    
	printf("%sOptions:\n", SKYBLUE);
	printf("%s  -h, --help%s           Show this help message and exit\n\n", YELLOW, SKYBLUE);
    
	printf("%sParameters:\n", SKYBLUE);
	printf("%s  wordlist             %sPath to the wordlist file for subdomain enumeration\n", YELLOW, SKYBLUE);
	printf("%s  domain               %sTarget domain name\n\n", YELLOW, SKYBLUE);
    
	printf("Examples:\n");
	printf("  1. Subdomain enumeration with wordlist:\n");
	printf("%s     ordereye-dnsmap wordlist/list.txt youtube.com\n\n", YELLOW);
    
	printf("%s  2. Using a custom wordlist:\n", SKYBLUE);
	printf("%s     ordereye-dnsmap /path/to/subdomains.txt example.com\n\n", YELLOW);
    
	printf("%s  3. Show this help message:\n", SKYBLUE);
	printf("%s     ordereye-dnsmap -h\n", YELLOW);
	printf("     ordereye-dnsmap --help%s\n\n", RESET);
	line("✦ ✧ ", 25, LILAC);

	exit(EXIT_SUCCESS);
}

void print_logo ()
{
	printf("%s                                ✴ .✴.✴.'... .✴..✴\n", BLUE);
	printf("%s                             ✴✴✴,LX✦OOOOOOkkxoc::;'✴\n", BLUE);
	printf("%s                      ✴..✴';lk0000OxddxO✧OOOOkoc:::;'. ✴\n", BLUE);
	printf("%s                       ..✴.,oxxxl:,..... %s✴%s  clccooo;.',;;.\n", BLUE, PURPLE, BLUE);
	printf("%s                  ✴✴.  .:o:;;,...  ... %s✴ |✴%s .;:,.,:::,....,,✴\n", BLUE, PURPLE, BLUE);
	printf("%s               ✴✴✴  ..,.;.,.,  '  '..  %s✴ |✴%s ..',,..,',,.... .'''✴\n", BLUE, PURPLE, BLUE);
	printf("%s             ✴,.   .,.''.;,.'. ' ..,'  %s✴ |✴%s ' '.;.'  ,........   .''.✴\n", BLUE, PURPLE, BLUE);
	printf("%s              ✴.✴.✴  .,;::cl;;... '.l  %s✴ |✴%s .'., ,.'  .. ' '. '.   .✴'\n", BLUE, PURPLE, BLUE);
	printf("%s                  .✴'...,cl✴doo;....'  %s✴ |✴%s ..'.'''. .'.',,:..✴✴✴✴✴\n", BLUE, PURPLE, BLUE);
	printf("%s                     ✴'''..;oxkOkl✶,'..  %s.%s ...;,'..:dodl;'...✴\n", BLUE, PURPLE, BLUE);
	printf("%s                       ✴.''.':oO0✦00OOkdoddxdoldOOxo:'...\n", BLUE);
	printf("%s                           ✴.✴.';codxkkkOkkxxdl:'..✴\n", BLUE);
	printf("%s                                ✴....✴⋆★✶✦✧.....✴\n\n\n", BLUE);

	printf("%s    ::::::::   :::::::::  :::::::::  :::::::::: ::::::::: %s      ::::::::::  ::: :::   ::::::::::\n", BLUE, PURPLE);
	printf("%s   :+:    :+:  :+:    :+: :+:    :+: :+:        :+:    :+:%s      f:+:        :+: :+:   :+:\n", BLUE, PURPLE);
	printf("%s  +:+      +:+ +:+    +:+ +:+    +:+ +:+        +:+    +:+%s      +:+         +:+ +:+   +:+\n", BLUE, PURPLE);
	printf("%s  +#+      +:+ +#++:++#:  +#+    +:+ +#++:++#   +#++:++#: %s      +#++:++#     +#++:    +#++:++#\n", BLUE, PURPLE);
	printf("%s  +#+      +#+ +#+    +#+ +#+    +#+ +#+        +#+    +#+%s      +#+           +#+     +#+\n", BLUE, PURPLE);
	printf("%s   #+#    #+#  #+#    #+# #+#    #+# #+#        #+#    #+#%s      #+#           #+#     #+#\n", BLUE, PURPLE);
	printf("%s    ########   ###    ### #########  ########## ###    ###%s      ##########    ###     ##########\n\n", BLUE, PURPLE);
	printf("Order Eye | DNS Infraestructure Mapping v(1.0.0) \n");
	printf("Part of the Order Eye Cybersecurity Reconnaissance Toolkit\n\n");
	printf("Usage: ordereye-dnsenum [options] [wordlist] [domain]\n");
	printf("Use --help for more information\n\n");
	printf("GitHub: https://github.com/Ordersec\n");
}

void line (const char *character, int length, const char *color)
{
	printf("%s", color);
	for(int c = 0; c < length; c++)
		printf("%s", character);
	printf("%s\n", RESET);

}

void arg_check (int argc, char **argv, shell_t *shell, struct option *long_options)
{
	int opt, argpos = 0;
	while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1)
	{
		switch (opt)
		{
			case 'h':
				help();
				break;
		}

	}

	shell->file = fopen(argv[optind], "r");

	for (int c = optind + 1; c < argc; c++, argpos++)
		copystr(argv[c], shell->arguments[argpos]);
}

void alloccheck (void *pointer)
{
	if (!pointer) error("Memory allocation fail");
}

void error (char *message)
{
	fprintf(stderr, "%s%s%s", RED, message, RESET);
	exit(EXIT_FAILURE);
}

void title (const char *character, int strlength, int qtype, char *domain)
{
	line(character , 25, LILAC);
	printf("\n");
	printf("%sQUERY %s of %s%s\n", SKYBLUE, get_strqtype(qtype), domain, RESET);
	printf("\n");
	line(character , 25, LILAC);
}

int hierarquic_print(dns_query_t *query, int layer) 
{
	if(!query) return -1;
	for(dns_query_t *cursor = query; cursor; cursor = cursor->next)
	{
		printf(" %s│", YELLOW);  
		for(int c = 0; c < layer; c++) printf("  ");

		if(cursor->next) printf(" ├─");
		else printf(" └─");

		printf(" %s%s ⟪%s %s | %s | %u %s⟫%s\n", SKYBLUE, cursor->answer.answer, YELLOW, get_strqtype(cursor->answer.qtype), get_strqclass(cursor->answer.qclass), cursor->answer.ttl, SKYBLUE, RESET);
		hierarquic_print(cursor->child, layer + 1);
	}

	return 0;
}

void results_print(char *domain, dns_query_t *query, bool hierarquic)
{
	title("✦ ✧ ", 25, query->qtype, domain);
	printf("%s✦ %s%s%s\n",YELLOW, PURPLE, domain, RESET);
	if(hierarquic)
	{
		int layer = 1; 
		// print de dados com hierarquia (NS, MX, CNAME)
		hierarquic_print(query, layer);

	} else
	{
		if(query->qtype == DNS_SOA)
		{
			printf(" %s├─ MNAME: %s%s (Primary Nameserver)%s\n", YELLOW, SKYBLUE, query->answer.soa.mname, RESET);
			printf(" %s├─ RNAME: %s%s (Responsible Person)%s\n", YELLOW, SKYBLUE, query->answer.soa.rname, RESET);
			printf(" %s├─ SERIAL: %s%u (Zone Version)%s\n", YELLOW, SKYBLUE, query->answer.soa.serial, RESET);
			printf(" %s├─ REFRESH: %s%u (Secondary NS refresh interval)%s\n", YELLOW, SKYBLUE, query->answer.soa.refresh, RESET);
			printf(" %s├─ RETRY: %s%u (Retry interval on failure)%s\n", YELLOW, SKYBLUE, query->answer.soa.retry, RESET);
			printf(" %s├─ EXPIRE: %s%u (Zone expiration time)%s\n", YELLOW, SKYBLUE, query->answer.soa.expire, RESET);
			printf(" %s└─ MINIMUM: %s%u (Negative caching TTL)%s\n", YELLOW, SKYBLUE, query->answer.soa.minimum, RESET);
		} else
		{
			for(dns_query_t *cursor = query; cursor; cursor = cursor->next) printf(" %s├─ %s %s ⟪ %s | %s | %u ⟫ %s\n", YELLOW, SKYBLUE, cursor->answer.answer, get_strqtype(cursor->answer.qtype), get_strqclass(cursor->answer.qclass), cursor->answer.ttl, RESET);
		}
	}

}
