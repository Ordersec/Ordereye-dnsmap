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

// Colors

#define RED "\033[38;2;255;40;40m"
#define YELLOW "\033[0;33m"
#define RESET "\033[0m"

void help (char *color)
{
	printf("%sUsage: ./ordereye-parser [options] [file] [pattern] [count] [position] [substring] [count]\n\n", color);

	printf("Options:\n");
	printf("  -l       Normal mode (like grep). Prints the entire line if it contains the specified pattern.\n");
	printf("  -p       Extraction mode. Extracts everything after the position until the pattern is found or after a certain number of occurrences.\n");
	printf("  -s       Substring extraction mode. Extracts everything after the specified substring until it finds the specified pattern a given number of times.\n");
	printf("  -v       Invert the result for `-l` mode, showing lines that do NOT contain the specified pattern.\n");
	printf("  -e       Enable enumeration. For `-l`, `-s`, and `-p` modes, this will display the line number alongside the results.\n\n");

	printf("Parameters:\n");
	printf("  file     The file you want to process.\n");
	printf("  pattern  The pattern or substring you want to search for.\n");
	printf("  count    The number of occurrences of the pattern or substring to consider for `-p` and `-s` modes.\n");
	printf("  position The starting position in the string for `-p` mode (applicable only for `-p` mode).\n");
	printf("  substring The substring used as the delimiter for extraction (applicable to `-p` and `-s` modes).\n\n");

	printf("Examples:\n");
	printf("1. Using `-l` mode with enumeration:\n");
	printf("   ./ordereye-parser -le test.txt 'substring'\n\n");

	printf("2. Using `-p` mode to extract after position 1 until the second occurrence of a space:\n");
	printf("   ./ordereye-parser -pe test.txt 1 ' ' 2\n\n");

	printf("3. Using `-s` mode to extract everything after 'substring' until the pattern '.' appears 2 times:\n");
	printf("   ./ordereye-parser -se test.txt 'substring' 1 '.' 2\n\n");

	printf("4. Using `-v` with `-l` to exclude lines containing 'substring':\n");
	printf("   ./ordereye-parser -l -v test.txt 'substring'%s\n", RESET);
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
				help(SKYBLUE);
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

		printf(" %s%s ⟪ %s | %s | %u ⟫%s\n", PURPLE, cursor->answer.answer, get_strqtype(cursor->answer.qtype), get_strqclass(cursor->answer.qclass), cursor->answer.ttl, RESET);
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
			printf(" %s├─ MNAME: %s%s (Primary Nameserver)%s\n", YELLOW, PURPLE, query->answer.soa.mname, RESET);
			printf(" %s├─ RNAME: %s%s (Responsible Person)%s\n", YELLOW, PURPLE, query->answer.soa.rname, RESET);
			printf(" %s├─ SERIAL: %s%u (Zone Version)%s\n", YELLOW, PURPLE, query->answer.soa.serial, RESET);
			printf(" %s├─ REFRESH: %s%u (Secondary NS refresh interval)%s\n", YELLOW, PURPLE, query->answer.soa.refresh, RESET);
			printf(" %s├─ RETRY: %s%u (Retry interval on failure)%s\n", YELLOW, PURPLE, query->answer.soa.retry, RESET);
			printf(" %s├─ EXPIRE: %s%u (Zone expiration time)%s\n", YELLOW, PURPLE, query->answer.soa.expire, RESET);
			printf(" %s└─ MINIMUM: %s%u (Negative caching TTL)%s\n", YELLOW, PURPLE, query->answer.soa.minimum, RESET);
		} else
		{
			for(dns_query_t *cursor = query; cursor; cursor = cursor->next) printf(" %s├─ %s %s ⟪ %s | %s | %u ⟫ %s\n", YELLOW, PURPLE, cursor->answer.answer, get_strqtype(cursor->answer.qtype), get_strqclass(cursor->answer.qclass), cursor->answer.ttl, RESET);
		}
	}

}
