#pragma once

#include <stdio.h>
#include <getopt.h>
#include "options.h"
#include "dns_resolver.h"

typedef struct {
	FILE *file;             
	char arguments[100][101];
}shell_t;

void help (char *color);
void print_logo ();
void arg_check (int argc, char **argv, shell_t *shell, struct option *long_option);
void alloccheck (void *pointer);
void line (const char *character, int length, const char *color);
void error (char *message);
int hierarquic_print (dns_query_t *query, int layer);
void results_print (char *domain, dns_query_t *query, bool hierarquic);
