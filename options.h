#pragma once
#include <stdbool.h>

typedef struct {
    bool ipv4;
    bool ipv6;
    bool is_domain;
    bool axfr;
    bool hierarquic;
} options_t;

