#pragma once
#include <stdint.h>
#include <stdlib.h>

typedef struct 
{
	uint8_t *memory;
	uint8_t *base;
	uint8_t *current;
	uint8_t *end;
}pool_t;

#define POOL_ALLOC(pool, size)                          \
	((pool)->current += size, (pool)->current - size) 

pool_t pool_create (size_t size);
void pool_reset (pool_t *pool);
void pool_delete (pool_t *pool);
void copystr (char *src, char *dest);
