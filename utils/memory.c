#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "memory.h"

pool_t pool_create (size_t size)
{
	pool_t pool = {0};
	size += 8;
	pool.memory = malloc(size);
	uintptr_t ptr = (uintptr_t)pool.memory;
	ptr = (ptr + 7) & ~7;
	pool.current = pool.base = (uint8_t *)ptr;
	pool.end = pool.memory + size;
	return pool;
}

void pool_reset (pool_t *pool)
{
	pool->current = pool->base;
}

void pool_delete (pool_t *pool)
{
	free(pool->memory);
}

void copystr (char *src, char *dest)
{
	size_t len = strlen(src) + 1;
	memcpy(dest, src, len);
}
