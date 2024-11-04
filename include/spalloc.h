#ifndef SPALLOC_H
#define SPALLOC_H

#include <stddef.h>

void* spmalloc(size_t size);
void* spcalloc(size_t n, size_t elem_size);
void* sprealloc(void* ptr, size_t size);
void spfree(void* ptr);

#endif
