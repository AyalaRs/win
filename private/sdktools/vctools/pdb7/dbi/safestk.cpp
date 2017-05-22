#include <malloc.h>
#include "safestk.h"



void* Allocator::AllocBytes(size_t size)
{
	return (void*)malloc(size);
}


