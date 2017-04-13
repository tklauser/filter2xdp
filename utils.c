/*
 * Partially taken from netsniff-ng.
 *
 * Copyright (C) 2017 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#include <stdlib.h>
#include <string.h>

#include "utils.h"

void *xmalloc(size_t size)
{
	void *ptr;

	if (unlikely(size == 0))
		panic("xmalloc: zero size\n");

	ptr = malloc(size);
	if (unlikely(ptr == NULL))
		panic("xmalloc: out of memory (allocating %zu bytes)\n",
		      size);

	return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (unlikely(nmemb == 0 || size == 0))
		panic("xcalloc: zero size\n");

	ptr = calloc(nmemb, size);
	if (unlikely(ptr == NULL))
		panic("xcalloc: out of memory (allocating %zu members of "
		      "%zu bytes)\n", nmemb, size);

	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	void *new_ptr;

	if (unlikely(size == 0))
		panic("xrealloc: zero size\n");

	new_ptr = realloc(ptr, size);
	if (unlikely(new_ptr == NULL))
		panic("xrealloc: out of memory (allocating %zu bytes)\n", size);

	return new_ptr;
}

char *argv2str(int startind, int argc, char **argv)
{
	off_t offset = 0;
	char *str = NULL;
	int ret, i;

	for (i = startind; i < argc; ++i) {
		size_t tlen = (i < argc - 1) ? 2 : 1;
		size_t alen = strlen(argv[i]) + tlen;
		size_t slen = str ? strlen(str) : 0;

		str = xrealloc(str, slen + alen);
		ret = snprintf(str + offset, strlen(argv[i]) + tlen, "%s%s",
				argv[i], tlen == 2 ? " " : "");
		if (ret < 0)
			panic("Cannot concatenate string!\n");
		else
			offset += ret;
	}

	return str;
}
