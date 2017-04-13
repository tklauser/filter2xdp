/*
 * Utility macros and functions.
 *
 * Copyright (C) 2017 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#ifndef __UTILS_H
#define __UTILS_H

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef offsetof
# define offsetof(type, member)	((size_t) &((type *) 0)->member)
#endif
#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif
#ifndef __unused
# define __unused		__attribute__((__unused__))
#endif
#ifndef __noreturn
# define __noreturn		__attribute__((noreturn))
#endif

static inline void __noreturn panic(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	vfprintf(stderr, fmt, vl);
	va_end(vl);

	exit(EXIT_FAILURE);
}

#define bug_on(condition)	assert(!(condition))

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);

static inline void xfree(void *ptr)
{
	free(ptr);
}

char *argv2str(int startind, int argc, char **argv);

#endif /* __UTILS_H */
