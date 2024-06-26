/*
 * Copyright (c) 2021, 2024 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "xwrapper.h"

int
mark_nonblock_cloexec(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		return 0;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return 0;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
		return 0;
	return 1;
}

int
has_suffix(const char *str, const char *sufx)
{
	size_t l, s;

	l = strlen(str);
	s = strlen(sufx);

	if (l < s)
		return 0;

	return !strcmp(str + (l - s), sufx);
}

void *
hash_alloc(size_t len, void *d)
{
	d = xmalloc(len);
	return d;
}

void *
hash_calloc(size_t nmemb, size_t size, void *d)
{
	d = xcalloc(nmemb, size);
	return d;
}

void
hash_free(void *ptr, void *d)
{
	free(ptr);
}
