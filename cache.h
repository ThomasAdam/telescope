/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
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

#ifndef CACHE_H
#define CACHE_H

#include <sys/types.h>

#include <stdint.h>
#include <stddef.h>

struct cache {
	int		fd;
	uint16_t	version;
	uint32_t	entries;
	uint64_t	indexsize;
	uint64_t	hpadding;   /* header padding */
	uint64_t	free_entry; /* first free entry */
	uint64_t	offend;	    /* EOF offset */
};

struct cache_hit {
	off_t	 pos;
};

int		cache_open(const char *path, struct cache *);
int		cache_search(struct cache *, const char *, struct cache_hit *);
int		cache_insert(struct cache *, const char *, const void *, size_t);
void		cache_close(struct cache *);

#endif
