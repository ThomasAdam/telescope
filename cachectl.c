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

#include "compat.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cache.h"

enum {
	MODE_INFO,
	MODE_ADD,
};

int mode = -1;

static void
set_prog_mode(int m)
{
	if (mode != -1)
		errx(1, "a mode was already specified");
	mode = m;
}

static char *
get_path(char *path, size_t len)
{
	char	*home;

	if ((home = getenv("HOME")) == NULL)
		errx(1, "HOME is not defined");

	strlcpy(path, home, len);
	strlcat(path, "/.telescope/cache", len);
	return path;
}

static int
copyall(FILE *in, FILE *out)
{
	char	buf[BUFSIZ];
	ssize_t	r;

	for (;;) {
		r = fread(buf, 1, sizeof(buf), in);
		if (r == 0)
			return 0;
		if (r == -1)
			return -1;
		if (fwrite(buf, 1, r, out) != (size_t)r)
			return -1;
	}
}

int
main(int argc, char **argv)
{
	FILE		*f;
	struct cache	 cache;
	size_t		 buflen;
	int		 ch;
	char		 cache_file[PATH_MAX];
	char		*buf, *path = NULL;
	const char	*arg;

#if 0
	static int attached = 0;
	while (!attached)
		sleep(1);
#endif

	while ((ch = getopt(argc, argv, "A:Ip:")) != -1) {
		switch (ch) {
		case 'A':
			set_prog_mode(MODE_ADD);
			arg = optarg;
			break;
		case 'I':
			set_prog_mode(MODE_INFO);
			break;
		case 'p':
			path = optarg;
			break;
		default:
			errx(1, "wrong usage");
		}
	}

	if (mode == -1)
		errx(1, "no mode specified");

	if (path == NULL)
		path = get_path(cache_file, sizeof(cache_file));

	if (cache_open(path, &cache) == -1)
		err(1, "can't open the cache file: %s",
		    cache_file);

	switch (mode) {
	case MODE_ADD:
		if ((f = open_memstream(&buf, &buflen)) == NULL)
			err(1, "open_memstream");
		if (copyall(stdin, f) == -1)
			err(1, "copyall");
		fclose(f);
		if (cache_insert(&cache, arg, buf, buflen) == -1)
			err(1, "cache_insert");
		free(buf);
		break;

	case MODE_INFO:
		printf("version:    %4d\n", cache.version);
		printf("entries:    %4d\n", cache.entries);
		printf("indexsize   %4llu\n", cache.indexsize);
		printf("hpadding:   %4llu\n", cache.hpadding);
		printf("free entry: %4llu\n", cache.free_entry);
		printf("offend:     %4llu\n", cache.offend);
		break;
	}

	cache_close(&cache);
	return 0;
}
