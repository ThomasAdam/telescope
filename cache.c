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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <endian.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "cache.h"
#include "telescope.h"

#define nitems(v)		(sizeof(v)/sizeof(v[0]))

#define MAGIC			"\0\0TC\0\0"
#define FILE_VERSION		1

#define INDEX_OFFSET		(6+2+8)
#define INDEX_SIZE_OFFSET	(6+2)
#define FOFF_OFFSET(base)	((base) + 8) /* skip 8 bytes of urlen+flags */
#define ENTRY_SIZE(urlen)	(8 + 8 + 8 + 8 + (urlen))

#define MIN_HDR_PADDING		128 /* XXX: bump to sth like 1K */

#define CF_DELETE		0x01

#define CHUNK			16384 /* for inflate/deflate */

/*
 * Cache file
 * ==========
 *
 * Telescope uses a custom file format to persist page cache across
 * sessions.  The layout on disk is as follows:
 *
 * 	MAGIC string		6 bytes
 * 	version number		2 bytes
 *	index size              8 bytes
 * 	index entries		--
 * 	compressed pages	--
 *
 * The magic string is used to uniquely identify the cache file, as
 * well as for marking the file as "binary" for other applications
 * like less(1) or file(1).
 *
 * The version number is handy if in the future we need to add other
 * fields, for the time being should be set to `01' to indicate the
 * first version.
 *
 * The index size is the number of index entries present in the
 * index.  Each index entry has the following structure:
 *
 *	urlen			4 bytes
 *	flags			4 bytes
 *	file offset		8 bytes
 *	size			8 bytes
 *	UNIX timestamp		8 bytes
 *	URL			urlen bytes
 *
 * In truth, 2 bytes would be enough for urlen but 4 bytes allows for
 * better alignment.  However, the upper bound for the URL len is the
 * one given by the Gemini specification: 1024 bytes.  The file offset
 * is absolute, i.e. it is meant to be passed to fseek(3).  The UNIX
 * timestamp allows to delete older pages and is *always* encoded as
 * 64bit number, regardless of how wide time_t is.  The URL *is not*
 * NUL-terminated.
 *
 * The index can have some padding space to avoid amortize the cost of
 * inserting a new page.  The first entry whose urlen is zero marks
 * the start of the padding space.
 *
 * Each compressed page is a zlib deflate stream.  Future version may
 * change the format, but it seems unlikely.
 *
 * The rationale for compressing page by page instead of the whole
 * file, which should give better results, is that it's easier this
 * way to add/remove pages and jump to the nth one.
 *
 * All the numbers are stored in little-endian.
 */

static int
scan_index(struct cache *c)
{
	struct iovec	iov[4];
	struct stat	sb;
	ssize_t		r;
	uint32_t	urlen, flags;
	uint64_t	foff, size;
	off_t		off, firstpage, offend, end;

	if (fstat(c->fd, &sb) == -1)
		return -1;

	offend = 0;
	firstpage = sb.st_size;
	off = INDEX_OFFSET;
	c->entries = 0;

	end = INDEX_OFFSET + c->indexsize;
	while (off + ENTRY_SIZE(0) < end) {
		if (lseek(c->fd, off, SEEK_SET) == -1)
			return -1;

		r = 0;

		iov[0].iov_base = &urlen;
		iov[0].iov_len = sizeof(urlen);
		r += sizeof(urlen);

		iov[1].iov_base = &flags;
		iov[1].iov_len = sizeof(flags);
		r += sizeof(flags);

		iov[2].iov_base = &foff;
		iov[2].iov_len = sizeof(foff);
		r += sizeof(urlen);

		iov[3].iov_base = &size;
		iov[3].iov_len = sizeof(size);
		r += sizeof(size);

		if (readv(c->fd, iov, nitems(iov)) != r)
			return -1;

		urlen = le64toh(urlen);
		foff = le64toh(foff);
		size = le64toh(size);

		if (urlen == 0)
			break;

		firstpage = MIN(firstpage, (off_t)foff);
		offend = MAX(offend, (off_t)(foff + size));

		off += ENTRY_SIZE(urlen);
		if (off > end)
			return -1;

		c->entries++;
	}

	if (c->entries == 0) {
		c->indexsize = 0;
		c->free_entry = INDEX_OFFSET;
		c->hpadding = MIN_HDR_PADDING;
		c->offend = INDEX_OFFSET + c->hpadding;
	} else {
		if (off >= firstpage || offend < firstpage)
			return -1;

		c->free_entry = off;
		c->hpadding = firstpage - off;
		c->offend = offend;
	}

	return 0;
}

static int
write_entry(struct cache *c, const char *url, off_t fileoff, size_t pagesize,
    uint64_t ts)
{
	struct iovec	iov[6];
	uint32_t	ulen, flags = 0;
	uint64_t	pgsz, foff, isz;
	ssize_t		r = 0;

	if (url == NULL)
		ulen = 0;
	else
		ulen = strlen(url);

	ulen = htole64(ulen);
	foff = htole64(fileoff);
	pgsz = htole64(pagesize);
	ts   = htole64(ts);

	iov[0].iov_base = &ulen;
	iov[0].iov_len = sizeof(ulen);
	r += sizeof(ulen);

	iov[1].iov_base = &flags;
	iov[1].iov_len = sizeof(flags);
	r += sizeof(flags);

	iov[2].iov_base = &foff;
	iov[2].iov_len = sizeof(foff);
	r += sizeof(foff);

	iov[3].iov_base = &pgsz;
	iov[3].iov_len = sizeof(pgsz);
	r += sizeof(pgsz);

	iov[4].iov_base = &ts;
	iov[4].iov_len = sizeof(ts);
	r += sizeof(ts);

	iov[5].iov_base = (void *)url;
	iov[5].iov_len = ulen;
	r += ulen;

	if (writev(c->fd, iov, nitems(iov)) != r)
		return -1;

	c->indexsize += r;
	c->hpadding -= r;

	isz = htole64(c->indexsize);
	if (pwrite(c->fd, &isz, sizeof(isz), INDEX_SIZE_OFFSET) != sizeof(isz))
		return -1;

	return 0;
}

int
cache_open(const char *path, struct cache *c)
{
	off_t		off;
	uint16_t	v;
	char		magic[6];

	memset(c, 0, sizeof(*c));

	if ((c->fd = open(path, O_RDWR|O_CREAT, 0600)) == -1)
		return -1;

	if ((off = lseek(c->fd, 0, SEEK_END)) == -1)
		goto err;

	if (off == 0) {
		/* new cache file, initialize it. */
		if (write(c->fd, MAGIC, sizeof(magic)) != sizeof(magic))
			goto err;

		c->version = FILE_VERSION;
		v = htole16(FILE_VERSION);
		if (write(c->fd, &v, sizeof(v)) != sizeof(v))
			goto err;

		/* Don't need to convert because it is 0 */
		if (write(c->fd, &c->indexsize, sizeof(c->indexsize)) !=
		    sizeof(c->indexsize))
			goto err;

		c->free_entry = INDEX_OFFSET;
		c->hpadding = MIN_HDR_PADDING;
		c->offend = INDEX_OFFSET + c->hpadding;
		return 0;
	}

	if (lseek(c->fd, 0, SEEK_SET) == -1)
		goto err;

	if (read(c->fd, magic, sizeof(magic)) != sizeof(magic))
		goto err;

	if (memcmp(magic, MAGIC, sizeof(magic)) != 0)
		goto err;

	if (read(c->fd, &v, sizeof(v)) != sizeof(v))
		goto err;

	c->version = le16toh(v);
	if (c->version != FILE_VERSION)
		goto err;

	if (read(c->fd, &c->indexsize, sizeof(c->indexsize)) !=
	    sizeof(c->indexsize))
		goto err;
	c->indexsize = le64toh(c->indexsize);

	return scan_index(c);

err:
	close(c->fd);
	c->fd = -1;
	return -1;
}

int
cache_search(struct cache *c, const char *url, struct cache_hit *hit)
{
	return 0;
}

/*
 * Copy the first page after the last one, making space for new index
 * entries.  (This happens even when there is only one page.)
 */
static int
grow_header(struct cache *c)
{
	struct iovec	iov[4];
	ssize_t		len, r = 0;
	off_t		offend;
	uint32_t	urlen, flags;
	uint64_t	foff, size, s;
	char		chunk[BUFSIZ];

	if (lseek(c->fd, INDEX_OFFSET, SEEK_SET) == -1)
		return -1;

	offend = c->offend;

	iov[0].iov_base = &urlen;
	iov[0].iov_len = sizeof(urlen);
	r += sizeof(urlen);

	iov[1].iov_base = &flags;
	iov[1].iov_len = sizeof(flags);
	r += sizeof(flags);

	iov[2].iov_base = &foff;
	iov[2].iov_len = sizeof(foff);
	r += sizeof(foff);

	iov[3].iov_base = &size;
	iov[3].iov_len = sizeof(size);
	r += sizeof(size);

	if (readv(c->fd, iov, nitems(iov)) != r)
		return -1;

	urlen = le32toh(urlen);
	flags = le32toh(flags);
	foff = le64toh(urlen);
	size = le64toh(size);

	for (s = size; s != 0;) {
		len = MIN(sizeof(chunk), s);
		if ((r = pread(c->fd, chunk, len, foff)) != len)
			return -1;

		if (pwrite(c->fd, chunk, r, offend) != r)
			return -1;

		foff += r;
		offend += r;
		s -= r;
	}

	/* update the content pointer */
	foff = htole64(offend - size);
	if (pwrite(c->fd, &foff, sizeof(foff),
	    FOFF_OFFSET(INDEX_OFFSET)) == -1)
		return -1;

	c->offend = offend;
	c->hpadding += size;

	return 0;
}

static int
cache_deflate(const uint8_t *data, size_t len, FILE *dest, int level)
{
	z_stream	strm;
	size_t		have;
	uint8_t		out[CHUNK];

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	if (deflateInit(&strm, level) != Z_OK)
		return -1;

	strm.avail_in = len;
	strm.next_in = (uint8_t*)data;

	do {
		strm.avail_out = sizeof(out);
		strm.next_out = out;

		/*
		 * We provided all the data, there's no point in
		 * calling Z_NO_FLUSH.  Z_FINISH signals that we're
		 * done with in data, we only want to "take out".
		 */
		deflate(&strm, Z_FINISH);

		have = sizeof(out) - strm.avail_out;
		fwrite(out, 1, have, dest);
		if (ferror(dest)) {
			deflateEnd(&strm);
			return -1;
		}
	} while (strm.avail_out == 0);

	deflateEnd(&strm);
	return 0;
}

int
cache_insert(struct cache *c, const char *url, const void *page, size_t len)
{
	FILE	*z = NULL;
	size_t	 buflen, urlen, es;
	char	*buf = NULL;

	if (url == NULL || page == NULL)
		return -1;

	urlen = strlen(url);
	es = ENTRY_SIZE(urlen);
	while (es > c->hpadding) {
		assert(c->entries > 0);

		if (grow_header(c) == -1)
			return -1;
	}

	/* deflate the page */
	if ((z = open_memstream(&buf, &buflen)) == NULL)
		return -1;

	if (cache_deflate(page, len, z, Z_DEFAULT_COMPRESSION) == -1)
		goto err;

	fclose(z);
	z = NULL;

	/*
	 * Write first, then update the index.  This way, if an error
	 * occurrs, the index is still in a coherent state.
	 */
	/* TODO: allow partial writes? */
	if (pwrite(c->fd, buf, buflen, c->offend) == -1)
                goto err;

	if (lseek(c->fd, c->free_entry, SEEK_SET) == -1)
                goto err;

	if (write_entry(c, url, c->offend, buflen, time(NULL)) == -1)
                goto err;

	c->offend += len;

	free(buf);
	return 0;

err:
	if (z != NULL)
		fclose(z);
	free(buf);
	return -1;
}

int
cache_compat(struct cache *c)
{
	return -1;
}

void
cache_close(struct cache *c)
{
	if (c->fd != -1)
		close(c->fd);
}
