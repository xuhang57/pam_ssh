/* $OpenBSD: digest-openssl.c,v 1.4 2014/07/03 03:26:43 djm Exp $ */
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

#include "includes.h"

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

////#include "openbsd-compat/openssl-compat.h"

#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

#ifndef HAVE_EVP_RIPEMD160
# define EVP_ripemd160 NULL
#endif /* HAVE_EVP_RIPEMD160 */
#ifndef HAVE_EVP_SHA256
# define EVP_sha256 NULL
# define EVP_sha384 NULL
# define EVP_sha512 NULL
#endif /* HAVE_EVP_SHA256 */

struct ssh_digest_ctx {
	int alg;
	EVP_MD_CTX *mdctx;
};

struct ssh_digest {
	int id;
	const char *name;
	size_t digest_len;
	const EVP_MD *(*mdfunc)(void);
};

/* NB. Indexed directly by algorithm number */
const struct ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",	 	16,	EVP_md5 },
	{ SSH_DIGEST_RIPEMD160,	"RIPEMD160",	20,	EVP_ripemd160 },
	{ SSH_DIGEST_SHA1,	"SHA1",	 	20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256", 	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512", 	64,	EVP_sha512 },
	{ -1,			NULL,		0,	NULL },
};

static const struct ssh_digest *
ssh_digest_by_alg(int alg)
{
	if (alg < 0 || alg >= SSH_DIGEST_MAX)
		return NULL;
	if (digests[alg].id != alg) /* sanity */
		return NULL;
	if (digests[alg].mdfunc == NULL)
		return NULL;
	return &(digests[alg]);
}

size_t
ssh_digest_bytes(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	return digest == NULL ? 0 : digest->digest_len;
}

#if 0
size_t
ssh_digest_blocksize(struct ssh_digest_ctx *ctx)
{
	return EVP_MD_CTX_block_size(&ctx->mdctx);
}
#endif

#if 0
struct ssh_digest_ctx *
ssh_digest_start(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	struct ssh_digest_ctx *ret;

	if (digest == NULL || ((ret = calloc(1, sizeof(*ret))) == NULL))
		return NULL;
	ret->alg = alg;
	EVP_MD_CTX_init(&ret->mdctx);
	if (EVP_DigestInit_ex(&ret->mdctx, digest->mdfunc(), NULL) != 1) {
		free(ret);
		return NULL;
	}
	return ret;
}
#endif

#if 0
int
ssh_digest_copy_state(struct ssh_digest_ctx *from, struct ssh_digest_ctx *to)
{
	if (from->alg != to->alg)
		return SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	if (!EVP_MD_CTX_copy_ex(&to->mdctx, &from->mdctx))
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}
#endif

#if 0
int
ssh_digest_update(struct ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	if (EVP_DigestUpdate(&ctx->mdctx, m, mlen) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}
#endif

#if 0
int
ssh_digest_update_buffer(struct ssh_digest_ctx *ctx, const struct sshbuf *b)
{
	return ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}
#endif

#if 0
int
ssh_digest_final(struct ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	if (dlen > UINT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen < digest->digest_len) /* No truncation allowed */
		return SSH_ERR_INVALID_ARGUMENT;
	if (EVP_DigestFinal_ex(&ctx->mdctx, d, &l) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (l != digest->digest_len) /* sanity */
		return SSH_ERR_INTERNAL_ERROR;
	return 0;
}
#endif

#if 0
void
ssh_digest_free(struct ssh_digest_ctx *ctx)
{
	if (ctx != NULL) {
		EVP_MD_CTX_cleanup(&ctx->mdctx);
		explicit_bzero(ctx, sizeof(*ctx));
		free(ctx);
	}
}
#endif

int
ssh_digest_memory(int alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	if (digest == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen > UINT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen < digest->digest_len)
		return SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	if (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), NULL))
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

#if 0
int
ssh_digest_buffer(int alg, const struct sshbuf *b, u_char *d, size_t dlen)
{
	return ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif
