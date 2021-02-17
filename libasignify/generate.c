/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_MLOCK
#include <sys/mman.h>
#endif

#include "asignify.h"
#include "asignify_internal.h"
#include "blake2.h"
#include "tweetnacl.h"

static bool
asignify_encrypt_privkey(struct asignify_private_key *privk, unsigned int rounds,
		asignify_password_cb password_cb, void *d)
{
	unsigned char canary[10];
	unsigned char xorkey[crypto_sign_SECRETKEYBYTES];
	char password[1024];
	int r;
	bool ret = false;

	privk->checksum = xmalloc(BLAKE2B_OUTBYTES);
	privk->salt = xmalloc(SALT_LEN);
	privk->rounds = rounds;
	privk->pbkdf_alg = PBKDF_ALG;
	randombytes(privk->salt, SALT_LEN);
	blake2b(privk->checksum, privk->encrypted_blob, NULL, BLAKE2B_OUTBYTES,
			crypto_sign_SECRETKEYBYTES, 0);

	randombytes(canary, sizeof(canary));
	memcpy(password + sizeof(password) - sizeof(canary), canary,
			sizeof(canary));
	r = password_cb(password, sizeof(password) - sizeof(canary), d);
	if (r <= 0 || r > sizeof(password) - sizeof(canary) ||
			memcmp(password + sizeof(password) - sizeof(canary), canary, sizeof(canary)) != 0) {
		goto cleanup;
	}

	if (pkcs5_pbkdf2(password, r, privk->salt, SALT_LEN, xorkey, sizeof(xorkey),
			privk->rounds) == -1) {
		goto cleanup;
	}

	explicit_memzero(password, sizeof(password));

	for (r = 0; r < sizeof(xorkey); r ++) {
		privk->encrypted_blob[r] ^= xorkey[r];
	}

	explicit_memzero(xorkey, sizeof(xorkey));
	ret = true;
cleanup:
	if (!ret) {
		free(privk->salt);
		privk->salt = NULL;
		free(privk->checksum);
		privk->checksum = NULL;
	}
	return (ret);
}

static bool
asignify_generate_v1(FILE *privf, FILE *pubf, unsigned int rounds,
		asignify_password_cb password_cb, void *d)
{

	struct asignify_private_key *privk;
	struct asignify_public_data *pubk;
	bool ret = false;

	if (privf == NULL || pubf == NULL) {
		return (false);
	}
	if (rounds != 0 && password_cb == NULL) {
		return (false);
	}
	if (rounds != 0 && rounds < PBKDF_MINROUNDS) {
		return (false);
	}

	privk = xmalloc0(sizeof(*privk));
	pubk = xmalloc0(sizeof(*pubk));

	privk->version = 1;
	privk->id = xmalloc(KEY_ID_LEN);
	randombytes(privk->id, KEY_ID_LEN);

	pubk->version = 1;
	pubk->data_len = crypto_sign_PUBLICKEYBYTES;
	pubk->id_len = KEY_ID_LEN;
	asignify_alloc_public_data_fields(pubk);

	memcpy(pubk->id, privk->id, KEY_ID_LEN);

	privk->encrypted_blob = xmalloc(crypto_sign_SECRETKEYBYTES);
	crypto_sign_keypair(pubk->data, privk->encrypted_blob);

	if (rounds > 0) {
		if (!asignify_encrypt_privkey(privk, rounds, password_cb, d)) {
			goto cleanup;
		}
	}

	ret = asignify_pubkey_write(pubk, pubf);
	if (ret) {
		ret = asignify_privkey_write(privk, privf);
	}

cleanup:
	asignify_public_data_free(pubk);

	explicit_memzero(privk->encrypted_blob, crypto_sign_SECRETKEYBYTES);
	free(privk->encrypted_blob);
	free(privk->id);
	free(privk);

	return (ret);
}

static bool
asignify_generate_pubkey_internal(struct asignify_private_data *privd,
		FILE *pubf)
{

	struct asignify_public_data *pubk;
	bool ret = true;

	if (privd == NULL || pubf == NULL) {
		return (false);
	}

#define	PUBKEY_OFF	(crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES)
	pubk = xmalloc0(sizeof(*pubk));
	pubk->version = 1;
	pubk->id = xmalloc(KEY_ID_LEN);
	pubk->id_len = KEY_ID_LEN;
	memcpy(pubk->id, privd->id, KEY_ID_LEN);
	pubk->data_len = crypto_sign_PUBLICKEYBYTES;
	pubk->data = xmalloc(pubk->data_len);
	memcpy(pubk->data, privd->data + PUBKEY_OFF, pubk->data_len);

	ret = asignify_pubkey_write(pubk, pubf);

	asignify_public_data_free(pubk);
	fclose(pubf);

	return (ret);
}

#define HEX_OUT_PRIVK(privk, field, name, size, f) do {						\
		hexdata = xmalloc((size) * 2 + 1);									\
		if(bin2hex(hexdata, (size) * 2 + 1, privk->field, (size)) == NULL) { \
			abort();														\
		}																	\
		fprintf(f, "%s: %s\n", (name), hexdata);							\
		free(hexdata);														\
	} while (0)

bool
asignify_privkey_write(struct asignify_private_key *privk, FILE *f)
{
	char *hexdata;

	if (privk == NULL || f == NULL) {
		return (false);
	}

	if (privk->version != 1) {
		return (false);
	}

	fprintf(f, PRIVKEY_MAGIC "\n" "version: %u\n", privk->version);
	HEX_OUT_PRIVK(privk, encrypted_blob, "data", crypto_sign_SECRETKEYBYTES, f);

	if (privk->id) {
		HEX_OUT_PRIVK(privk, id, "id", KEY_ID_LEN, f);
	}

	/* Encrypted privkey */
	if (privk->pbkdf_alg != NULL) {
		fprintf(f, "kdf: %s\n", privk->pbkdf_alg);
		fprintf(f, "rounds: %u\n", privk->rounds);
		HEX_OUT_PRIVK(privk, salt, "salt", SALT_LEN, f);
		HEX_OUT_PRIVK(privk, checksum, "checksum", BLAKE2B_OUTBYTES, f);
	}

	return (true);
}

bool
asignify_generate(const char *privkf, const char *pubkf, unsigned int version,
		unsigned int rounds, asignify_password_cb password_cb, void *d)
{
	FILE *privf, *pubf;
	bool ret = false;

	if (version != 1)
		return (false);

	privf = xfopen(privkf, "w");
	pubf = xfopen(pubkf, "w");

	if (!privf || !pubf) {
		goto cleanup;
	}

	ret = asignify_generate_v1(privf, pubf, rounds, password_cb, d);
cleanup:
	if (pubf != NULL)
		fclose(pubf);
	if (privf != NULL)
		fclose(privf);
	return (ret);
}

bool
asignify_generate_pubkey(const char *privkf, const char *pubkf,
		asignify_password_cb password_cb, void *d)
{
	FILE *privf, *pubf;
	struct asignify_private_data *privd = NULL;
	int error;
	bool ret;

	privf = xfopen(privkf, "r");
	pubf = xfopen(pubkf, "w");

	if (!privf || !pubf) {
		return (false);
	}

	privd = asignify_private_data_load(privf, &error, password_cb, d);
	if (privd == NULL) {
		/* XXX */
		(void)error;
		return (false);
	}

	ret = asignify_generate_pubkey_internal(privd, pubf);

	asignify_private_data_free(privd);
	return (ret);
}

bool
asignify_privkey_from_ssh(const char *sshkf, const char *privkf,
		unsigned int version, unsigned int rounds,
		asignify_password_cb password_cb, void *d)
{
	FILE *privf, *sshf;
	struct asignify_private_data *privd = NULL;
	struct asignify_private_key privk;
	bool ret = false;

	if (version != 1)
		return (false);

	privf = NULL;
	sshf = xfopen(sshkf, "r");

	if (!sshf) {
		return (false);
	}

	privd = asignify_ssh_privkey_load(sshf, NULL);
	if (privd == NULL) {
		goto cleanup;
	}

	privf = xfopen(privkf, "w");
	if (privf == NULL) {
		goto cleanup;
	}

	memset(&privk, 0, sizeof(privk));
	privk.encrypted_blob = privd->data;
	privk.version = version;
	privk.id = NULL;

	if (password_cb != NULL) {
		if (!asignify_encrypt_privkey(&privk, rounds, password_cb, d)) {
			goto cleanup;
		}
	}

	ret = asignify_privkey_write(&privk, privf);

cleanup:
	asignify_private_data_free(privd);
	if (sshf != NULL)
		fclose(sshf);
	if (privf != NULL)
		fclose(privf);

	return (ret);
}
