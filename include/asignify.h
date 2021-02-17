/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#ifndef libasignify_H
#define libasignify_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PBKDF_MINROUNDS 10000

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * Opaque structures
 */
struct asignify_verify_ctx;
struct asignify_sign_ctx;
struct asignify_encrypt_ctx;
typedef struct asignify_verify_ctx asignify_verify_t;
typedef struct asignify_sign_ctx asignify_sign_t;
typedef struct asignify_encrypt_ctx asignify_encrypt_t;

typedef int (*asignify_password_cb)(char *buf, size_t len, void *d);

/**
 * Signature type
 */
enum asignify_digest_type {
	ASIGNIFY_DIGEST_SHA256 = 0,
	ASIGNIFY_DIGEST_SHA512,
	ASIGNIFY_DIGEST_BLAKE2,
	ASIGNIFY_DIGEST_SIZE,
	ASIGNIFY_DIGEST_MAX
};

/**
 * Encryption type
 */
enum asignify_encrypt_type {
	ASIGNIFY_ENCRYPT_SAFE = 0,
	ASIGNIFY_ENCRYPT_FAST
};

/**
 * Initialize verify context
 * @return new verify context or NULL
 */
asignify_verify_t* asignify_verify_init(void);

/**
 * Load public key from a file
 * @param ctx verify context
 * @param pubf file name or '-' to read from stdin
 * @return true if a key has been successfully loaded
 */
bool asignify_verify_load_pubkey(asignify_verify_t *ctx, const char *pubf);

/**
 * Load and parse signature file
 * @param ctx verify context
 * @param sigf file name or '-' to read from stdin
 * @return true if a signature has been successfully loaded
 */
bool asignify_verify_load_signature(asignify_verify_t *ctx, const char *sigf);

/**
 * Verify file against parsed signature and pubkey
 * @param ctx verify context
 * @param checkf file name or '-' to read from stdin
 * @return true if a file is valid
 */
bool asignify_verify_file(asignify_verify_t *ctx, const char *checkf);

/**
 * Returns last error for verify context
 * @param ctx verify context
 * @return constant string corresponding to the last error occurred during verification
 */
const char* asignify_verify_get_error(asignify_verify_t *ctx);

/**
 * Free verify context
 * @param ctx verify context
 */
void asignify_verify_free(asignify_verify_t *ctx);

/**
 * Initialize sign context
 * @return new sign context or NULL
 */
asignify_sign_t* asignify_sign_init(void);

/**
 * Load private key from a file
 * @param ctx sign context
 * @param privf file name or '-' to read from stdin
 * @param password_cb function that is called to get password from a user
 * @param d opaque data pointer for password callback
 * @return true if a key has been successfully loaded
 */
bool asignify_sign_load_privkey(asignify_sign_t *ctx, const char *privf,
	asignify_password_cb password_cb, void *d);

/**
 * Add specified file to the signature context
 * @param ctx sign context
 * @param f file name or '-' to read from stdin
 * @param dt type of digest to be calculated
 * @return true if a file is valid
 */
bool asignify_sign_add_file(asignify_sign_t *ctx, const char *f,
	enum asignify_digest_type dt);

/**
 * Write the complete signature for this context
 * @param ctx sign context
 * @param sigf file name or '-' to write to stdout
 * @return true if a signature has been successfully written
 */
bool asignify_sign_write_signature(asignify_sign_t *ctx, const char *sigf);

/**
 * Returns last error for sign context
 * @param ctx sign context
 * @return constant string corresponding to the last error occurred during signing
 */
const char* asignify_sign_get_error(asignify_sign_t *ctx);

/**
 * Free sign context
 * @param ctx sign context
 */
void asignify_sign_free(asignify_sign_t *ctx);

/**
 * Generate new keypair
 * @param privkf filename for private key
 * @param pubkf filename for public key
 * @param version version of pair
 * @param rounds rounds of PBKDF (if 0 then private key is not encrypted)
 * @param password_cb password callback (if NULL then private key is not encrypted)
 * @param d opaque data pointer for password
 * @return true if pair has been written successfully
 */
bool asignify_generate(const char *privkf, const char *pubkf,
		unsigned int version, unsigned int rounds,
		asignify_password_cb password_cb, void *d);

/**
 * Regenerate public key for given private key
 * @param privkf filename for private key
 * @param pubkf filename for public key
 * @param password_cb password callback
 * @param d opaque data pointer for password
 * @return true if pair has been written successfully
 */
bool asignify_generate_pubkey(const char *privkf, const char *pubkf,
		asignify_password_cb password_cb, void *d);

/**
 * Safely zero specified memory region
 * @param pnt pointer to zero
 * @param len size of region
 */
void explicit_memzero(void * const pnt, const size_t len);

/**
 * Returns size of specified digest
 * @param type type of digest
 * @return size of digest or 0 if it is invalid
 */
unsigned int asignify_digest_len(enum asignify_digest_type type);

/**
 * Get name of the specified digest
 * @param type type of digest
 * @return symbolic name or NULL, this string must not be modified
 */
const char * asignify_digest_name(enum asignify_digest_type type);

/**
 * Calculates specific digest for a file represented by an open fd
 * @param type type of digest
 * @param fd file descriptor
 * @return allocated binary chunk with the digest or NULL in case of failure (this blob must be freed after use)
 */
unsigned char* asignify_digest_fd(enum asignify_digest_type type, int fd);

/**
 * Parse string and returns the digest type
 * @param data string to parse
 * @param dlen size of string
 * @return valid digest id or ASIGNIFY_DIGEST_MAX in case of failure
 */
enum asignify_digest_type asignify_digest_from_str(const char *data,
	ssize_t dlen);

/**
 * Convert unencrypted SSH ed25519 private key to the native format
 * @param sshkf filename for ssh key
 * @param privkf filename for native key
 * @param version veriosn to use (1 is the current version)
 * @param rounds rounds to apply PBKDF
 * @param password_cb password callback (or NULL for unencrypted native key)
 * @param d opaque data pointer for password callback
 * @return true if key has been generated successfully
 */
bool asignify_privkey_from_ssh(const char *sshkf, const char *privkf,
		unsigned int version, unsigned int rounds,
		asignify_password_cb password_cb, void *d);

/**
 * Initialize encrypt context
 * @return new encrypt context or NULL
 */
asignify_encrypt_t* asignify_encrypt_init(void);

/**
 * Load public key from a file
 * @param ctx encrypt context
 * @param pubf file name or '-' to read from stdin
 * @return true if a key has been successfully loaded
 */
bool asignify_encrypt_load_pubkey(asignify_encrypt_t *ctx, const char *pubf);

/**
 * Load private key from a file
 * @param ctx encrypt context
 * @param privf file name or '-' to read from stdin
 * @param password_cb function that is called to get password from a user
 * @param d opaque data pointer for password callback
 * @return true if a key has been successfully loaded
 */
bool asignify_encrypt_load_privkey(asignify_encrypt_t *ctx, const char *privf,
	asignify_password_cb password_cb, void *d);

/**
 * Encrypt and sign the specified file using remote pubkey and local privkey
 * @param ctx encrypt context
 * @param version version of encryption
 * @param inf input file
 * @param outf output file (MUST be a regular file)
 * @return true if input has been encrypted and signed
 */
bool
asignify_encrypt_crypt_file(asignify_encrypt_t *ctx, unsigned int version,
	const char *inf, const char *outf, enum asignify_encrypt_type type);

/**
 * Validate and decrypt the specified file using remote pubkey and local privkey
 * @param ctx encrypt context
 * @param inf input file (MUST be a regular file)
 * @param outf output file
 * @return true if input has been verified and decrypted
 */
bool
asignify_encrypt_decrypt_file(asignify_encrypt_t *ctx, const char *inf,
	const char *outf);
/**
 * Returns last error for encrypt context
 * @param ctx encrypt context
 * @return constant string corresponding to the last error occurred during signing
 */
const char* asignify_encrypt_get_error(asignify_encrypt_t *ctx);

/**
 * Free encrypt context
 * @param ctx encrypt context
 */
void asignify_encrypt_free(asignify_encrypt_t *ctx);

#if defined(__cplusplus)
}
#endif

#endif
