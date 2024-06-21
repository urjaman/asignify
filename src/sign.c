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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

#include "asignify.h"
#include "cli.h"

#ifdef HAVE_READPASSPHRASE_H
#include <readpassphrase.h>
#elif defined(HAVE_BSD_READPASSPHRASE_H)
#include <bsd/readpassphrase.h>
#else
#include "readpassphrase_compat.h"
#endif

static int
read_password(char *buf, size_t len, void *d)
{
	char password[512];
	int l;

	if (readpassphrase("Password:", password, sizeof(password), 0) != NULL) {
		l = strlen(password);
		memcpy(buf, password, l);
		explicit_memzero(password, sizeof(password));

		return (l);
	}

	return (-1);
}

const char *
cli_sign_help(bool full)
{

	const char *fullmsg = ""
		"asignify [global_opts] sign - creates a signature\n\n"
		"Usage: asignify sign [-n] [-N] [-d <digest>...] [-S <suffix>] <secretkey> [signature] [file1 [file2...]]\n"
		"\t-n            Do not record files sizes\n"
		"\t-N            Do not record filename (only one file per digest allowed)\n"
		"\t-d            Write specific digest (sha256, sha512, blake2)\n"
		"\t-S <suffix>   Write seperate digest for each file to file<suffix>\n"
		"\tsecretkey     Path to a secret key file make a signature\n"
		"\tsignature     Path to signature file to write\n"
		"\tfile          A file that will be recorded in the signature digests\n";

	if (!full) {
		return ("sign [-n] [-N] [-d <digest>] [-S <suffix>] secretkey [signature] [file1 [file2...]]");
	}

	return (fullmsg);
}

struct digest_item {
	enum asignify_digest_type type;
	struct digest_item *next;
};

static int
cli_write_sign(asignify_sign_t *sgn, const char* sigfile, int added, bool no_name)
{
	if (added == 0) {
		fprintf(stderr, "no digests has been added to the signature");
		return (-1);
	}

	if (!asignify_sign_write_signature(sgn, sigfile, no_name)) {
		fprintf(stderr, "cannot write sign file %s: %s\n", sigfile,
			asignify_sign_get_error(sgn));
		return (-1);
	}

	return 0;
}

int
cli_sign(int argc, char **argv)
{
	asignify_sign_t *sgn;
	const char *suffix = NULL;
	const char *seckeyfile = NULL, *sigfile = NULL;
	int i;
	int ch;
	int ret = 1;
	int added = 0;
	bool no_size = false;
	bool no_name = false;
	/* XXX: we do not free this list on exit */
	struct digest_item *dt_list = NULL, *dtit;
	enum asignify_digest_type dt;
	static struct option long_options[] = {
		{"no-size",   no_argument,     0,  'n' },
		{"no-name",   no_argument, 0, 'N'},
		{"digest", 	required_argument, 0,  'd' },
		{"suffix", 	required_argument, 0,  'S' },
		{0,         0,                 0,  0 }
	};

	while ((ch = getopt_long(argc, argv, "nNd:S:", long_options, NULL)) != -1) {
		switch (ch) {
		case 'n':
			no_size = true;
			break;
		case 'N':
			no_name = true;
			break;
		case 'd':
			dt = asignify_digest_from_str(optarg, strlen(optarg));
			if (dt == ASIGNIFY_DIGEST_MAX) {
				fprintf(stderr, "bad digest type: %s\n", optarg);
				return (0);
			}
			dtit = malloc(sizeof(*dtit));
			dtit->type = dt;
			dtit->next = dt_list;
			dt_list = dtit;
			break;
		case 'S':
			suffix = optarg;
			break;
		default:
			return (0);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		return (0);
	}

	if (dt_list == NULL) {
		dt_list = malloc(sizeof(*dt_list));
		dt_list->next = NULL;
		dt_list->type = ASIGNIFY_DIGEST_BLAKE2;
	}

	seckeyfile = argv[0];
	if (!suffix) sigfile = argv[1];

	sgn = asignify_sign_init();

	if (!asignify_sign_load_privkey(sgn, seckeyfile, read_password, NULL)) {
		fprintf(stderr, "cannot load private key %s: %s\n", seckeyfile,
			asignify_sign_get_error(sgn));
		asignify_sign_free(sgn);
		return (-1);
	}


	for (i = suffix ? 1 : 2; i < argc; i ++) {
		dtit = dt_list;
		while(dtit != NULL) {
			if (!asignify_sign_add_file(sgn, argv[i], dtit->type)) {
				fprintf(stderr, "cannot sign file %s: %s\n", argv[i],
					asignify_sign_get_error(sgn));
				ret = -1;
			}
			else {
				if (!quiet) {
					printf("added %s digest of %s\n",
							asignify_digest_name(dtit->type), argv[i]);
				}
				added ++;
			}
			dtit = dtit->next;
		}
		if (!no_size) {
			if (!asignify_sign_add_file(sgn, argv[i], ASIGNIFY_DIGEST_SIZE)) {
				fprintf(stderr, "cannot calculated file size %s: %s\n", argv[i],
					asignify_sign_get_error(sgn));
				ret = -1;
			}
		}
		if (suffix) {
			int r;
			int fnlen = strlen(argv[i]) + strlen(suffix) + 1;
			char *sigfn = malloc(fnlen);
			strcpy(sigfn, argv[i]);
			strcat(sigfn, suffix);
			r = cli_write_sign(sgn, sigfn, added, no_name);
			free(sigfn);
			asignify_sign_reset_files(sgn);
			added = 0;
			if (r < 0) {
				ret = -2;
				break;
			}

		}
	}

	if (!suffix) {
		if (cli_write_sign(sgn, sigfile, added, no_name))
			ret = -2;
	}

	asignify_sign_free(sgn);

	if (!quiet) {
		if (ret == -2) {
			/* We already wrote about this */
		} else if (ret == 1) {
			printf("Digests file(s) have been successfully signed\n");
		} else {
			printf("Digests file(s) have been signed but some files were not added due to errors\n");
		}
	}

	return (ret);
}
