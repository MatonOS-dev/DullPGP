/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "gpgme.h"
#include <openssl/evp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void fuzz_import(const unsigned char *data, size_t size)
{
	gpgme_ctx_t ctx = NULL;
	gpgme_data_t input = NULL;
	if (gpgme_new(&ctx) == 0 &&
	    gpgme_data_new_from_mem(&input, (const char *)data, size, 1) == 0)
		(void)gpgme_op_import(ctx, input);
	gpgme_data_release(input);
	gpgme_release(ctx);
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	const char *root = getenv("GPGME_LITE_FUZZ_HOME_ROOT");
	char home[4096];
	char keyring[4096];
	char pubring[4096];
	char dir[4096];
	char parent[4096];
	unsigned char *armored = NULL;
	int encoded_len;
	static const char armor_prefix[] =
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
		"Version: DullPGP fuzz\n\n";
	static const char armor_suffix[] = "\n-----END PGP PUBLIC KEY BLOCK-----\n";
	if (!root || !*root ||
	    snprintf(home, sizeof(home), "%s/import-XXXXXX", root) >=
		    (int)sizeof(home) ||
	    size == 0 || size > 8u * 1024u * 1024u || !mkdtemp(home))
		return 0;
	(void)snprintf(parent, sizeof(parent), "%s/.local/share", home);
	{
		char local[sizeof(home) + sizeof("/.local")];
		(void)snprintf(local, sizeof(local), "%s/.local", home);
		if (mkdir(local, 0700) != 0 || mkdir(parent, 0700) != 0)
			goto done;
	}
	(void)snprintf(dir, sizeof(dir), "%s/.local/share/gpgme-lite", home);
	if (mkdir(dir, 0700) != 0)
		goto done;
	if (setenv("HOME", home, 1) != 0)
		goto done;
	fuzz_import(data, size);
	if (size > (size_t)INT_MAX)
		goto done;
	armored = malloc(sizeof(armor_prefix) + 4 * ((size + 2) / 3) +
			 sizeof(armor_suffix));
	if (!armored)
		goto done;
	memcpy(armored, armor_prefix, sizeof(armor_prefix) - 1);
	encoded_len = EVP_EncodeBlock(armored + sizeof(armor_prefix) - 1,
				      data, (int)size);
	if (encoded_len < 0)
		goto done;
	memcpy(armored + sizeof(armor_prefix) - 1 + (size_t)encoded_len,
	       armor_suffix, sizeof(armor_suffix));
	fuzz_import(armored, sizeof(armor_prefix) - 1 +
		    (size_t)encoded_len + sizeof(armor_suffix) - 1);
done:
	free(armored);
	(void)snprintf(dir, sizeof(dir), "%s/.local/share/gpgme-lite", home);
	(void)snprintf(keyring, sizeof(keyring), "%s/gpgme-lite.keys", dir);
	(void)snprintf(pubring, sizeof(pubring), "%s/pubring.gpg", dir);
	(void)unlink(keyring);
	(void)unlink(pubring);
	(void)rmdir(dir);
	(void)rmdir(parent);
	{
		char local[sizeof(home) + sizeof("/.local")];
		(void)snprintf(local, sizeof(local), "%s/.local", home);
		(void)rmdir(local);
	}
	(void)rmdir(home);
	return 0;
}
