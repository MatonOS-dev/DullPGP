/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "gpgme.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static gpgme_data_t open_data(const char *path)
{
	gpgme_data_t data = NULL;
	int fd = open(path, O_RDONLY);

	if (fd < 0 || gpgme_data_new_from_fd(&data, fd))
		return NULL;
	return data;
}

static int verify_flathub(gpgme_ctx_t ctx, const char *vectors)
{
	char path[4096];
	gpgme_data_t signature;
	gpgme_data_t signed_data;
	gpgme_error_t error;
	gpgme_signature_t result;

	if (snprintf(path, sizeof(path), "%s/summary.gpgsig", vectors) >=
	    (int)sizeof(path))
		return 0;
	signature = open_data(path);
	if (snprintf(path, sizeof(path), "%s/summary", vectors) >=
	    (int)sizeof(path)) {
		gpgme_data_release(signature);
		return 0;
	}
	signed_data = open_data(path);
	if (!signature || !signed_data) {
		gpgme_data_release(signature);
		gpgme_data_release(signed_data);
		return 0;
	}
	error = gpgme_op_verify(ctx, signature, signed_data, NULL);
	result = gpgme_op_verify_result(ctx)->signatures;
	gpgme_data_release(signature);
	gpgme_data_release(signed_data);
	return !gpgme_err_code(error) && result &&
		(result->summary & GPGME_SIGSUM_VALID) && result->status == 0;
}

int main(int argc, char **argv)
{
	char path[4096];
	gpgme_ctx_t source = NULL;
	gpgme_ctx_t destination = NULL;
	gpgme_ctx_t reopened = NULL;
	gpgme_data_t keydata = NULL;
	gpgme_data_t exported = NULL;
	gpgme_key_t key = NULL;
	gpgme_key_t keys[2] = {NULL, NULL};
	int exit_status = 1;

	if (argc != 3)
		return 2;
	if (gpgme_new(&source) ||
	    gpgme_ctx_set_engine_info(source, GPGME_PROTOCOL_OpenPGP, NULL,
				      argv[2]))
		goto out;
	if (snprintf(path, sizeof(path), "%s/flathub.gpg", argv[1]) >=
	    (int)sizeof(path))
		goto out;
	keydata = open_data(path);
	if (!keydata || gpgme_op_import(source, keydata) ||
	    gpgme_op_keylist_start(source, NULL, 0) ||
	    gpgme_op_keylist_next(source, &key))
		goto out;
	keys[0] = key;
	if (gpgme_data_new(&exported) ||
	    gpgme_op_export_keys(source, keys, 0, exported) ||
	    gpgme_data_seek(exported, 0, SEEK_SET) < 0 ||
	    gpgme_new(&destination) ||
	    snprintf(path, sizeof(path), "%s/destination", argv[2]) >=
		(int)sizeof(path) ||
	    gpgme_ctx_set_engine_info(destination, GPGME_PROTOCOL_OpenPGP, NULL,
				      path) ||
	    gpgme_op_import(destination, exported) ||
	    !verify_flathub(destination, argv[1]))
		goto out;
	if (gpgme_new(&reopened) ||
	    snprintf(path, sizeof(path), "%s/destination", argv[2]) >=
		(int)sizeof(path) ||
	    gpgme_ctx_set_engine_info(reopened, GPGME_PROTOCOL_OpenPGP, NULL,
				      path) ||
	    !verify_flathub(reopened, argv[1]))
		goto out;
	fprintf(stderr, "export/import/persistent keyring: GOOD\n");
	exit_status = 0;
out:
	gpgme_key_unref(key);
	gpgme_data_release(keydata);
	gpgme_data_release(exported);
	gpgme_release(source);
	gpgme_release(destination);
	gpgme_release(reopened);
	return exit_status;
}
