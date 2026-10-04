/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "gpgme.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static gpgme_data_t open_data(const char *path)
{
	gpgme_data_t data = NULL;
	int fd = open(path, O_RDONLY);

	if (fd < 0 || gpgme_data_new_from_fd(&data, fd))
		return NULL;
	return data;
}

int main(int argc, char **argv)
{
	gpgme_ctx_t ctx = NULL;
	gpgme_data_t key = NULL;
	gpgme_data_t signature = NULL;
	gpgme_data_t signed_data = NULL;
	gpgme_signature_t result;
	gpgme_error_t error;
	unsigned long expected_error;
	unsigned long expected_summary;
	unsigned long expected_status;
	int exit_status = 0;

	if (argc != 8)
		return 2;
	expected_error = strtoul(argv[5], NULL, 0);
	expected_summary = strtoul(argv[6], NULL, 0);
	expected_status = strtoul(argv[7], NULL, 0);
	if (gpgme_new(&ctx) ||
	    gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL,
				      argv[4])) {
		exit_status = 3;
		goto out;
	}
	key = open_data(argv[1]);
	signature = open_data(argv[2]);
	signed_data = open_data(argv[3]);
	if (!key || !signature || !signed_data) {
		exit_status = 4;
		goto out;
	}
	error = gpgme_op_import(ctx, key);
	if (gpgme_err_code(error)) {
		fprintf(stderr, "import failed: %u\n", gpgme_err_code(error));
		exit_status = 5;
		goto out;
	}
	error = gpgme_op_verify(ctx, signature, signed_data, NULL);
	result = gpgme_op_verify_result(ctx)->signatures;
	fprintf(stderr, "api=%u summary=0x%x status=%u fpr=%s hash=%d\n",
		gpgme_err_code(error), result ? result->summary : 0,
		result ? gpgme_err_code(result->status) : 0,
		result && result->fpr ? result->fpr : "(null)",
		result ? result->hash_algo : 0);
	if (gpgme_err_code(error) != expected_error)
		exit_status = 6;
	if (result && (result->summary != expected_summary ||
		       gpgme_err_code(result->status) != expected_status))
		exit_status = 7;
out:
	gpgme_data_release(key);
	gpgme_data_release(signature);
	gpgme_data_release(signed_data);
	gpgme_release(ctx);
	return exit_status;
}
