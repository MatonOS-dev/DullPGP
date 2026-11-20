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
	gpgme_data_t signatures = NULL;
	gpgme_data_t signed_data = NULL;
	gpgme_signature_t signature;
	unsigned long expected_valid;
	unsigned long count = 0;
	unsigned long valid = 0;
	int exit_status = 0;

	if (argc != 6)
		return 2;
	expected_valid = strtoul(argv[5], NULL, 0);
	if (gpgme_new(&ctx) ||
	    gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL,
				      argv[4])) {
		exit_status = 3;
		goto out;
	}
	key = open_data(argv[1]);
	signatures = open_data(argv[2]);
	signed_data = open_data(argv[3]);
	if (!key || !signatures || !signed_data || gpgme_op_import(ctx, key)) {
		exit_status = 4;
		goto out;
	}
	if (gpgme_op_verify(ctx, signatures, signed_data, NULL)) {
		fprintf(stderr, "concatenated signature verification returned an API error\n");
		exit_status = 5;
		goto out;
	}
	for (signature = gpgme_op_verify_result(ctx)->signatures;
	     signature; signature = signature->next) {
		count++;
		if (signature->summary & GPGME_SIGSUM_VALID)
			valid++;
	}
	if (count != 2 || valid != expected_valid) {
		fprintf(stderr, "signature packets=%lu valid=%lu expected-valid=%lu\n",
			count, valid, expected_valid);
		exit_status = 6;
	}
out:
	gpgme_data_release(key);
	gpgme_data_release(signatures);
	gpgme_data_release(signed_data);
	gpgme_release(ctx);
	return exit_status;
}
