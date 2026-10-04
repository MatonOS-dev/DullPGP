/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "gpgme.h"
#include <stdio.h>

int main(void)
{
	static const char v6_key[] = {0xc6, 0x03, 0x06, 0x00, 0x00};
	static const char v6_signature[] = {0xc2, 0x03, 0x06, 0x00, 0x00};
	gpgme_ctx_t ctx = NULL;
	gpgme_data_t key_data = NULL;
	gpgme_data_t signature_data = NULL;
	gpgme_data_t signed_data = NULL;
	gpgme_error_t error;
	int status = 1;

	if (gpgme_new(&ctx) ||
	    gpgme_data_new_from_mem(&key_data, v6_key, sizeof(v6_key), 1))
		goto out;
	error = gpgme_op_import(ctx, key_data);
	if (gpgme_err_code(error) != GPG_ERR_NOT_SUPPORTED)
		goto out;
	if (gpgme_data_new_from_mem(&signature_data, v6_signature,
				    sizeof(v6_signature), 1) ||
	    gpgme_data_new_from_mem(&signed_data, "", 0, 1))
		goto out;
	error = gpgme_op_verify(ctx, signature_data, signed_data, NULL);
	if (gpgme_err_code(error) != GPG_ERR_NOT_SUPPORTED)
		goto out;
	fprintf(stderr, "v6 key and signature rejected as unsupported\n");
	status = 0;
out:
	gpgme_data_release(key_data);
	gpgme_data_release(signature_data);
	gpgme_data_release(signed_data);
	gpgme_release(ctx);
	return status;
}
