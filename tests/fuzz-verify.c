/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "gpgme.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FUZZ_VECTOR_DIR
#error FUZZ_VECTOR_DIR must name tests/vectors
#endif

static gpgme_ctx_t context;
static gpgme_data_t signed_data;

static int import_file(const char *path)
{
	FILE *file = fopen(path, "rb");
	long length;
	char *bytes;
	gpgme_data_t data = NULL;
	int ok = 0;
	if (!file || fseek(file, 0, SEEK_END) != 0 ||
	    (length = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0)
		goto out;
	bytes = malloc((size_t)length);
	if (!bytes || fread(bytes, 1, (size_t)length, file) != (size_t)length) {
		free(bytes);
		goto out;
	}
	if (gpgme_data_new_from_mem(&data, bytes, (size_t)length, 0) == 0 &&
	    gpgme_op_import(context, data) == 0)
		ok = 1;
	gpgme_data_release(data);
	free(bytes);
out:
	if (file)
		fclose(file);
	return ok;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char path[4096];
	FILE *file;
	long length;
	char *bytes;
	(void)argc;
	(void)argv;
	if (gpgme_new(&context) != 0)
		return 0;
	(void)snprintf(path, sizeof(path), "%s/flathub.gpg", FUZZ_VECTOR_DIR);
	if (!import_file(path))
		return 0;
	(void)snprintf(path, sizeof(path), "%s/summary", FUZZ_VECTOR_DIR);
	file = fopen(path, "rb");
	if (!file || fseek(file, 0, SEEK_END) != 0 ||
	    (length = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0)
		return 0;
	bytes = malloc((size_t)length);
	if (!bytes || fread(bytes, 1, (size_t)length, file) != (size_t)length)
		return 0;
	fclose(file);
	if (gpgme_data_new_from_mem(&signed_data, bytes, (size_t)length, 0) != 0)
		return 0;
	return 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	gpgme_data_t signature = NULL;
	if (!context || !signed_data || size == 0 || size > 1024u * 1024u)
		return 0;
	if (gpgme_data_new_from_mem(&signature, (const char *)data, size, 1) == 0)
		(void)gpgme_op_verify(context, signature, signed_data, NULL);
	gpgme_data_release(signature);
	return 0;
}
