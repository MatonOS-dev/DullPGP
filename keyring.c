/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static char *keyring_path(gpgme_ctx_t ctx)
{
	static const char suffix[] = "/gpgme-lite.keys";
	size_t home_len;
	char *path;

	if (!ctx->home)
		return NULL;
	home_len = strlen(ctx->home);
	if (home_len > 4096 - sizeof(suffix))
		return NULL;
	path = malloc(home_len + sizeof(suffix));
	if (!path)
		return NULL;
	memcpy(path, ctx->home, home_len);
	memcpy(path + home_len, suffix, sizeof(suffix));
	return path;
}

static char *pubring_path(gpgme_ctx_t ctx)
{
	static const char suffix[] = "/pubring.gpg";
	size_t home_len;
	char *path;

	if (!ctx->home)
		return NULL;
	home_len = strlen(ctx->home);
	if (home_len > 4096 - sizeof(suffix))
		return NULL;
	path = malloc(home_len + sizeof(suffix));
	if (!path)
		return NULL;
	memcpy(path, ctx->home, home_len);
	memcpy(path + home_len, suffix, sizeof(suffix));
	return path;
}

static int append_import_packet(CBB *stream, struct gl_packet packet);
static gpgme_error_t push_parsed_key(gpgme_key_t **keys, size_t *count,
				     unsigned char *encoded, size_t encoded_len);
static int add_key(gpgme_ctx_t ctx, gpgme_key_t key);

static gpgme_error_t load_pubring_key(gpgme_ctx_t ctx,
				      unsigned char *encoded, size_t encoded_len)
{
	gpgme_key_t key = NULL;
	gpgme_error_t error = gl_parse_key(encoded, encoded_len, &key);

	if (error)
		return error;
	if (!add_key(ctx, key)) {
		gl_free_key(key);
		return gl_err(GPG_ERR_ENOMEM);
	}
	return 0;
}

static gpgme_error_t load_pubring(gpgme_ctx_t ctx, const unsigned char *bytes,
				  size_t len)
{
	CBS packets;
	struct gl_packet packet;
	CBB stream;
	unsigned char *encoded = NULL;
	size_t encoded_len = 0;
	gpgme_error_t error = 0;

	if (!len)
		return 0;
	CBS_init(&packets, bytes, len);
	if (!CBB_init(&stream, 1024))
		return gl_err(GPG_ERR_ENOMEM);
	while (CBS_len(&packets)) {
		if (!gl_next_packet(&packets, &packet)) {
			error = gl_err(GPG_ERR_BAD_DATA);
			goto out;
		}
		if (packet.tag == 6 && CBB_len(&stream)) {
			if (!CBB_finish(&stream, &encoded, &encoded_len)) {
				error = gl_err(GPG_ERR_ENOMEM);
				goto out;
			}
		error = load_pubring_key(ctx, encoded, encoded_len);
			OPENSSL_free(encoded);
			encoded = NULL;
			if (error || !CBB_init(&stream, 1024)) {
				if (!error)
					error = gl_err(GPG_ERR_ENOMEM);
				goto out;
			}
		}
		if (!append_import_packet(&stream, packet)) {
			error = gl_err(GPG_ERR_BAD_DATA);
			goto out;
		}
	}
	if (CBB_len(&stream)) {
		if (!CBB_finish(&stream, &encoded, &encoded_len)) {
			error = gl_err(GPG_ERR_ENOMEM);
			goto out;
		}
		error = load_pubring_key(ctx, encoded, encoded_len);
	}
out:
	OPENSSL_free(encoded);
	CBB_cleanup(&stream);
	return error;
}

static int add_key(gpgme_ctx_t ctx, gpgme_key_t key)
{
	gpgme_key_t *keys;
	size_t i;

	for (i = 0; i < ctx->key_count; i++) {
		if (strcmp(ctx->keys[i]->fpr, key->fpr) == 0) {
			gl_free_key(key);
			return 1;
		}
	}
	keys = realloc(ctx->keys, (ctx->key_count + 1) * sizeof(*keys));
	if (!keys)
		return 0;
	ctx->keys = keys;
	ctx->keys[ctx->key_count++] = key;
	return 1;
}

gpgme_error_t gl_reload_keyring(gpgme_ctx_t ctx)
{
	char *pubring;
	FILE *file;
	pubring = pubring_path(ctx);
	if (!pubring)
		return gl_err(GPG_ERR_ENOMEM);
	file = fopen(pubring, "rb");
	free(pubring);
	if (!file) {
		if (errno == ENOENT)
			return 0;
		return gl_err(GPG_ERR_KEYRING_OPEN);
	}
	{
		unsigned char *bytes = malloc(GL_MAX_OBJECT);
		size_t len = 0;
		int ch;

		if (!bytes) {
			fclose(file);
			return gl_err(GPG_ERR_ENOMEM);
		}
		while ((ch = fgetc(file)) != EOF) {
			if (len == GL_MAX_OBJECT) {
				free(bytes);
				fclose(file);
				return gl_err(GPG_ERR_TOO_LARGE);
			}
			bytes[len++] = (unsigned char)ch;
		}
		if (ferror(file)) {
			free(bytes);
			fclose(file);
			return gl_err(GPG_ERR_KEYRING_OPEN);
		}
		fclose(file);
		{
			gpgme_error_t error = load_pubring(ctx, bytes, len);
			free(bytes);
			if (error)
				return error;
		}
	}
	return 0;
}

gpgme_error_t gl_load_keyring(gpgme_ctx_t ctx)
{
	char *path;
	FILE *file;
	unsigned char header[4];

	path = keyring_path(ctx);
	if (!path)
		return gl_err(GPG_ERR_ENOMEM);
	file = fopen(path, "rb");
	free(path);
	if (!file) {
		if (errno != ENOENT)
			return gl_err(GPG_ERR_KEYRING_OPEN);
	} else {
		while (fread(header, 1, sizeof(header), file) == sizeof(header)) {
			CBS size_cbs;
			uint32_t size;
			unsigned char *bytes;
			gpgme_key_t key = NULL;

			CBS_init(&size_cbs, header, sizeof(header));
			if (!CBS_get_u32(&size_cbs, &size) || size == 0 ||
			    size > GL_MAX_OBJECT) {
				fclose(file);
				return gl_err(GPG_ERR_BAD_DATA);
			}
			bytes = malloc(size);
			if (!bytes) {
				fclose(file);
				return gl_err(GPG_ERR_ENOMEM);
			}
			if (fread(bytes, 1, size, file) != size) {
				free(bytes);
				fclose(file);
				return gl_err(GPG_ERR_TRUNCATED);
			}
			if (gl_parse_key(bytes, size, &key) || !add_key(ctx, key)) {
				free(bytes);
				fclose(file);
				return gl_err(GPG_ERR_BAD_DATA);
			}
			free(bytes);
		}
		if (ferror(file)) {
			fclose(file);
			return gl_err(GPG_ERR_KEYRING_OPEN);
		}
		fclose(file);
	}
	return gl_reload_keyring(ctx);
}

gpgme_error_t gl_save_keyring(gpgme_ctx_t ctx, gpgme_key_t key)
{
	char *path;
	int fd;
	uint8_t header[4];
	struct gl_key *private_key = (struct gl_key *)key;
	CBB length;
	uint8_t *length_data = NULL;
	size_t length_len = 0;
	size_t written = 0;
	char *directory;

	path = keyring_path(ctx);
	if (!path)
		return gl_err(GPG_ERR_ENOMEM);
	directory = gl_strdup(ctx->home);
	if (!directory) {
		free(path);
		return gl_err(GPG_ERR_ENOMEM);
	}
	if (mkdir(directory, 0700) < 0 && errno != EEXIST) {
		free(directory);
		free(path);
		return gl_err(GPG_ERR_KEYRING_OPEN);
	}
	free(directory);
	if (private_key->packets_len > UINT32_MAX ||
	    !CBB_init(&length, 4) ||
	    !CBB_add_u32(&length, (uint32_t)private_key->packets_len) ||
	    !CBB_finish(&length, &length_data, &length_len)) {
		CBB_cleanup(&length);
		free(path);
		return gl_err(GPG_ERR_TOO_LARGE);
	}
	memcpy(header, length_data, sizeof(header));
	OPENSSL_free(length_data);
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	free(path);
	if (fd < 0)
		return gl_err(GPG_ERR_KEYRING_OPEN);
	while (written < sizeof(header)) {
		ssize_t n = write(fd, header + written, sizeof(header) - written);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			close(fd);
			return gl_err(GPG_ERR_KEYRING_OPEN);
		}
		written += (size_t)n;
	}
	written = 0;
	while (written < private_key->packets_len) {
		ssize_t n = write(fd, private_key->packets + written,
				  private_key->packets_len - written);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			close(fd);
			return gl_err(GPG_ERR_KEYRING_OPEN);
		}
		written += (size_t)n;
	}
	if (fsync(fd) < 0) {
		close(fd);
		return gl_err(GPG_ERR_KEYRING_OPEN);
	}
	close(fd);
	path = pubring_path(ctx);
	if (!path)
		return gl_err(GPG_ERR_ENOMEM);
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	free(path);
	if (fd < 0)
		return gl_err(GPG_ERR_KEYRING_OPEN);
	written = 0;
	while (written < private_key->packets_len) {
		ssize_t n = write(fd, private_key->packets + written,
				  private_key->packets_len - written);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			close(fd);
			return gl_err(GPG_ERR_KEYRING_OPEN);
		}
		written += (size_t)n;
	}
	if (fsync(fd) < 0) {
		close(fd);
		return gl_err(GPG_ERR_KEYRING_OPEN);
	}
	close(fd);
	return 0;
}

static int append_import_packet(CBB *stream, struct gl_packet packet)
{
	size_t length = CBS_len(&packet.body);
	uint32_t adjusted;

	/* RFC 9580 section 4.2.2: canonicalize imported packets as new format. */
	if (length < 192) {
		if (!CBB_add_u8(stream, (uint8_t)(0xc0 | packet.tag)) ||
		    !CBB_add_u8(stream, (uint8_t)length))
			return 0;
	} else if (length <= 8383) {
		adjusted = (uint32_t)length - 192;
		if (!CBB_add_u8(stream, (uint8_t)(0xc0 | packet.tag)) ||
		    !CBB_add_u8(stream, (uint8_t)((adjusted >> 8) + 192)) ||
		    !CBB_add_u8(stream, (uint8_t)adjusted))
			return 0;
	} else if (length <= UINT32_MAX) {
		if (!CBB_add_u8(stream, (uint8_t)(0xc0 | packet.tag)) ||
		    !CBB_add_u8(stream, 255) ||
		    !CBB_add_u32(stream, (uint32_t)length))
			return 0;
	} else {
		return 0;
	}
	return CBB_add_bytes(stream, CBS_data(&packet.body), length);
}

static gpgme_error_t push_parsed_key(gpgme_key_t **keys, size_t *count,
				     unsigned char *encoded, size_t encoded_len)
{
	gpgme_key_t key = NULL;
	gpgme_key_t *larger;

	gpgme_error_t error = gl_parse_key(encoded, encoded_len, &key);

	if (error)
		return error;
	larger = realloc(*keys, (*count + 1) * sizeof(**keys));
	if (!larger) {
		gl_free_key(key);
		return gl_err(GPG_ERR_ENOMEM);
	}
	*keys = larger;
	(*keys)[(*count)++] = key;
	return 0;
}

gpgme_error_t gpgme_op_import(gpgme_ctx_t ctx, gpgme_data_t input)
{
	unsigned char *bytes = NULL;
	unsigned char *decoded = NULL;
	gpgme_key_t *parsed = NULL;
	size_t parsed_count = 0;
	size_t len = 0;
	size_t decoded_len = 0;
	CBS packets;
	struct gl_packet packet;
	CBB stream;
	unsigned char *encoded = NULL;
	size_t encoded_len = 0;
	gpgme_import_result_t result = NULL;
	gpgme_import_status_t *last_status;
	size_t packet_count = 0;
	size_t i;
	gpgme_error_t error = 0;

	if (!ctx || !input)
		return gl_err(GPG_ERR_INV_VALUE);
	gl_free_import_result(ctx->ir);
	ctx->ir = NULL;
	if (!gl_read_all(input, &bytes, &len))
		return gl_err(GPG_ERR_BAD_DATA);
	if (gl_decode_armor(bytes, len, &decoded, &decoded_len)) {
		free(bytes);
		bytes = decoded;
		len = decoded_len;
	} else if (len >= 10 && memcmp(bytes, "-----BEGIN", 10) == 0) {
		free(bytes);
		return gl_err(GPG_ERR_INV_ARMOR);
	}
	CBS_init(&packets, bytes, len);
	if (!CBB_init(&stream, 1024)) {
		free(bytes);
		return gl_err(GPG_ERR_ENOMEM);
	}
	while (CBS_len(&packets)) {
		if (++packet_count > GL_MAX_PACKETS ||
		    !gl_next_packet(&packets, &packet)) {
			error = gl_err(GPG_ERR_BAD_DATA);
			goto out;
		}
		if (packet.tag == 6 && CBB_len(&stream) != 0) {
			if (!CBB_finish(&stream, &encoded, &encoded_len)) {
				error = gl_err(GPG_ERR_ENOMEM);
				goto out;
			}
			error = push_parsed_key(&parsed, &parsed_count, encoded,
					encoded_len);
			if (error) {
				OPENSSL_free(encoded);
				encoded = NULL;
				goto out;
			}
			OPENSSL_free(encoded);
			encoded = NULL;
			if (!CBB_init(&stream, 1024)) {
				error = gl_err(GPG_ERR_ENOMEM);
				goto out;
			}
		}
		if (!append_import_packet(&stream, packet)) {
			error = gl_err(GPG_ERR_BAD_DATA);
			goto out;
		}
	}
	if (CBB_len(&stream) == 0) {
		error = gl_err(GPG_ERR_BAD_DATA);
		goto out;
	}
	if (!CBB_finish(&stream, &encoded, &encoded_len)) {
		error = gl_err(GPG_ERR_ENOMEM);
		goto out;
	}
	error = push_parsed_key(&parsed, &parsed_count, encoded, encoded_len);
	if (error)
		goto out;
	OPENSSL_free(encoded);
	encoded = NULL;
	result = calloc(1, sizeof(*result));
	if (!result) {
		error = gl_err(GPG_ERR_ENOMEM);
		goto out;
	}
	last_status = &result->imports;
	for (i = 0; i < parsed_count; i++) {
		gpgme_import_status_t status = calloc(1, sizeof(*status));
		int already_present = 0;
		size_t j;

		if (!status) {
			error = gl_err(GPG_ERR_ENOMEM);
			goto out;
		}
		status->fpr = gl_strdup(parsed[i]->fpr);
		if (!status->fpr) {
			free(status);
			error = gl_err(GPG_ERR_ENOMEM);
			goto out;
		}
		for (j = 0; j < ctx->key_count; j++) {
			if (strcmp(ctx->keys[j]->fpr, parsed[i]->fpr) == 0) {
				already_present = 1;
				break;
			}
		}
		status->result = 0;
		status->status = already_present ? 0 : GPGME_IMPORT_NEW;
		*last_status = status;
		last_status = &status->next;
		result->considered++;
		if (already_present) {
			result->unchanged++;
			gl_free_key(parsed[i]);
			parsed[i] = NULL;
			continue;
		}
		if (!add_key(ctx, parsed[i])) {
			error = gl_err(GPG_ERR_ENOMEM);
			goto out;
		}
		parsed[i] = NULL;
		result->imported++;
		if (((struct gl_key *)ctx->keys[ctx->key_count - 1])->ed25519 == 0)
			result->imported_rsa++;
		error = gl_save_keyring(ctx, ctx->keys[ctx->key_count - 1]);
		if (error)
			goto out;
	}
	ctx->ir = result;
	result = NULL;

out:
	if (encoded)
		OPENSSL_free(encoded);
	CBB_cleanup(&stream);
	free(bytes);
	if (parsed) {
		for (i = 0; i < parsed_count; i++)
			gl_free_key(parsed[i]);
		free(parsed);
	}
	gl_free_import_result(result);
	return error;
}

gpgme_import_result_t gpgme_op_import_result(gpgme_ctx_t ctx)
{
	return ctx ? ctx->ir : NULL;
}

gpgme_error_t gpgme_op_export_keys(gpgme_ctx_t ctx, gpgme_key_t keys[],
				   gpgme_export_mode_t mode, gpgme_data_t output)
{
	size_t i;

	(void)mode;
	if (!ctx || !keys || !output)
		return gl_err(GPG_ERR_INV_VALUE);
	for (i = 0; keys[i]; i++) {
		gpgme_error_t error = gl_export_key(output, keys[i]);

		if (error)
			return error;
	}
	return 0;
}

gpgme_error_t gpgme_op_keylist_start(gpgme_ctx_t ctx, const char *pattern,
				     int secret_only)
{
	if (!ctx || pattern || secret_only)
		return gl_err(GPG_ERR_INV_VALUE);
	ctx->cursor = 0;
	return 0;
}

gpgme_error_t gpgme_op_keylist_next(gpgme_ctx_t ctx, gpgme_key_t *output)
{
	if (!ctx || !output)
		return gl_err(GPG_ERR_INV_VALUE);
	*output = NULL;
	if (ctx->cursor >= ctx->key_count)
		return gl_err(GPG_ERR_EOF);
	*output = ctx->keys[ctx->cursor++];
	gpgme_key_ref(*output);
	return 0;
}

gpgme_error_t gpgme_get_key(gpgme_ctx_t ctx, const char *pattern,
			    gpgme_key_t *output, int secret)
{
	gpgme_key_t match = NULL;
	size_t pattern_len;
	size_t i;
	size_t matches = 0;

	if (output)
		*output = NULL;
	if (!ctx || !pattern || !output || secret)
		return gl_err(GPG_ERR_INV_VALUE);
	pattern_len = strlen(pattern);
	if (pattern_len < 8 || pattern_len > 40)
		return gl_err(GPG_ERR_INV_VALUE);
	for (i = 0; i < ctx->key_count; i++) {
		gpgme_subkey_t subkey;

		for (subkey = ctx->keys[i]->subkeys; subkey; subkey = subkey->next) {
			size_t fpr_len = subkey->fpr ? strlen(subkey->fpr) : 0;

			if (fpr_len >= pattern_len &&
			    strncasecmp(subkey->fpr + fpr_len - pattern_len,
					pattern, pattern_len) == 0) {
				match = ctx->keys[i];
				matches++;
				break;
			}
		}
	}
	if (matches == 0)
		return gl_err(GPG_ERR_EOF);
	if (matches > 1)
		return gl_err(GPG_ERR_AMBIGUOUS_NAME);
	gpgme_key_ref(match);
	*output = match;
	return 0;
}
