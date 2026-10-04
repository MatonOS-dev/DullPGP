/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _FILE_OFFSET_BITS 64
#include "internal.h"
#undef gpgme_check_version
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct _gpgme_engine_info default_engine = {
	NULL,
	GPGME_PROTOCOL_OpenPGP,
	(char *)"gpgme-lite",
	(char *)"0.1",
	"2.0.1",
	NULL
};

gpgme_error_t gl_err(gpg_err_code_t code)
{
	return (gpgme_error_t)code;
}

char *gl_strdup(const char *value)
{
	char *copy;
	size_t length;

	if (!value)
		return NULL;
	length = strlen(value) + 1;
	copy = malloc(length);
	if (copy)
		memcpy(copy, value, length);
	return copy;
}

const char *gpgme_check_version(const char *required)
{
	(void)required;
	return "2.0.1";
}

const char *gpgme_check_version_internal(const char *required, size_t offset)
{
	(void)offset;
	return gpgme_check_version(required);
}

gpgme_error_t gpgme_set_locale(gpgme_ctx_t ctx, int category,
			       const char *value)
{
	(void)ctx;
	(void)category;
	(void)value;
	return 0;
}

static int mkdir_parents(const char *path)
{
	char *copy = gl_strdup(path);
	char *cursor;
	int result = 1;

	if (!copy)
		return 0;
	for (cursor = copy + 1; *cursor; cursor++) {
		if (*cursor != '/')
			continue;
		*cursor = '\0';
		if (mkdir(copy, 0700) < 0 && errno != EEXIST)
			result = 0;
		*cursor = '/';
		if (!result)
			break;
	}
	if (result && mkdir(copy, 0700) < 0 && errno != EEXIST)
		result = 0;
	free(copy);
	return result;
}

static void clear_context_keys(gpgme_ctx_t ctx)
{
	size_t i;

	for (i = 0; i < ctx->key_count; i++) {
		gpgme_key_unref(ctx->keys[i]);
	}
	free(ctx->keys);
	ctx->keys = NULL;
	ctx->key_count = 0;
	ctx->cursor = 0;
}

gpgme_error_t gpgme_new(gpgme_ctx_t *output)
{
	gpgme_ctx_t ctx;
	const char *home;
	char *path;
	gpgme_error_t error;

	if (!output)
		return gl_err(GPG_ERR_INV_VALUE);
	*output = NULL;
	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return gl_err(GPG_ERR_ENOMEM);
	ctx->protocol = GPGME_PROTOCOL_OpenPGP;
	ctx->engine = default_engine;
	home = getenv("HOME");
	if (home && *home) {
		static const char suffix[] = "/.local/share/gpgme-lite";
		size_t length = strlen(home) + sizeof(suffix);

		path = malloc(length);
		if (!path) {
			free(ctx);
			return gl_err(GPG_ERR_ENOMEM);
		}
		memcpy(path, home, strlen(home));
		memcpy(path + strlen(home), suffix, sizeof(suffix));
		ctx->home = path;
		ctx->engine.home_dir = ctx->home;
	}
	error = gl_load_keyring(ctx);
	if (error) {
		free(ctx->home);
		free(ctx);
		return error;
	}
	*output = ctx;
	return 0;
}

gpgme_engine_info_t gpgme_ctx_get_engine_info(gpgme_ctx_t ctx)
{
	return ctx ? &ctx->engine : NULL;
}

gpgme_error_t gpgme_get_engine_info(gpgme_engine_info_t *output)
{
	if (!output)
		return gl_err(GPG_ERR_INV_VALUE);
	*output = &default_engine;
	return 0;
}

gpgme_error_t gpgme_ctx_set_engine_info(gpgme_ctx_t ctx,
					gpgme_protocol_t protocol,
					const char *file_name,
					const char *home_dir)
{
	char *home_copy = NULL;
	char *file_copy = NULL;
	gpgme_error_t error;

	if (!ctx || protocol != GPGME_PROTOCOL_OpenPGP)
		return gl_err(GPG_ERR_INV_VALUE);
	if (home_dir) {
		home_copy = gl_strdup(home_dir);
		if (!home_copy)
			return gl_err(GPG_ERR_ENOMEM);
	} else {
		home_copy = gl_strdup(ctx->home);
		if (ctx->home && !home_copy)
			return gl_err(GPG_ERR_ENOMEM);
	}
	if (file_name) {
		file_copy = gl_strdup(file_name);
		if (!file_copy) {
			free(home_copy);
			return gl_err(GPG_ERR_ENOMEM);
		}
	}
	if (home_dir && (!ctx->home || strcmp(ctx->home, home_dir) != 0)) {
		clear_context_keys(ctx);
	}
	free(ctx->home);
	ctx->home = home_copy;
	ctx->engine.home_dir = ctx->home;
	ctx->engine.protocol = protocol;
	if (file_copy)
		ctx->engine.file_name = file_copy;
	ctx->protocol = protocol;
	if (ctx->home && !mkdir_parents(ctx->home))
		return gl_err(GPG_ERR_KEYRING_OPEN);
	error = gl_load_keyring(ctx);
	if (error)
		clear_context_keys(ctx);
	return error;
}

void gpgme_set_armor(gpgme_ctx_t ctx, int armor)
{
	if (ctx)
		ctx->armor = !!armor;
}

int gpgme_get_armor(gpgme_ctx_t ctx)
{
	return ctx ? ctx->armor : 0;
}

static gpgme_error_t data_new(gpgme_data_t *output)
{
	gpgme_data_t data;

	if (!output)
		return gl_err(GPG_ERR_INV_VALUE);
	*output = NULL;
	data = calloc(1, sizeof(*data));
	if (!data)
		return gl_err(GPG_ERR_ENOMEM);
	data->fd = -1;
	data->owned = 1;
	*output = data;
	return 0;
}

gpgme_error_t gpgme_data_new(gpgme_data_t *output)
{
	return data_new(output);
}

gpgme_error_t gpgme_data_new_from_mem(gpgme_data_t *output,
				      const char *buffer, size_t size,
				      int copy)
{
	gpgme_error_t error;

	if ((!buffer && size) || size > GL_MAX_OBJECT)
		return gl_err(GPG_ERR_INV_VALUE);
	error = data_new(output);
	if (error)
		return error;
	if (copy && size) {
		(*output)->buf = malloc(size);
		if (!(*output)->buf) {
			free(*output);
			*output = NULL;
			return gl_err(GPG_ERR_ENOMEM);
		}
		memcpy((*output)->buf, buffer, size);
		(*output)->owned = 1;
	} else {
		(*output)->buf = (unsigned char *)buffer;
		(*output)->owned = 0;
	}
	(*output)->len = size;
	(*output)->cap = size;
	return 0;
}

static ssize_t fd_read(void *handle, void *buffer, size_t size)
{
	int fd = *(int *)handle;
	ssize_t count;

	do {
		count = read(fd, buffer, size);
	} while (count < 0 && errno == EINTR);
	return count;
}

static off_t fd_seek(void *handle, off_t offset, int whence)
{
	return lseek(*(int *)handle, offset, whence);
}

gpgme_error_t gpgme_data_new_from_fd(gpgme_data_t *output, int fd)
{
	gpgme_error_t error;

	if (fd < 0)
		return gl_err(GPG_ERR_INV_VALUE);
	error = data_new(output);
	if (error)
		return error;
	(*output)->fd = fd;
	(*output)->handle = &(*output)->fd;
	(*output)->cbs.read = fd_read;
	(*output)->cbs.seek = fd_seek;
	return 0;
}

gpgme_error_t gpgme_data_new_from_cbs(gpgme_data_t *output,
				      gpgme_data_cbs_t callbacks,
				      void *handle)
{
	gpgme_error_t error;

	if (!callbacks)
		return gl_err(GPG_ERR_INV_VALUE);
	error = data_new(output);
	if (error)
		return error;
	(*output)->cbs = *callbacks;
	(*output)->handle = handle;
	return 0;
}

static int reserve_data(gpgme_data_t data, size_t size)
{
	size_t needed;
	size_t capacity;
	unsigned char *larger;

	if (size > GL_MAX_OBJECT || data->pos > GL_MAX_OBJECT - size) {
		errno = EFBIG;
		return 0;
	}
	needed = data->pos + size;
	if (needed <= data->cap && data->owned)
		return 1;
	capacity = data->cap ? data->cap : 256;
	while (capacity < needed) {
		if (capacity > GL_MAX_OBJECT / 2) {
			capacity = GL_MAX_OBJECT;
			break;
		}
		capacity *= 2;
	}
	larger = malloc(capacity);
	if (!larger)
		return 0;
	if (data->len)
		memcpy(larger, data->buf, data->len);
	if (data->owned)
		free(data->buf);
	data->buf = larger;
	data->cap = capacity;
	data->owned = 1;
	return 1;
}

ssize_t gpgme_data_read(gpgme_data_t data, void *buffer, size_t size)
{
	if (!data || (!buffer && size)) {
		errno = EINVAL;
		return -1;
	}
	if (data->cbs.read)
		return data->cbs.read(data->handle, buffer, size);
	if (data->fd >= 0)
		return fd_read(&data->fd, buffer, size);
	if (data->pos >= data->len)
		return 0;
	if (size > data->len - data->pos)
		size = data->len - data->pos;
	if (size)
		memcpy(buffer, data->buf + data->pos, size);
	data->pos += size;
	return (ssize_t)size;
}

ssize_t gpgme_data_write(gpgme_data_t data, const void *buffer, size_t size)
{
	if (!data || (!buffer && size)) {
		errno = EINVAL;
		return -1;
	}
	if (data->cbs.write)
		return data->cbs.write(data->handle, buffer, size);
	if (data->fd >= 0) {
		errno = EBADF;
		return -1;
	}
	if (!reserve_data(data, size))
		return -1;
	if (data->pos > data->len)
		memset(data->buf + data->len, 0, data->pos - data->len);
	if (size)
		memcpy(data->buf + data->pos, buffer, size);
	data->pos += size;
	if (data->pos > data->len)
		data->len = data->pos;
	return (ssize_t)size;
}

off_t gpgme_data_seek(gpgme_data_t data, off_t offset, int whence)
{
	off_t base;
	off_t position;

	if (!data) {
		errno = EINVAL;
		return -1;
	}
	if (data->cbs.seek)
		return data->cbs.seek(data->handle, offset, whence);
	if (data->fd >= 0)
		return fd_seek(&data->fd, offset, whence);
	if (whence == SEEK_SET)
		base = 0;
	else if (whence == SEEK_CUR)
		base = (off_t)data->pos;
	else if (whence == SEEK_END)
		base = (off_t)data->len;
	else {
		errno = EINVAL;
		return -1;
	}
	if ((offset < 0 && offset < -base) ||
	    offset > (off_t)GL_MAX_OBJECT - base) {
		errno = EINVAL;
		return -1;
	}
	position = base + offset;
	data->pos = (size_t)position;
	return position;
}

void gpgme_data_release(gpgme_data_t data)
{
	if (!data)
		return;
	if (data->cbs.release)
		data->cbs.release(data->handle);
	if (data->owned)
		free(data->buf);
	free(data);
}

char *gpgme_data_release_and_get_mem(gpgme_data_t data, size_t *size)
{
	char *memory;

	if (!data || data->fd >= 0 || data->cbs.read || data->cbs.write)
		return NULL;
	if (!data->owned && data->len) {
		memory = malloc(data->len);
		if (!memory)
			return NULL;
		memcpy(memory, data->buf, data->len);
	} else {
		memory = (char *)data->buf;
	}
	if (size)
		*size = data->len;
	data->buf = NULL;
	data->owned = 0;
	gpgme_data_release(data);
	return memory;
}

void gpgme_free(void *memory)
{
	free(memory);
}

void gl_free_import_result(gpgme_import_result_t result)
{
	gpgme_import_status_t status;

	if (!result)
		return;
	status = result->imports;
	while (status) {
		gpgme_import_status_t next = status->next;

		free(status->fpr);
		free(status);
		status = next;
	}
	free(result);
}

void gl_free_verify_result(gpgme_verify_result_t result)
{
	gpgme_signature_t signature;

	if (!result)
		return;
	signature = result->signatures;
	while (signature) {
		gpgme_signature_t next = signature->next;

		free(signature->fpr);
		free(signature);
		signature = next;
	}
	free(result->file_name);
	free(result);
}

void gpgme_key_unref(gpgme_key_t key)
{
	if (!key)
		return;
	if (key->_refs > 1) {
		key->_refs--;
		return;
	}
	gl_free_key(key);
}

void gpgme_key_ref(gpgme_key_t key)
{
	if (key)
		key->_refs++;
}

void gpgme_key_release(gpgme_key_t key)
{
	gpgme_key_unref(key);
}

void gpgme_release(gpgme_ctx_t ctx)
{
	size_t i;

	if (!ctx)
		return;
	for (i = 0; i < ctx->key_count; i++)
		gpgme_key_unref(ctx->keys[i]);
	free(ctx->keys);
	free(ctx->home);
	gl_free_import_result(ctx->ir);
	gl_free_verify_result(ctx->vr);
	free(ctx);
}

gpgme_error_t gpgme_op_verify(gpgme_ctx_t ctx, gpgme_data_t signature_data,
			      gpgme_data_t signed_data,
			      gpgme_data_t plaintext)
{
	unsigned char *signature_bytes = NULL;
	unsigned char *signed_bytes = NULL;
	unsigned char *decoded = NULL;
	size_t signature_len = 0;
	size_t signed_len = 0;
	size_t decoded_len = 0;
	CBS packets;
	struct gl_packet packet;
	gpgme_signature_t record;
	gpgme_error_t error;

	(void)plaintext;
	if (!ctx || !signature_data || !signed_data)
		return gl_err(GPG_ERR_INV_VALUE);
	error = gl_reload_keyring(ctx);
	if (error)
		return error;
	gl_free_verify_result(ctx->vr);
	ctx->vr = NULL;
	if (!gl_read_all(signature_data, &signature_bytes, &signature_len) ||
	    !gl_read_all(signed_data, &signed_bytes, &signed_len)) {
		free(signature_bytes);
		free(signed_bytes);
		return gl_err(GPG_ERR_BAD_DATA);
	}
	if (gl_decode_armor(signature_bytes, signature_len, &decoded, &decoded_len)) {
		free(signature_bytes);
		signature_bytes = decoded;
		signature_len = decoded_len;
	}
	ctx->vr = calloc(1, sizeof(*ctx->vr));
	record = calloc(1, sizeof(*record));
	if (!ctx->vr || !record) {
		free(signature_bytes);
		free(signed_bytes);
		free(record);
		gl_free_verify_result(ctx->vr);
		ctx->vr = NULL;
		return gl_err(GPG_ERR_ENOMEM);
	}
	ctx->vr->signatures = record;
	CBS_init(&packets, signature_bytes, signature_len);
	if (!gl_next_packet(&packets, &packet) || packet.tag != 2 ||
	    CBS_len(&packets) != 0) {
		free(signature_bytes);
		free(signed_bytes);
		return gl_err(GPG_ERR_BAD_DATA);
	}
	error = gl_verify_signature(ctx, CBS_data(&packet.body),
				    CBS_len(&packet.body), signed_bytes,
				    signed_len, record);
	free(signature_bytes);
	free(signed_bytes);
	return error;
}

gpgme_verify_result_t gpgme_op_verify_result(gpgme_ctx_t ctx)
{
	return ctx ? ctx->vr : NULL;
}

void gpgme_result_ref(void *result)
{
	(void)result;
}

void gpgme_result_unref(void *result)
{
	(void)result;
}

gpgme_error_t gpgme_signers_add(gpgme_ctx_t ctx, const gpgme_key_t key)
{
	(void)ctx;
	(void)key;
	return gl_err(GPG_ERR_NOT_SUPPORTED);
}

gpgme_error_t gpgme_op_sign(gpgme_ctx_t ctx, gpgme_data_t plain,
			    gpgme_data_t signature, gpgme_sig_mode_t mode)
{
	(void)ctx;
	(void)plain;
	(void)signature;
	(void)mode;
	return gl_err(GPG_ERR_NOT_SUPPORTED);
}

const char *gpgme_pubkey_algo_name(gpgme_pubkey_algo_t algorithm)
{
	switch (algorithm) {
	case GPGME_PK_RSA:
	case GPGME_PK_RSA_E:
	case GPGME_PK_RSA_S:
		return "RSA";
	case GPGME_PK_EDDSA:
		return "EdDSA";
	default:
		return NULL;
	}
}

const char *gpgme_hash_algo_name(gpgme_hash_algo_t algorithm)
{
	switch (algorithm) {
	case GPGME_MD_SHA256:
		return "SHA256";
	case GPGME_MD_SHA384:
		return "SHA384";
	case GPGME_MD_SHA512:
		return "SHA512";
	default:
		return NULL;
	}
}

const char *gpgme_strerror(gpgme_error_t error)
{
	switch (gpgme_err_code(error)) {
	case GPG_ERR_NO_ERROR:
		return "Success";
	case GPG_ERR_EOF:
		return "End of file";
	case GPG_ERR_ENOMEM:
		return "Out of memory";
	case GPG_ERR_INV_VALUE:
		return "Invalid value";
	case GPG_ERR_BAD_DATA:
	case GPG_ERR_INV_PACKET:
		return "Invalid OpenPGP data";
	case GPG_ERR_BAD_SIGNATURE:
		return "Bad signature";
	case GPG_ERR_NO_PUBKEY:
		return "No public key";
	case GPG_ERR_CERT_REVOKED:
		return "Certificate revoked";
	case GPG_ERR_CERT_EXPIRED:
	case GPG_ERR_SIG_EXPIRED:
		return "Signature or key expired";
	case GPG_ERR_AMBIGUOUS_NAME:
		return "Ambiguous name";
	case GPG_ERR_NOT_SUPPORTED:
		return "Not supported";
	default:
		return "OpenPGP operation failed";
	}
}

int gpgme_strerror_r(gpg_error_t error, char *buffer, size_t size)
{
	const char *message = gpgme_strerror(error);
	size_t length;

	if (!buffer || size == 0)
		return ERANGE;
	length = strlen(message);
	if (length >= size) {
		memcpy(buffer, message, size - 1);
		buffer[size - 1] = '\0';
		return ERANGE;
	}
	memcpy(buffer, message, length + 1);
	return 0;
}

const char *gpgme_strsource(gpgme_error_t error)
{
	(void)error;
	return "gpgme-lite";
}

const char *gpg_strerror(gpg_error_t error)
{
	return gpgme_strerror(error);
}

int gpg_strerror_r(gpg_error_t error, char *buffer, size_t size)
{
	return gpgme_strerror_r(error, buffer, size);
}

const char *gpg_strsource(gpg_error_t error)
{
	(void)error;
	return "gpgme-lite";
}
