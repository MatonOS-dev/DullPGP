/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef GPGME_LITE_INTERNAL_H
#define GPGME_LITE_INTERNAL_H

#define _FILE_OFFSET_BITS 64
#include "gpgme.h"
#include <openssl/base.h>
#ifdef GL_BORINGSSL_PREFIXED
#include <boringssl_prefix_symbols.h>
#endif
#include <openssl/bytestring.h>
#include <stddef.h>
#include <stdint.h>

#define GL_MAX_OBJECT (64u * 1024u * 1024u)
#define GL_MAX_PACKET (4u * 1024u * 1024u)
#define GL_MAX_PACKETS 4096

struct gpgme_data {
	unsigned char *buf;
	size_t len;
	size_t cap;
	size_t pos;
	int owned;
	int fd;
	struct gpgme_data_cbs cbs;
	void *handle;
};

struct gl_signer {
	struct gl_signer *next;
	char *fpr;
	unsigned char *body;
	size_t body_len;
	uint32_t expires_at;
	uint8_t algorithm;
	int ed25519;
	int revoked;
	unsigned char public_key[32];
	struct gl_signer *signers;
	struct gl_signer **last_signer;
};

struct gl_key {
	struct _gpgme_key pub;
	unsigned char *packets;
	size_t packets_len;
	unsigned char *primary_body;
	size_t primary_len;
	unsigned char *signing_body;
	size_t signing_len;
	unsigned char *sig_body;
	size_t sig_len;
	char *signing_fpr;
	char *pending_subkey_fpr;
	unsigned char *pending_subkey_body;
	size_t pending_subkey_len;
	uint32_t pending_subkey_created;
	uint8_t pending_subkey_algorithm;
	int pending_subkey_ed25519;
	int pending_subkey_revoked;
	unsigned char pending_subkey_public_key[32];
	uint8_t key_algorithm;
	uint8_t sig_algorithm;
	uint32_t created;
	uint32_t expires_at;
	uint32_t signing_expires_at;
	uint32_t key_expire_seconds;
	int ed25519;
	int signing_subkey;
	int signing_revoked;
	unsigned char public_key[32];
	struct gl_signer *signers;
	struct gl_signer **last_signer;
};

struct gpgme_context {
	int armor;
	gpgme_protocol_t protocol;
	char *home;
	struct _gpgme_engine_info engine;
	gpgme_import_result_t ir;
	gpgme_verify_result_t vr;
	gpgme_key_t *keys;
	size_t key_count;
	size_t cursor;
};

struct gl_packet {
	uint8_t tag;
	CBS body;
	const uint8_t *encoded;
	size_t encoded_len;
};

int gl_read_all(gpgme_data_t data, unsigned char **out, size_t *out_len);
int gl_decode_armor(const unsigned char *in, size_t in_len,
		    unsigned char **out, size_t *out_len);
int gl_next_packet(CBS *input, struct gl_packet *packet);
gpgme_error_t gl_parse_key(const unsigned char *data, size_t len,
			   gpgme_key_t *out);
void gl_free_key(gpgme_key_t key);
gpgme_error_t gl_load_keyring(gpgme_ctx_t ctx);
gpgme_error_t gl_reload_keyring(gpgme_ctx_t ctx);
gpgme_error_t gl_save_keyring(gpgme_ctx_t ctx, gpgme_key_t key);
gpgme_error_t gl_verify_signature(gpgme_ctx_t ctx, const unsigned char *sig,
				   size_t sig_len, const unsigned char *data,
				   size_t data_len, gpgme_signature_t result);
gpgme_error_t gl_export_key(gpgme_data_t out, gpgme_key_t key);
void gl_free_import_result(gpgme_import_result_t result);
void gl_free_verify_result(gpgme_verify_result_t result);
gpgme_error_t gl_err(gpg_err_code_t code);
char *gl_strdup(const char *s);

#endif
