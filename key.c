/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/curve25519.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <time.h>

static char *hex_string(const unsigned char *bytes, size_t len)
{
	static const char hex[] = "0123456789ABCDEF";
	char *text = malloc(len * 2 + 1);
	size_t i;

	if (!text)
		return NULL;
	for (i = 0; i < len; i++) {
		text[i * 2] = hex[bytes[i] >> 4];
		text[i * 2 + 1] = hex[bytes[i] & 15];
	}
	text[len * 2] = '\0';
	return text;
}


static char *fingerprint_v4(CBS body)
{
	unsigned char fingerprint[SHA_DIGEST_LENGTH];
	CBB cbb;
	uint8_t *encoded = NULL;
	size_t encoded_len = 0;
	char *text;

	if (CBS_len(&body) > UINT16_MAX || !CBB_init(&cbb, CBS_len(&body) + 3) ||
	    !CBB_add_u8(&cbb, 0x99) ||
	    !CBB_add_u16(&cbb, (uint16_t)CBS_len(&body)) ||
	    !CBB_add_bytes(&cbb, CBS_data(&body), CBS_len(&body)) ||
	    !CBB_finish(&cbb, &encoded, &encoded_len)) {
		CBB_cleanup(&cbb);
		return NULL;
	}
	SHA1(encoded, encoded_len, fingerprint);
	OPENSSL_free(encoded);
	text = hex_string(fingerprint, sizeof(fingerprint));
	return text;
}

static int signature_key_metadata(CBS body, uint8_t *sig_type,
				  uint8_t *key_flags, uint32_t *key_expire)
{
	uint8_t version;
	uint8_t public_algorithm;
	uint8_t hash_algorithm;
	uint16_t hashed_len;
	uint16_t unhashed_len;
	CBS hashed;
	CBS unhashed;
	CBS prefix;
	CBS *sets[2];
	size_t i;

	/* RFC 9580 section 5.2.3: key signatures use the v4 signature format. */
	if (!CBS_get_u8(&body, &version) || version != 4 ||
	    !CBS_get_u8(&body, sig_type) ||
	    !CBS_get_u8(&body, &public_algorithm) ||
	    !CBS_get_u8(&body, &hash_algorithm) ||
	    !CBS_get_u16(&body, &hashed_len) ||
	    !CBS_get_bytes(&body, &hashed, hashed_len) ||
	    !CBS_get_u16(&body, &unhashed_len) ||
	    !CBS_get_bytes(&body, &unhashed, unhashed_len) ||
	    !CBS_get_bytes(&body, &prefix, 2))
		return 0;
	sets[0] = &hashed;
	sets[1] = &unhashed;
	for (i = 0; i < 2; i++) {
		CBS *set = sets[i];
		int is_hashed = i == 0;

		while (CBS_len(set)) {
			uint32_t length;
			uint8_t first;
			uint8_t raw_type;
			uint8_t type;
			CBS item;

			if (!CBS_get_u8(set, &first))
				return 0;
			if (first < 192) {
				length = first;
			} else if (first < 255) {
				uint8_t second;

				if (!CBS_get_u8(set, &second))
					return 0;
				length = ((uint32_t)(first - 192) << 8) + second + 192;
			} else if (!CBS_get_u32(set, &length)) {
				return 0;
			}
			if (length == 0 || !CBS_get_u8(set, &raw_type) ||
			    !CBS_get_bytes(set, &item, length - 1))
				return 0;
			type = raw_type & 0x7f;
			if (is_hashed && type == 9 && CBS_len(&item) == 4)
				CBS_get_u32(&item, key_expire);
			else if (is_hashed && type == 27 && CBS_len(&item))
				CBS_get_u8(&item, key_flags);
			else if ((type == 2 || type == 3 || type == 11 || type == 16 ||
				  type == 21 || type == 22 || type == 23 || type == 25 ||
				  type == 30 || type == 32 || type == 33 || type == 34))
				continue;
			else if (type != 9 && type != 27 && (raw_type & 0x80))
				return 0;
		}
	}
	(void)public_algorithm;
	(void)hash_algorithm;
	(void)prefix;
	return 1;
}

static int embedded_primary_binding(CBS signature, CBS *embedded)
{
	uint8_t version, type, algorithm, hash_algorithm;
	uint16_t hashed_len, unhashed_len;
	CBS hashed;
	CBS unhashed;
	CBS *sets[2];
	size_t i;

	if (!CBS_get_u8(&signature, &version) || version != 4 ||
	    !CBS_get_u8(&signature, &type) || type != 0x18 ||
	    !CBS_get_u8(&signature, &algorithm) ||
	    !CBS_get_u8(&signature, &hash_algorithm) ||
	    !CBS_get_u16(&signature, &hashed_len) ||
	    !CBS_get_bytes(&signature, &hashed, hashed_len) ||
	    !CBS_get_u16(&signature, &unhashed_len) ||
	    !CBS_get_bytes(&signature, &unhashed, unhashed_len))
		return 0;
	sets[0] = &hashed;
	sets[1] = &unhashed;
	for (i = 0; i < 2; i++) {
		CBS *set = sets[i];
		while (CBS_len(set)) {
		uint32_t length;
		uint8_t first, raw_type;
		CBS item;

		if (!CBS_get_u8(set, &first))
			return 0;
		if (first < 192)
			length = first;
		else if (first < 255) {
			uint8_t second;
			if (!CBS_get_u8(set, &second))
				return 0;
			length = ((uint32_t)(first - 192) << 8) + second + 192;
		} else if (!CBS_get_u32(set, &length))
			return 0;
		if (length == 0 || !CBS_get_u8(set, &raw_type) ||
		    !CBS_get_bytes(set, &item, length - 1))
			return 0;
		if ((raw_type & 0x7f) == 32) {
			*embedded = item;
			return 1;
		}
		}
	}
	(void)algorithm;
	(void)hash_algorithm;
	return 0;
}

static const EVP_MD *key_digest(uint8_t algorithm)
{
	switch (algorithm) {
	case 8:
		return EVP_sha256();
	case 9:
		return EVP_sha384();
	case 10:
		return EVP_sha512();
	default:
		return NULL;
	}
}

static int add_key_frame(CBB *data, CBS body)
{
	/* RFC 9580 section 5.2.4: v4 signed keys use the 0x99 framing prefix. */
	return CBS_len(&body) <= UINT16_MAX && CBB_add_u8(data, 0x99) &&
	       CBB_add_u16(data, (uint16_t)CBS_len(&body)) &&
	       CBB_add_bytes(data, CBS_data(&body), CBS_len(&body));
}

static int verify_key_signature(struct gl_key *key, CBS signature,
				const unsigned char *uid, size_t uid_len,
				const unsigned char *subkey, size_t subkey_len,
				const unsigned char *signer, size_t signer_len,
				uint8_t signer_algorithm, int signer_ed25519,
				const unsigned char signer_public_key[32])
{
	uint8_t version;
	uint8_t sig_type;
	uint8_t public_algorithm;
	uint8_t hash_algorithm;
	uint16_t hashed_len;
	uint16_t unhashed_len;
	CBS hashed;
	CBS unhashed;
	CBS hash_prefix;
	CBS signature_mpis;
	CBS primary;
	CBS subkey_body;
	CBS uid_body;
	CBB signed_data;
	CBB signature_header;
	CBB trailer;
	uint8_t *signed_bytes = NULL;
	uint8_t *header_bytes = NULL;
	uint8_t *trailer_bytes = NULL;
	size_t signed_len = 0;
	size_t header_len = 0;
	size_t trailer_len = 0;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	const EVP_MD *md;
	EVP_MD_CTX *digest_context = NULL;
	int valid = 0;

	if (!CBS_get_u8(&signature, &version) || version != 4 ||
	    !CBS_get_u8(&signature, &sig_type) ||
	    !CBS_get_u8(&signature, &public_algorithm) ||
	    !CBS_get_u8(&signature, &hash_algorithm) ||
	    !CBS_get_u16(&signature, &hashed_len) ||
	    !CBS_get_bytes(&signature, &hashed, hashed_len) ||
	    !CBS_get_u16(&signature, &unhashed_len) ||
	    !CBS_get_bytes(&signature, &unhashed, unhashed_len) ||
	    !CBS_get_bytes(&signature, &hash_prefix, 2))
		return 0;
	md = key_digest(hash_algorithm);
	if (!md || public_algorithm != (signer ? signer_algorithm :
						key->key_algorithm) ||
	    (public_algorithm != 1 && public_algorithm != 3 &&
		    public_algorithm != 22))
		return 0;
	if (!CBS_get_bytes(&signature, &signature_mpis, CBS_len(&signature)))
		return 0;
	if (!CBB_init(&signed_data, 1024) ||
	    !CBB_init(&signature_header, (size_t)hashed_len + 6) ||
	    !CBB_init(&trailer, 6))
		goto done;
	CBS_init(&primary, key->primary_body, key->primary_len);
	if (!add_key_frame(&signed_data, primary))
		goto done;
	if (uid) {
		/* RFC 9580 section 5.2.4: user IDs use 0xb4 + four-byte length. */
		if (uid_len > UINT32_MAX || !CBB_add_u8(&signed_data, 0xb4) ||
		    !CBB_add_u32(&signed_data, (uint32_t)uid_len) ||
		    !CBB_add_bytes(&signed_data, uid, uid_len))
			goto done;
	}
	if (subkey) {
		/* RFC 9580 section 5.2.4: subkey bindings append a framed subkey. */
		CBS_init(&subkey_body, subkey, subkey_len);
		if (!add_key_frame(&signed_data, subkey_body))
			goto done;
	}
	if (!CBB_add_u8(&signature_header, version) ||
	    !CBB_add_u8(&signature_header, sig_type) ||
	    !CBB_add_u8(&signature_header, public_algorithm) ||
	    !CBB_add_u8(&signature_header, hash_algorithm) ||
	    !CBB_add_u16(&signature_header, hashed_len) ||
	    !CBB_add_bytes(&signature_header, CBS_data(&hashed), hashed_len) ||
	    !CBB_add_u8(&trailer, version) || !CBB_add_u8(&trailer, 0xff) ||
	    !CBB_add_u32(&trailer, (uint32_t)(hashed_len + 6)) ||
	    !CBB_finish(&signed_data, &signed_bytes, &signed_len) ||
	    !CBB_finish(&signature_header, &header_bytes, &header_len) ||
	    !CBB_finish(&trailer, &trailer_bytes, &trailer_len))
		goto done;
	digest_context = EVP_MD_CTX_new();
	if (!digest_context || !EVP_DigestInit_ex(digest_context, md, NULL) ||
	    !EVP_DigestUpdate(digest_context, signed_bytes, signed_len) ||
	    !EVP_DigestUpdate(digest_context, header_bytes, header_len) ||
	    !EVP_DigestUpdate(digest_context, trailer_bytes, trailer_len) ||
	    !EVP_DigestFinal_ex(digest_context, digest, &digest_len) ||
	    digest_len < 2 ||
	    CRYPTO_memcmp(CBS_data(&hash_prefix), digest, 2) != 0)
		goto done;
	if (public_algorithm == 22 &&
	    (signer ? signer_ed25519 : key->ed25519)) {
		uint16_t bits;
		CBS first;
		CBS second;
		BIGNUM *r = NULL;
		BIGNUM *s = NULL;
		unsigned char sig[64];

		if (!CBS_get_u16(&signature_mpis, &bits) ||
		    !CBS_get_bytes(&signature_mpis, &first, (bits + 7) / 8))
			goto done;
		r = BN_bin2bn(CBS_data(&first), (int)CBS_len(&first), NULL);
		if (!r || !CBS_get_u16(&signature_mpis, &bits) ||
		    !CBS_get_bytes(&signature_mpis, &second, (bits + 7) / 8) ||
		    CBS_len(&signature_mpis) != 0) {
			BN_free(r);
			goto done;
		}
		s = BN_bin2bn(CBS_data(&second), (int)CBS_len(&second), NULL);
		if (s && BN_bn2binpad(r, sig, 32) == 32 &&
		    BN_bn2binpad(s, sig + 32, 32) == 32)
			valid = ED25519_verify(digest, digest_len, sig,
					       signer ? signer_public_key : key->public_key);
		BN_free(r);
		BN_free(s);
	} else if (public_algorithm == 1 || public_algorithm == 3) {
		uint8_t key_version;
		uint32_t key_created;
		uint8_t key_algorithm;
		uint16_t bits;
		BIGNUM *n = NULL;
		BIGNUM *e = NULL;
		RSA *rsa = NULL;
		unsigned char *padded = NULL;
		CBS mpi;

		CBS_init(&primary, signer ? signer : key->primary_body,
			 signer ? signer_len : key->primary_len);
		if (!CBS_get_u8(&primary, &key_version) ||
		    !CBS_get_u32(&primary, &key_created) ||
		    !CBS_get_u8(&primary, &key_algorithm) ||
		    !CBS_get_u16(&primary, &bits) ||
		    !CBS_get_bytes(&primary, &mpi, (bits + 7) / 8))
			goto done;
		n = BN_bin2bn(CBS_data(&mpi), (int)CBS_len(&mpi), NULL);
		if (!n || !CBS_get_u16(&primary, &bits) ||
		    !CBS_get_bytes(&primary, &mpi, (bits + 7) / 8)) {
			BN_free(n);
			goto done;
		}
		e = BN_bin2bn(CBS_data(&mpi), (int)CBS_len(&mpi), NULL);
		if (!e || !CBS_get_u16(&signature_mpis, &bits) ||
		    !CBS_get_bytes(&signature_mpis, &mpi, (bits + 7) / 8) ||
		    CBS_len(&signature_mpis) != 0) {
			BN_free(n);
			BN_free(e);
			goto done;
		}
		rsa = RSA_new_public_key(n, e);
		if (rsa && CBS_len(&mpi) <= (size_t)RSA_size(rsa)) {
			padded = OPENSSL_malloc((size_t)RSA_size(rsa));
			if (padded) {
				memset(padded, 0, (size_t)RSA_size(rsa) - CBS_len(&mpi));
				memcpy(padded + RSA_size(rsa) - CBS_len(&mpi),
				       CBS_data(&mpi), CBS_len(&mpi));
				valid = RSA_verify(EVP_MD_type(md), digest, digest_len,
						   padded, (unsigned int)RSA_size(rsa),
						   rsa);
			}
		}
		OPENSSL_free(padded);
		RSA_free(rsa);
		BN_free(n);
		BN_free(e);
	}
	done:
	EVP_MD_CTX_free(digest_context);
	OPENSSL_free(signed_bytes);
	OPENSSL_free(header_bytes);
	OPENSSL_free(trailer_bytes);
	CBB_cleanup(&signed_data);
	CBB_cleanup(&signature_header);
	CBB_cleanup(&trailer);
	(void)unhashed;
	(void)uid_body;
	return valid;
}

static int parse_mpi(CBS *body, BIGNUM **value)
{
	uint16_t bits;
	CBS bytes;
	size_t length;

	if (!CBS_get_u16(body, &bits) || bits == 0)
		return 0;
	length = (bits + 7) / 8;
	if (length > 512 || !CBS_get_bytes(body, &bytes, length))
		return 0;
	*value = BN_bin2bn(CBS_data(&bytes), (int)CBS_len(&bytes), NULL);
	return *value != NULL && BN_num_bits(*value) == bits;
}

static int parse_public_key(struct gl_key *key, CBS body)
{
	uint8_t version;
	uint32_t created;
	uint8_t algorithm;

	/* RFC 9580 section 5.5.2.2: parse version 4 public-key packet fields. */
	if (!CBS_get_u8(&body, &version) || version != 4 ||
	    !CBS_get_u32(&body, &created) || !CBS_get_u8(&body, &algorithm))
		return 0;
	key->created = created;
	key->key_algorithm = algorithm;
	key->pub.protocol = GPGME_PROTOCOL_OpenPGP;
	key->pub._refs = 1;
	if (algorithm == 1 || algorithm == 2 || algorithm == 3) {
		BIGNUM *n = NULL;
		BIGNUM *e = NULL;

		/* RFC 9580 section 5.5.5.1: RSA public-key material is n and e MPIs. */
		if (!parse_mpi(&body, &n) || !parse_mpi(&body, &e) ||
		    CBS_len(&body) != 0 || BN_num_bits(n) < 2048 ||
		    BN_num_bits(n) > 4096) {
			BN_free(n);
			BN_free(e);
			return 0;
		}
		BN_free(n);
		BN_free(e);
		key->pub.can_encrypt = algorithm == 2;
		if (key->pub.subkeys)
			key->pub.subkeys->pubkey_algo = GPGME_PK_RSA;
	} else if (algorithm == 22) {
		uint8_t oid_len;
		CBS oid;
		BIGNUM *point = NULL;
		static const unsigned char ed25519_oid[] = {
			0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01
		};

		/* RFC 9580 section 5.5.5.5: accept legacy EdDSA only for Ed25519 OID. */
		if (!CBS_get_u8(&body, &oid_len) ||
		    !CBS_get_bytes(&body, &oid, oid_len) ||
		    CBS_len(&oid) != sizeof(ed25519_oid) ||
		    CRYPTO_memcmp(CBS_data(&oid), ed25519_oid, sizeof(ed25519_oid)) ||
		    !parse_mpi(&body, &point) || CBS_len(&body) != 0 ||
		    BN_num_bytes(point) > (int)sizeof(key->public_key) + 1) {
			BN_free(point);
			return 0;
		}
		{
			unsigned char point_bytes[33];
			int point_len = BN_bn2bin(point, point_bytes);

			if (point_len == 33 && point_bytes[0] == 0x40) {
				memcpy(key->public_key, point_bytes + 1, 32);
			} else if (point_len == 32) {
				memcpy(key->public_key, point_bytes, 32);
			} else {
				BN_free(point);
				return 0;
			}
		}
		BN_free(point);
		key->ed25519 = 1;
		if (key->pub.subkeys)
			key->pub.subkeys->pubkey_algo = GPGME_PK_EDDSA;
	} else {
		return 0;
	}
	return 1;
}

static int init_primary(struct gl_key *key, CBS body)
{
	gpgme_subkey_t subkey;
	CBS fields = body;
	uint8_t version;

	if (!CBS_get_u8(&fields, &version) || version != 4)
		return 0;
	key->pub.fpr = fingerprint_v4(body);
	if (!key->pub.fpr)
		return 0;
	subkey = calloc(1, sizeof(*subkey));
	if (!subkey)
		return 0;
	subkey->fpr = gl_strdup(key->pub.fpr);
	subkey->keyid = gl_strdup(key->pub.fpr + 24);
	if (!subkey->fpr || !subkey->keyid) {
		free(subkey->fpr);
		free(subkey->keyid);
		free(subkey);
		return 0;
	}
	key->pub.subkeys = subkey;
	key->pub._last_subkey = subkey;
	key->last_signer = &key->signers;
	return 1;
}

static char *copy_bytes(const unsigned char *bytes, size_t length)
{
	char *copy = malloc(length + 1);

	if (!copy)
		return NULL;
	memcpy(copy, bytes, length);
	copy[length] = '\0';
	return copy;
}

static int add_uid(struct gl_key *key, CBS body)
{
	gpgme_user_id_t uid;
	char *value;
	CBS scan = body;
	uint8_t byte;
	size_t length = CBS_len(&body);
	size_t position = 0;
	size_t left_angle = SIZE_MAX;
	size_t right_angle = SIZE_MAX;

	/* RFC 9580 section 5.11: a User ID packet contains UTF-8 text bytes. */
	if (length == 0 || length > 4096)
		return 0;
	value = malloc(length + 1);
	uid = calloc(1, sizeof(*uid));
	if (!value || !uid) {
		free(value);
		free(uid);
		return 0;
	}
	memcpy(value, CBS_data(&body), length);
	value[length] = '\0';
	uid->uid = value;
	uid->validity = GPGME_VALIDITY_UNKNOWN;
	while (CBS_get_u8(&scan, &byte)) {
		if (byte == '<')
			left_angle = position;
		if (byte == '>')
			right_angle = position;
		position++;
	}
	if (left_angle != SIZE_MAX && right_angle > left_angle) {
		CBS text = body;
		CBS name_part;
		CBS email_part;
		uint8_t delimiter;

		if (!CBS_get_bytes(&text, &name_part, left_angle) ||
		    !CBS_get_u8(&text, &delimiter) || delimiter != '<' ||
		    !CBS_get_bytes(&text, &email_part,
				   right_angle - left_angle - 1)) {
			free(uid->uid);
			free(uid);
			return 0;
		}
		uid->email = copy_bytes(CBS_data(&email_part), CBS_len(&email_part));
		uid->name = copy_bytes(CBS_data(&name_part), CBS_len(&name_part));
	} else {
		uid->name = gl_strdup(value);
	}
	if (!uid->name ||
	    (left_angle != SIZE_MAX && right_angle > left_angle && !uid->email)) {
		free(uid->uid);
		free(uid->name);
		free(uid->email);
		free(uid);
		return 0;
	}
	if (key->pub._last_uid)
		key->pub._last_uid->next = uid;
	else
		key->pub.uids = uid;
	key->pub._last_uid = uid;
	return 1;
}

static int save_packet(CBB *all, uint8_t tag, CBS body)
{
	CBB packet;

	if (!CBB_add_u8(all, (uint8_t)(0xc0 | tag)) ||
	    !CBB_add_u8(all, 255) || !CBB_add_u32(all, (uint32_t)CBS_len(&body)) ||
	    !CBB_add_bytes(all, CBS_data(&body), CBS_len(&body)))
		return 0;
	(void)packet;
	return 1;
}

gpgme_error_t gl_parse_key(const unsigned char *data, size_t len,
			   gpgme_key_t *out)
{
	CBS input;
	struct gl_packet packet;
	struct gl_key *key = NULL;
	CBB all;
	uint8_t *stored = NULL;
	size_t stored_len = 0;
	int have_primary = 0;
	int have_uid = 0;
	unsigned char *current_uid = NULL;
	size_t current_uid_len = 0;
	int self_signature_valid = 0;
	int packets = 0;

	*out = NULL;
	CBS_init(&input, data, len);
	key = calloc(1, sizeof(*key));
	if (!key)
		return gl_err(GPG_ERR_ENOMEM);
	if (!CBB_init(&all, len)) {
		free(key);
		return gl_err(GPG_ERR_ENOMEM);
	}
	while (CBS_len(&input) != 0 && packets++ < GL_MAX_PACKETS) {
		CBS body;
		int ok;

		if (!gl_next_packet(&input, &packet))
			goto malformed;
		body = packet.body;
		if (packet.tag == 6 || packet.tag == 14) {
			uint8_t version;
			CBS version_cbs = body;

			if (!CBS_get_u8(&version_cbs, &version))
				goto malformed;
			if (version == 6)
				goto unsupported;
		}
		ok = save_packet(&all, packet.tag, body);
		if (!ok)
			goto malformed;
		if (packet.tag == 6) {
			/* RFC 9580 section 5.5.1.1: only one primary key starts a block. */
			if (have_primary || !init_primary(key, body) ||
			    !parse_public_key(key, body))
				goto malformed;
			have_primary = 1;
			key->primary_body = malloc(CBS_len(&body));
			if (!key->primary_body)
				goto nomem;
			memcpy(key->primary_body, CBS_data(&body), CBS_len(&body));
			key->primary_len = CBS_len(&body);
		} else if (packet.tag == 13 && have_primary) {
			if (!add_uid(key, body))
				goto nomem;
			free(current_uid);
			current_uid = malloc(CBS_len(&body));
			if (!current_uid)
				goto nomem;
			memcpy(current_uid, CBS_data(&body), CBS_len(&body));
			current_uid_len = CBS_len(&body);
			have_uid = 1;
		} else if (packet.tag == 14 && have_primary) {
			struct gl_key temporary = {0};

			/* RFC 9580 section 5.5.1.2: retain candidate subkey public material. */
			if (!parse_public_key(&temporary, body))
				goto malformed;
			free(key->pending_subkey_body);
			free(key->pending_subkey_fpr);
			key->pending_subkey_body = malloc(CBS_len(&body));
			key->pending_subkey_fpr = fingerprint_v4(body);
			if (!key->pending_subkey_body || !key->pending_subkey_fpr)
				goto nomem;
			memcpy(key->pending_subkey_body, CBS_data(&body), CBS_len(&body));
			key->pending_subkey_len = CBS_len(&body);
			key->pending_subkey_created = temporary.created;
			key->pending_subkey_algorithm = temporary.key_algorithm;
			key->pending_subkey_ed25519 = temporary.ed25519;
			memcpy(key->pending_subkey_public_key, temporary.public_key,
			       sizeof(key->pending_subkey_public_key));
			key->pending_subkey_revoked = 0;
		} else if (packet.tag == 2 && have_primary) {
			uint8_t sig_type = 0;
			uint8_t key_flags = 0;
			uint32_t key_expire = 0;
			int valid_signature;
			int valid_embedded = 0;
			const char *revoked_fpr = key->pending_subkey_fpr;

			/* RFC 9580 sections 5.2.1.4-5.2.1.8, 5.2.1.11-5.2.1.13. */
			if (!signature_key_metadata(body, &sig_type, &key_flags,
						    &key_expire)) {
				goto malformed;
			}
			valid_signature = verify_key_signature(
				key, body,
				(sig_type >= 0x10 && sig_type <= 0x13) ? current_uid : NULL,
				(sig_type >= 0x10 && sig_type <= 0x13) ?
				current_uid_len : 0,
				(sig_type == 0x18 || sig_type == 0x28) ?
				key->pending_subkey_body : NULL,
				(sig_type == 0x18 || sig_type == 0x28) ?
				key->pending_subkey_len : 0,
				NULL, 0, key->key_algorithm, key->ed25519,
				key->public_key);
			if (sig_type == 0x28 && !valid_signature) {
				struct gl_signer *candidate;

				for (candidate = key->signers; candidate;
				     candidate = candidate->next) {
					valid_signature = verify_key_signature(
						key, body, NULL, 0, candidate->body,
						candidate->body_len, NULL, 0,
						key->key_algorithm, key->ed25519,
						key->public_key);
					if (valid_signature) {
						revoked_fpr = candidate->fpr;
						break;
					}
				}
			}
			if (valid_signature && sig_type == 0x18 &&
			    (key_flags & 0x02) && key->pending_subkey_body) {
				CBS embedded;

				if (embedded_primary_binding(body, &embedded))
					valid_embedded = verify_key_signature(
						key, embedded, NULL, 0,
						key->pending_subkey_body,
						key->pending_subkey_len,
						key->pending_subkey_body,
						key->pending_subkey_len,
						key->pending_subkey_algorithm,
						key->pending_subkey_ed25519,
						key->pending_subkey_public_key);
			}
			if (!valid_signature) {
				continue;
			}
			if (sig_type == 0x20) {
				key->pub.revoked = 1;
			} else if (sig_type == 0x28) {
				gpgme_subkey_t subkey;

				if (revoked_fpr && key->pending_subkey_fpr &&
				    strcmp(revoked_fpr, key->pending_subkey_fpr) == 0)
					key->pending_subkey_revoked = 1;

				for (subkey = key->pub.subkeys; subkey;
				     subkey = subkey->next) {
					if (subkey->fpr && revoked_fpr &&
					    strcmp(subkey->fpr, revoked_fpr) == 0)
						subkey->revoked = 1;
				}
				{
					struct gl_signer *signer;

					for (signer = key->signers; signer;
					     signer = signer->next) {
						if (revoked_fpr &&
						    strcmp(signer->fpr, revoked_fpr) == 0)
							signer->revoked = 1;
					}
				}
			} else if ((sig_type == 0x10 || sig_type == 0x11 ||
				    sig_type == 0x12 || sig_type == 0x13) &&
				   !key->signing_subkey) {
				self_signature_valid = 1;
				key->pub.subkeys->can_sign = (key_flags & 0x02) != 0;
				key->pub.subkeys->can_certify = (key_flags & 0x01) != 0;
				key->pub.subkeys->can_encrypt = (key_flags & 0x0c) != 0;
				key->pub.can_sign = key->pub.subkeys->can_sign;
				key->pub.can_certify = key->pub.subkeys->can_certify;
				key->pub.can_encrypt = key->pub.subkeys->can_encrypt;
				key->pub.has_sign = key->pub.can_sign;
				key->pub.has_certify = key->pub.can_certify;
				key->pub.has_encrypt = key->pub.can_encrypt;
				if (key_expire) {
					key->expires_at = key->created + key_expire;
					key->pub.subkeys->expires = key->expires_at;
				}
			} else if (sig_type == 0x18 && key->pending_subkey_body) {
				gpgme_subkey_t subkey = calloc(1, sizeof(*subkey));

				if (!subkey)
					goto nomem;
				subkey->fpr = gl_strdup(key->pending_subkey_fpr);
				subkey->keyid = gl_strdup(key->pending_subkey_fpr + 24);
				subkey->revoked = key->pending_subkey_revoked;
				subkey->can_sign = (key_flags & 0x02) != 0 && valid_embedded;
				subkey->can_encrypt = (key_flags & 0x0c) != 0;
				subkey->pubkey_algo = key->pending_subkey_algorithm == 22 ?
					GPGME_PK_EDDSA : GPGME_PK_RSA;
				subkey->timestamp = key->pending_subkey_created;
				if (key_expire) {
					subkey->expires =
						(unsigned long)key->pending_subkey_created + key_expire;
					subkey->expired = subkey->expires < (unsigned long)time(NULL);
				}
				if (!subkey->fpr || !subkey->keyid) {
					free(subkey->fpr);
					free(subkey->keyid);
					free(subkey);
					goto nomem;
				}
				key->pub._last_subkey->next = subkey;
				key->pub._last_subkey = subkey;
				key->pub.has_encrypt |= subkey->can_encrypt;
				key->pub.has_sign |= subkey->can_sign;
				if (subkey->can_sign) {
					struct gl_signer *signer = calloc(1, sizeof(*signer));

					if (!signer)
						goto nomem;
					signer->fpr = gl_strdup(key->pending_subkey_fpr);
					signer->body = malloc(key->pending_subkey_len);
					if (!signer->fpr || !signer->body) {
						free(signer->fpr);
						free(signer->body);
						free(signer);
						goto nomem;
					}
					memcpy(signer->body, key->pending_subkey_body,
					       key->pending_subkey_len);
					signer->body_len = key->pending_subkey_len;
					signer->algorithm = key->pending_subkey_algorithm;
					signer->ed25519 = key->pending_subkey_ed25519;
					signer->revoked = key->pending_subkey_revoked;
					signer->expires_at = (uint32_t)subkey->expires;
					memcpy(signer->public_key,
					       key->pending_subkey_public_key,
					       sizeof(signer->public_key));
					*key->last_signer = signer;
					key->last_signer = &signer->next;
					key->signing_expires_at = (uint32_t)subkey->expires;
				}
			}
		}
	}
	if (!have_primary || !have_uid || !self_signature_valid ||
	    packets >= GL_MAX_PACKETS)
		goto malformed;
	free(current_uid);
	if (!CBB_finish(&all, &stored, &stored_len))
		goto nomem;
	key->packets = stored;
	key->packets_len = stored_len;

	*out = &key->pub;
	return 0;

nomem:
	free(current_uid);
	CBB_cleanup(&all);
	gl_free_key(&key->pub);
	return gl_err(GPG_ERR_ENOMEM);
malformed:
	free(current_uid);
	CBB_cleanup(&all);
	gl_free_key(&key->pub);
	return gl_err(GPG_ERR_BAD_DATA);
unsupported:
	free(current_uid);
	CBB_cleanup(&all);
	gl_free_key(&key->pub);
	return gl_err(GPG_ERR_NOT_SUPPORTED);
}

void gl_free_key(gpgme_key_t public_key)
{
	struct gl_key *key = (struct gl_key *)public_key;
	gpgme_subkey_t subkey;
	gpgme_user_id_t uid;

	if (!key)
		return;
	subkey = key->pub.subkeys;
	while (subkey) {
		gpgme_subkey_t next = subkey->next;

		free(subkey->fpr);
		free(subkey->keyid);
		free(subkey);
		subkey = next;
	}
	uid = key->pub.uids;
	while (uid) {
		gpgme_user_id_t next = uid->next;

		free(uid->uid);
		free(uid->name);
		free(uid->email);
		free(uid->comment);
		free(uid);
		uid = next;
	}
	free(key->pub.fpr);
	OPENSSL_free(key->packets);
	free(key->primary_body);
	free(key->signing_body);
	free(key->sig_body);
	free(key->signing_fpr);
	free(key->pending_subkey_fpr);
	free(key->pending_subkey_body);
	while (key->signers) {
		struct gl_signer *next = key->signers->next;

		free(key->signers->fpr);
		free(key->signers->body);
		free(key->signers);
		key->signers = next;
	}
	free(key);
}

gpgme_error_t gl_export_key(gpgme_data_t out, gpgme_key_t public_key)
{
	struct gl_key *key = (struct gl_key *)public_key;

	if (!key || !out || !key->packets ||
	    gpgme_data_write(out, key->packets, key->packets_len) !=
	    (ssize_t)key->packets_len)
		return gl_err(GPG_ERR_INV_VALUE);
	return 0;
}
