/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/curve25519.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const EVP_MD *digest_for(uint8_t algorithm)
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

static int skip_subpackets(CBS subpackets, uint32_t *created,
			   uint32_t *sig_expire, uint8_t *key_flags,
			   uint64_t *issuer, uint8_t *issuer_fpr,
			   int *has_issuer_fpr, int *has_created,
			   int hashed_values)
{
	while (CBS_len(&subpackets) != 0) {
		uint32_t length;
		uint8_t first;
		uint8_t raw_type;
		uint8_t type;
		CBS item;

		/* RFC 9580 section 5.2.3.7: lengths include the type octet. */
		if (!CBS_get_u8(&subpackets, &first))
			return 0;
		if (first < 192) {
			length = first;
		} else if (first < 255) {
			uint8_t second;

			if (!CBS_get_u8(&subpackets, &second))
				return 0;
			length = ((uint32_t)(first - 192) << 8) + second + 192;
		} else {
			if (!CBS_get_u32(&subpackets, &length))
				return 0;
		}
		if (length == 0 || !CBS_get_u8(&subpackets, &raw_type) ||
		    !CBS_get_bytes(&subpackets, &item, length - 1))
			return 0;
		type = raw_type & 0x7f;
		if (hashed_values && type == 2 && CBS_len(&item) == 4) {
			/* RFC 9580 section 5.2.3.11: creation time is hashed. */
			CBS_get_u32(&item, created);
			*has_created = 1;
		} else if (hashed_values && type == 3 && CBS_len(&item) == 4) {
			/* RFC 9580 section 5.2.3.18: signature expiry is hashed. */
			CBS_get_u32(&item, sig_expire);
		} else if (type == 16 && CBS_len(&item) == 8) {
			/* RFC 9580 section 5.2.3.12: issuer IDs are eight octets. */
			CBS_get_u64(&item, issuer);
		} else if (hashed_values && type == 27 && CBS_len(&item) > 0) {
			/* RFC 9580 section 5.2.3.29: key flags are an octet string. */
			CBS_get_u8(&item, key_flags);
		} else if (type == 33 && CBS_len(&item) == 21) {
			uint8_t key_version;
			CBS fingerprint;

			/* RFC 9580 section 5.2.3.35: v4 fingerprints are 20 octets. */
			if (!CBS_get_u8(&item, &key_version) || key_version != 4 ||
			    !CBS_get_bytes(&item, &fingerprint, 20))
				return 0;
			if (!*has_issuer_fpr || hashed_values) {
				memcpy(issuer_fpr, CBS_data(&fingerprint), 20);
				*has_issuer_fpr = 1;
			}
		} else if ((raw_type & 0x80) != 0) {
			/* RFC 9580 section 5.2.3.9: reject unknown critical subpackets. */
			return 0;
		}
	}
	return 1;
}

static int signature_digest(uint8_t hash_algorithm, CBS signed_data,
			    CBS signature_header, unsigned char *digest,
			    unsigned int *digest_len)
{
	const EVP_MD *md = digest_for(hash_algorithm);
	EVP_MD_CTX *ctx;
	CBB suffix;
	uint8_t *trailer = NULL;
	size_t trailer_len = 0;
	int ok;

	if (!md)
		return 0;
	if (!CBB_init(&suffix, 6) || !CBB_add_u8(&suffix, 4) ||
	    !CBB_add_u8(&suffix, 0xff) ||
	    !CBB_add_u32(&suffix, (uint32_t)CBS_len(&signature_header)) ||
	    !CBB_finish(&suffix, &trailer, &trailer_len)) {
		CBB_cleanup(&suffix);
		return 0;
	}
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		OPENSSL_free(trailer);
		return 0;
	}
	ok = EVP_DigestInit_ex(ctx, md, NULL) &&
	     EVP_DigestUpdate(ctx, CBS_data(&signed_data), CBS_len(&signed_data)) &&
	     EVP_DigestUpdate(ctx, CBS_data(&signature_header),
			      CBS_len(&signature_header)) &&
	     EVP_DigestUpdate(ctx, trailer, trailer_len) &&
	     EVP_DigestFinal_ex(ctx, digest, digest_len);
	EVP_MD_CTX_free(ctx);
	OPENSSL_free(trailer);
	return ok;
}

static int rsa_verify(struct gl_key *key, CBS signature, const EVP_MD *md,
		      const unsigned char *digest, unsigned int digest_len,
		      uint8_t *sig_data, size_t sig_len)
{
	CBS public_body;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	BIGNUM *sig = NULL;
	RSA *rsa = NULL;
	uint8_t version;
	uint32_t created;
	uint8_t algorithm;
	uint16_t bits;
	CBS bytes;
	CBS sig_bytes;
	unsigned char *padded = NULL;
	int ok = 0;

	public_body = (CBS){0};
	CBS_init(&public_body, key->signing_body ? key->signing_body :
		 key->primary_body, key->signing_body ? key->signing_len :
		 key->primary_len);
	if (!CBS_get_u8(&public_body, &version) ||
	    !CBS_get_u32(&public_body, &created) ||
	    !CBS_get_u8(&public_body, &algorithm) ||
	    !CBS_get_u16(&public_body, &bits) ||
	    !CBS_get_bytes(&public_body, &bytes, (bits + 7) / 8))
		goto done;
	n = BN_bin2bn(CBS_data(&bytes), (int)CBS_len(&bytes), NULL);
	if (!n || !CBS_get_u16(&public_body, &bits) ||
	    !CBS_get_bytes(&public_body, &bytes, (bits + 7) / 8))
		goto done;
	e = BN_bin2bn(CBS_data(&bytes), (int)CBS_len(&bytes), NULL);
	if (!e || !CBS_get_u16(&signature, &bits) ||
	    !CBS_get_bytes(&signature, &bytes, (bits + 7) / 8))
		goto done;
	sig = BN_bin2bn(CBS_data(&bytes), (int)CBS_len(&bytes), NULL);
	if (!sig || CBS_len(&signature) != 0)
		goto done;
	CBS_init(&sig_bytes, sig_data, sig_len);
	rsa = RSA_new_public_key(n, e);
	if (!rsa)
		goto done;
	if (sig_len > (size_t)RSA_size(rsa))
		goto done;
	padded = OPENSSL_malloc((size_t)RSA_size(rsa));
	if (!padded)
		goto done;
	memset(padded, 0, (size_t)RSA_size(rsa) - sig_len);
	memcpy(padded + RSA_size(rsa) - sig_len, sig_data, sig_len);
	/* RFC 9580 section 5.2.4: MPI signatures need RSA-width left padding. */
	ok = RSA_verify(EVP_MD_type(md), digest, digest_len,
			padded, (unsigned int)RSA_size(rsa), rsa);
	done:
	OPENSSL_free(padded);
	RSA_free(rsa);
	BN_free(n);
	BN_free(e);
	BN_free(sig);
	return ok;
}

static int fpr_matches(const char *fingerprint,
		       const unsigned char expected[20])
{
	unsigned char actual[20];
	size_t i;

	if (!fingerprint || strlen(fingerprint) != 40)
		return 0;
	for (i = 0; i < sizeof(actual); i++) {
		unsigned int byte;

		if (sscanf(fingerprint + i * 2, "%2x", &byte) != 1)
			return 0;
		actual[i] = (unsigned char)byte;
	}
	return CRYPTO_memcmp(actual, expected, sizeof(actual)) == 0;
}

static int keyid_matches(const char *fingerprint, uint64_t issuer)
{
	unsigned char actual[8];
	size_t i;

	if (!fingerprint || strlen(fingerprint) != 40 || issuer == 0)
		return 0;
	for (i = 0; i < sizeof(actual); i++) {
		unsigned int byte;

		if (sscanf(fingerprint + 24 + i * 2, "%2x", &byte) != 1)
			return 0;
		actual[i] = (unsigned char)byte;
	}
	for (i = 0; i < sizeof(actual); i++) {
		if (actual[i] != (unsigned char)(issuer >> ((7 - i) * 8)))
			return 0;
	}
	return 1;
}

static char *issuer_string(const unsigned char fingerprint[20], int has_fpr,
			   uint64_t issuer)
{
	static const char hex[] = "0123456789abcdef";
	size_t bytes = has_fpr ? 20 : 8;
	char *text;
	size_t i;

	if (!has_fpr && issuer == 0)
		return gl_strdup("");
	text = malloc(bytes * 2 + 1);
	if (!text)
		return NULL;
	for (i = 0; i < bytes; i++) {
		unsigned char value = has_fpr ? fingerprint[i] :
			(unsigned char)(issuer >> ((bytes - i - 1) * 8));
		text[i * 2] = hex[value >> 4];
		text[i * 2 + 1] = hex[value & 15];
	}
	text[bytes * 2] = '\0';
	return text;
}

gpgme_error_t gl_verify_signature(gpgme_ctx_t ctx, const unsigned char *sig,
				   size_t sig_len, const unsigned char *data,
				   size_t data_len, gpgme_signature_t result)
{
	CBS input;
	CBS hashed;
	CBS unhashed;
	CBS hash_header;
	CBS mpi;
	CBS signed_cbs;
	CBB signature_header;
	uint8_t *signature_header_data = NULL;
	size_t signature_header_len = 0;
	uint8_t version;
	uint8_t sig_type;
	uint8_t pubkey_algorithm;
	uint8_t hash_algorithm;
	uint16_t hashed_len;
	uint16_t unhashed_len;
	uint8_t hash_prefix[2];
	uint32_t created = 0;
	uint32_t sig_expire = 0;
	uint8_t key_flags = 0;
	uint64_t issuer = 0;
	uint8_t issuer_fpr[20] = {0};
	int has_issuer_fpr = 0;
	int has_created = 0;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	const EVP_MD *md;
	struct gl_key *selected = NULL;
	struct gl_signer *selected_signer = NULL;
	struct gl_key signing_view;
	size_t i;
	int cryptographic = 0;
	int hash_prefix_valid = 0;

	CBS_init(&input, sig, sig_len);
	{
		CBS version_cbs = input;

		if (CBS_get_u8(&version_cbs, &version) && version == 6)
			return gl_err(GPG_ERR_NOT_SUPPORTED);
	}
	/* RFC 9580 section 5.2.3: parse a v4 binary signature packet body. */
	if (!CBS_get_u8(&input, &version) || version != 4 ||
	    !CBS_get_u8(&input, &sig_type) || sig_type != 0 ||
	    !CBS_get_u8(&input, &pubkey_algorithm) ||
	    !CBS_get_u8(&input, &hash_algorithm) ||
	    !CBS_get_u16(&input, &hashed_len) ||
	    !CBS_get_bytes(&input, &hashed, hashed_len) ||
	    !CBS_get_u16(&input, &unhashed_len) ||
	    !CBS_get_bytes(&input, &unhashed, unhashed_len) ||
	    !CBS_get_u8(&input, &hash_prefix[0]) ||
	    !CBS_get_u8(&input, &hash_prefix[1])) {
		return gl_err(GPG_ERR_BAD_DATA);
	}
	if (!skip_subpackets(hashed, &created, &sig_expire, &key_flags,
			     &issuer, issuer_fpr, &has_issuer_fpr, &has_created, 1) ||
	    !skip_subpackets(unhashed, &created, &sig_expire, &key_flags,
			     &issuer, issuer_fpr, &has_issuer_fpr, &has_created, 0)) {
		return gl_err(GPG_ERR_BAD_DATA);
	}
	if (!CBS_get_bytes(&input, &mpi, CBS_len(&input))) {
		return gl_err(GPG_ERR_BAD_DATA);
	}
	result->timestamp = created;
	result->pubkey_algo = pubkey_algorithm == 22 ? GPGME_PK_EDDSA :
		(pubkey_algorithm == 3 ? GPGME_PK_RSA : pubkey_algorithm);
	result->hash_algo = hash_algorithm;
	result->exp_timestamp = sig_expire && created ? created + sig_expire : 0;
	if (pubkey_algorithm != 1 && pubkey_algorithm != 3 &&
	    pubkey_algorithm != 22)
		return gl_err(GPG_ERR_UNSUPPORTED_ALGORITHM);
	md = digest_for(hash_algorithm);
	if (!md)
		return gl_err(GPG_ERR_DIGEST_ALGO);
	if (!CBB_init(&signature_header, (size_t)hashed_len + 6) ||
	    !CBB_add_u8(&signature_header, version) ||
	    !CBB_add_u8(&signature_header, sig_type) ||
	    !CBB_add_u8(&signature_header, pubkey_algorithm) ||
	    !CBB_add_u8(&signature_header, hash_algorithm) ||
	    !CBB_add_u16(&signature_header, hashed_len) ||
	    !CBB_add_bytes(&signature_header, CBS_data(&hashed), hashed_len) ||
	    !CBB_finish(&signature_header, &signature_header_data,
			&signature_header_len)) {
		CBB_cleanup(&signature_header);
		return gl_err(GPG_ERR_ENOMEM);
	}
	CBS_init(&signed_cbs, data, data_len);
	CBS_init(&hash_header, signature_header_data, signature_header_len);
	if (!signature_digest(hash_algorithm, signed_cbs, hash_header, digest,
			      &digest_len)) {
		OPENSSL_free(signature_header_data);
		return gl_err(GPG_ERR_BAD_DATA);
	}
	OPENSSL_free(signature_header_data);
	hash_prefix_valid = digest_len >= 2 &&
		CRYPTO_memcmp(hash_prefix, digest, 2) == 0;
	(void)key_flags;
	(void)issuer;
	for (i = 0; i < ctx->key_count; i++) {
		struct gl_key *candidate = (struct gl_key *)ctx->keys[i];
		struct gl_signer *signer;

		if (((has_issuer_fpr &&
		      fpr_matches(candidate->pub.fpr, issuer_fpr)) ||
		     (!has_issuer_fpr &&
		      keyid_matches(candidate->pub.fpr, issuer))) &&
		    candidate->pub.can_sign) {
			selected = candidate;
			result->fpr = gl_strdup(candidate->pub.fpr);
			break;
		}
		for (signer = candidate->signers; signer; signer = signer->next) {
			if ((has_issuer_fpr && fpr_matches(signer->fpr, issuer_fpr)) ||
			    (!has_issuer_fpr && keyid_matches(signer->fpr, issuer))) {
				selected = candidate;
				selected_signer = signer;
				result->fpr = gl_strdup(signer->fpr);
				break;
			}
		}
		if (selected)
			break;
	}

	if (selected && !result->fpr)
		return gl_err(GPG_ERR_ENOMEM);
	if (!selected) {
		result->fpr = issuer_string(issuer_fpr, has_issuer_fpr, issuer);
		if (!result->fpr)
			return gl_err(GPG_ERR_ENOMEM);
		result->summary = GPGME_SIGSUM_KEY_MISSING;
		result->status = gl_err(GPG_ERR_NO_PUBKEY);
		return 0;
	}
	signing_view = *selected;
	if (selected_signer) {
		signing_view.signing_body = selected_signer->body;
		signing_view.signing_len = selected_signer->body_len;
		signing_view.signing_fpr = selected_signer->fpr;
		signing_view.signing_expires_at = selected_signer->expires_at;
		signing_view.signing_revoked = selected_signer->revoked;
		signing_view.key_algorithm = selected_signer->algorithm;
		signing_view.ed25519 = selected_signer->ed25519;
		memcpy(signing_view.public_key, selected_signer->public_key,
		       sizeof(signing_view.public_key));
	} else {
		signing_view.signing_body = NULL;
		signing_view.signing_len = 0;
		signing_view.signing_fpr = NULL;
		signing_view.signing_expires_at = 0;
		signing_view.signing_revoked = 0;
	}

	if (!hash_prefix_valid || !has_created ||
	    pubkey_algorithm != signing_view.key_algorithm &&
	    !((pubkey_algorithm == 1 || pubkey_algorithm == 3) &&
	      (signing_view.key_algorithm == 1 ||
	       signing_view.key_algorithm == 3))) {
		cryptographic = 0;
	} else if (signing_view.ed25519) {
		unsigned char ed_signature[64];
		BIGNUM *r = NULL;
		BIGNUM *s = NULL;
		CBS mpis = mpi;
		uint16_t bits;
		CBS bytes;

		if (!CBS_get_u16(&mpis, &bits) ||
		    !CBS_get_bytes(&mpis, &bytes, (bits + 7) / 8))
			return gl_err(GPG_ERR_BAD_DATA);
		r = BN_bin2bn(CBS_data(&bytes), (int)CBS_len(&bytes), NULL);
		if (!r || !CBS_get_u16(&mpis, &bits) ||
		    !CBS_get_bytes(&mpis, &bytes, (bits + 7) / 8)) {
			BN_free(r);
			return gl_err(GPG_ERR_BAD_DATA);
		}
		s = BN_bin2bn(CBS_data(&bytes), (int)CBS_len(&bytes), NULL);
		if (CBS_len(&mpis) == 0 && r && s &&
		    BN_bn2binpad(r, ed_signature, 32) == 32 &&
		    BN_bn2binpad(s, ed_signature + 32, 32) == 32)
			cryptographic = ED25519_verify(digest, digest_len, ed_signature,
						       signing_view.public_key);
		BN_free(r);
		BN_free(s);
	} else {
		CBS signature_mpi = mpi;
		uint16_t bits;
		CBS signature_bytes;

		if (CBS_get_u16(&signature_mpi, &bits) &&
		    CBS_get_bytes(&signature_mpi, &signature_bytes, (bits + 7) / 8) &&
		    CBS_len(&signature_mpi) == 0)
			cryptographic = rsa_verify(&signing_view, mpi, md, digest,
					   digest_len,
					   (uint8_t *)CBS_data(&signature_bytes),
					   CBS_len(&signature_bytes));
	}
	if (!cryptographic) {
		result->summary = GPGME_SIGSUM_RED;
		result->status = gl_err(GPG_ERR_BAD_SIGNATURE);
	} else if (signing_view.pub.revoked || signing_view.signing_revoked) {
		result->summary = GPGME_SIGSUM_KEY_REVOKED;
		result->status = gl_err(GPG_ERR_CERT_REVOKED);
	} else if ((selected_signer && signing_view.expires_at &&
		   signing_view.expires_at < (uint32_t)time(NULL)) ||
		  (selected_signer ? signing_view.signing_expires_at :
		    signing_view.expires_at) &&
		   (selected_signer ? signing_view.signing_expires_at :
		    signing_view.expires_at) < (uint32_t)time(NULL)) {
		result->summary = GPGME_SIGSUM_KEY_EXPIRED;
		result->status = gl_err(GPG_ERR_CERT_EXPIRED);
	} else if (result->exp_timestamp &&
		   result->exp_timestamp < (unsigned long)time(NULL)) {
		result->summary = GPGME_SIGSUM_SIG_EXPIRED;
		result->status = gl_err(GPG_ERR_SIG_EXPIRED);
	} else {
		result->summary = GPGME_SIGSUM_VALID | GPGME_SIGSUM_GREEN;
		result->status = 0;
	}
	return 0;
}
