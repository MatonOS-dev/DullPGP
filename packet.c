/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <openssl/base64.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* RFC 9580 section 6.2: armor carries base64-encoded OpenPGP packet octets. */
int gl_decode_armor(const unsigned char *in, size_t in_len,
		    unsigned char **out, size_t *out_len)
{
	static const char begin[] = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
	static const char sig_begin[] = "-----BEGIN PGP SIGNATURE-----";
	const unsigned char *start = in;
	const unsigned char *end = in + in_len;
	const unsigned char *line_end;
	const unsigned char *body;
	const unsigned char *crc;
	char *encoded;
	size_t encoded_len = 0;
	size_t decoded_len = 0;
	size_t cap;
	unsigned char *decoded;
	uint32_t crc24 = 0xb704ce;
	size_t i;

	*out = NULL;
	*out_len = 0;
	if (in_len > GL_MAX_OBJECT)
		return 0;
	if (in_len >= sizeof(begin) - 1 &&
	    CRYPTO_memcmp(in, begin, sizeof(begin) - 1) == 0)
		start = in + sizeof(begin) - 1;
	else if (in_len >= sizeof(sig_begin) - 1 &&
		 CRYPTO_memcmp(in, sig_begin, sizeof(sig_begin) - 1) == 0)
		start = in + sizeof(sig_begin) - 1;
	else
		return 0;
	line_end = start;
	while (line_end < end && *line_end != '\n')
		line_end++;
	if (line_end == end)
		return 0;
	body = line_end + 1;
	while (body < end) {
		line_end = body;
		while (line_end < end && *line_end != '\n')
			line_end++;
		if (line_end == body) {
			body = line_end < end ? line_end + 1 : end;
			break;
		}
		if (memchr(body, ':', (size_t)(line_end - body)) == NULL)
			break;
		body = line_end < end ? line_end + 1 : end;
	}
	/* RFC 9580 section 6.2.2: armor headers end at the first empty line. */
	encoded = malloc(in_len + 1);
	if (!encoded)
		return 0;
	while (body < end) {
		line_end = body;
		while (line_end < end && *line_end != '\n')
			line_end++;
		if (line_end > body && body[0] == '=')
			break;
		if (line_end - body >= 9 &&
		    memcmp(body, "-----END ", 9) == 0)
			break;
		for (i = 0; i < (size_t)(line_end - body); i++) {
			if (!isspace(body[i]))
				encoded[encoded_len++] = (char)body[i];
		}
		body = line_end < end ? line_end + 1 : end;
	}
	if (encoded_len == 0 || encoded_len > GL_MAX_OBJECT) {
		free(encoded);
		return 0;
	}
	cap = (encoded_len / 4 + 1) * 3;
	decoded = malloc(cap);
	if (!decoded) {
		free(encoded);
		return 0;
	}
	if (!EVP_DecodeBase64(decoded, &decoded_len, cap,
			      (const uint8_t *)encoded, encoded_len)) {
		free(encoded);
		free(decoded);
		return 0;
	}
	free(encoded);
	crc = body;
	while (crc < end && *crc != '\n')
		crc++;
	if (body < end && *body == '=') {
		unsigned char checksum[4];
		size_t checksum_len = 0;

		if (!EVP_DecodeBase64(checksum, &checksum_len, sizeof(checksum),
				      body + 1, (size_t)(crc - body - 1)) ||
		    checksum_len != 3) {
			free(decoded);
			return 0;
		}
		/* RFC 9580 section 6.1: CRC-24 covers decoded packet bytes. */
		for (i = 0; i < decoded_len; i++) {
			unsigned int bit;

			crc24 ^= (uint32_t)decoded[i] << 16;
			for (bit = 0; bit < 8; bit++) {
				crc24 <<= 1;
				if (crc24 & 0x1000000)
					crc24 ^= 0x1864cfb;
			}
		}
		if (checksum[0] != (unsigned char)(crc24 >> 16) ||
		    checksum[1] != (unsigned char)(crc24 >> 8) ||
		    checksum[2] != (unsigned char)crc24) {
			free(decoded);
			return 0;
		}
	}
	*out = decoded;
	*out_len = decoded_len;
	return 1;
}

/* RFC 9580 sections 4.2.1 and 4.2.2: decode both packet header formats. */
int gl_next_packet(CBS *input, struct gl_packet *packet)
{
	CBS body;
	uint8_t ctb;
	uint8_t length_type;
	uint32_t length;

	if (!CBS_get_u8(input, &ctb) || !(ctb & 0x80))
		return 0;
	if (ctb & 0x40) {
		packet->tag = ctb & 0x3f;
		/* RFC 9580 sections 4.2.1.1-4.2.1.3 define definite new lengths. */
		if (!CBS_get_u8(input, &length_type))
			return 0;
		if (length_type < 192) {
			length = length_type;
		} else if (length_type < 224) {
			uint8_t second;

			if (!CBS_get_u8(input, &second))
				return 0;
			length = ((uint32_t)(length_type - 192) << 8) + second + 192;
		} else if (length_type == 255) {
			if (!CBS_get_u32(input, &length))
				return 0;
		} else {
			/* RFC 9580 section 4.2.1.4: reject partial body lengths here. */
			return 0;
		}
	} else {
		/* RFC 9580 section 4.2.2: decode the legacy length selector. */
		packet->tag = (ctb >> 2) & 0x0f;
		length_type = ctb & 3;
		if (length_type == 0) {
			uint8_t n;

			if (!CBS_get_u8(input, &n))
				return 0;
			length = n;
		} else if (length_type == 1) {
			uint16_t n;

			if (!CBS_get_u16(input, &n))
				return 0;
			length = n;
		} else if (length_type == 2) {
			if (!CBS_get_u32(input, &length))
				return 0;
		} else {
			return 0;
		}
	}
	if (length > GL_MAX_PACKET || !CBS_get_bytes(input, &body, length))
		return 0;
	packet->body = body;
	packet->encoded = NULL;
	packet->encoded_len = 0;
	return 1;
}

int gl_read_all(gpgme_data_t data, unsigned char **out, size_t *out_len)
{
	unsigned char *buf = NULL;
	size_t len = 0;
	size_t cap = 4096;

	if (!data || !out || !out_len)
		return 0;
	buf = malloc(cap);
	if (!buf)
		return 0;
	for (;;) {
		ssize_t n;

		if (len == cap) {
			size_t next = cap * 2;
			unsigned char *larger;

			if (cap >= GL_MAX_OBJECT) {
				free(buf);
				return 0;
			}
			if (next > GL_MAX_OBJECT)
				next = GL_MAX_OBJECT;
			larger = realloc(buf, next);
			if (!larger) {
				free(buf);
				return 0;
			}
			buf = larger;
			cap = next;
		}
		n = gpgme_data_read(data, buf + len, cap - len);
		if (n < 0) {
			free(buf);
			return 0;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	*out = buf;
	*out_len = len;
	return 1;
}
