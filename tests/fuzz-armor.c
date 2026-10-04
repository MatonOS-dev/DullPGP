/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	unsigned char *decoded = NULL;
	size_t decoded_len = 0;
	if (size <= GL_MAX_OBJECT &&
	    gl_decode_armor(data, size, &decoded, &decoded_len))
		free(decoded);
	return 0;
}
