# SPDX-License-Identifier: LGPL-2.1-or-later
CC ?= cc
AR ?= ar
CFLAGS ?= -O2
BSSL_SRC ?= /usr/include
BSSL_LIBDIR ?= /usr/lib
CPPFLAGS += -Iinclude -I$(BSSL_SRC)/src/include -D_FILE_OFFSET_BITS=64
ifeq ($(GL_BORINGSSL_PREFIXED),1)
CPPFLAGS += -DGL_BORINGSSL_PREFIXED=1 -DBORINGSSL_PREFIX=GPGMELITE
endif
CFLAGS += -std=c11 -fPIC -Wall -Wextra -Werror
SOURCES = api.c packet.c key.c keyring.c verify.c
OBJECTS = $(SOURCES:.c=.o)

all: libgpgme-lite.a gpgme.pc

%.o: %.c internal.h include/gpgme.h include/gpg-error.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

libgpgme-lite.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

gpgme.pc: gpgme.pc.in
	sed 's|@PREFIX@|$(PREFIX)|g; s|@LIBDIR@|$(LIBDIR)|g; s|@INCLUDEDIR@|$(INCLUDEDIR)|g' $< > $@

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

clean:
	$(RM) $(OBJECTS) gpgme-lite.o libgpgme-lite.a gpgme.pc

.PHONY: all clean
