ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = COPYING README.md

lib_LTLIBRARIES = libshamir.la
libshamir_la_SOURCES = src/shamir.c include/shamir.h include/g256_tables.h
libshamir_la_LDFLAGS = -version-info @LTLIBVER@
libshamir_la_CPPFLAGS = -I$(top_srcdir)/include
libshamir_la_CFLAGS = -Wall -Wextra
include_HEADERS = include/shamir.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libshamir.pc

AM_CFLAGS = -I$(srcdir)/include

C_TESTS = test_shamir
TESTS = $(C_TESTS)

check_PROGRAMS = $(C_TESTS)

test_shamir_SOURCES = tests/test_shamir.c
test_shamir_LDADD = libshamir.la
test_shamir_LDFLAGS = -static
test_shamir_CPPFLAGS = -I$(top_srcdir)/include
test_shamir_CFLAGS = -Wall -Werror

dist_man_MANS = man/shamir.7 \
	man/shamir_get_key.3 man/shamir_get_keys.3 \
	man/shamir_init_poly.3 \
	man/shamir_poly_size.3 man/shamir_key_size.3 \
	man/shamir_recover_secret.3 man/shamir_recover_poly.3

man/shamir_get_key.3: man/shamir_get_keys.3
	cp man/shamir_get_keys.3 man/shamir_get_key.3

man/shamir_key_size.3: man/shamir_poly_size.3
	cp man/shamir_poly_size.3 man/shamir_key_size.3

man/shamir_recover_poly.3: man/shamir_recover_secret.3
	cp man/shamir_recover_secret.3 man/shamir_recover_poly.3
