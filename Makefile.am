ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = COPYING README.md

lib_LTLIBRARIES = libshamir.la
libshamir_la_SOURCES = src/shamir.c
libshamir_la_LDFLAGS = -version-info @LTLIBVER@
libshamir_la_CPPFLAGS = -I$(top_srcdir)/include
libshamir_la_CFLAGS = -Wall -Wextra
include_HEADERS = include/shamir.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libshamir.pc.in

AM_CFLAGS = -I$(srcdir)/include

