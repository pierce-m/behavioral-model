AM_CPPFLAGS = -I$(srcdir)/include/
if WITH_PCAP_FIX
AM_CPPFLAGS += -DWITH_PCAP_FIX
else
AM_CPPFLAGS +=
endif
AM_CFLAGS = $(PICKY_CFLAGS)

noinst_LTLIBRARIES = libpktpipe.la

common_source = \
src/pktpipe.c

common_include = \
include/pktpipe/pktpipe.h

libpktpipe_la_SOURCES = $(common_source) $(common_include)
