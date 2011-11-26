#
# src/Makefile.am
#

SUBDIRS = asn1

## libdnds should be installed in ../lib/ folder
lib_LTLIBRARIES = libdnds.la

## libdnds include should be in ../include/dnds/
libdnds_includedir=$(includedir)/dnds

## library source
libdnds_la_SOURCES = aclset.c bitpool.c dnds.c event.c ftable.c hash.c hooklet.c ipf.c ipset.c journal.c jsw_hlib.c jsw_rbtree.c krypt.c mbuf.c net.c netbus.c options.c xsched.c utils.c pki.c inet.c 

libdnds_include_HEADERS = aclset.c bitpool.h dnds.h event.h ftable.h hash.h hooklet.h ion.h ipf.h ipset.h journal.h jsw_hlib.h jsw_rbtree.h krypt.h mbuf.h net.h netbus.h options.h xsched.h udtbus.h utils.h tun.h pki.h inet.h 

## conditional source
EXTRA_libdnds_la_SOURCES = ion_epoll.c ion_kqueue.c tun_ifreq.c tun_tuninfo.c udtbus.cpp

## adding needed lib
libdnds_la_LIBADD = @ION_FLAVOR@ @TUN_FLAVOR@ @WANT_UDT@ asn1/libasn1.la @UDT_PATH@/libudt.a
libdnds_la_DEPENDENCIES = @ION_FLAVOR@ @TUN_FLAVOR@ @WANT_UDT@

## extra generic flags
AM_LDFLAGS = @openssl_LIBS@ @UDT_LIBS@
AM_CXXFLAGS = @UDT_CXXFLAGS@
AM_CFLAGS = @openssl_CFLAGS@ -I ./asn1/

## libdnds flags
libdnds_la_LDFLAGS = -version-info 0:1

