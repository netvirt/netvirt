#
# src/Makefile.am
#

sbin_PROGRAMS = dnc
dnc_SOURCES = dnc.c request.c session.c main.c
dnc_SOURCES +=
dnc_LDFLAGS = -rdynamic @DNDSLIBS_LIBS@
dnc_CFLAGS =  -DCONFIG_FILE=\"@sysconfdir@/dnc.conf\"
dnc_CFLAGS += @DNDSLIBS_CFLAGS@
