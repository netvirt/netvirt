#
# src/Makefile.am
#

sbin_PROGRAMS = dsd
dsd_SOURCES = main.c dsd.c request.c 
dsd_SOURCES += dsd.h request.h
dsd_LDFLAGS = -rdynamic @libdnds_LIBS@
dsd_CFLAGS = -DCONFIG_FILE=\"@sysconfdir@/dsd.conf\"
dsd_CFLAGS += @libdnds_CFLAGS@ -g
