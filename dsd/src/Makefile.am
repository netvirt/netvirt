#
# src/Makefile.am
#

sbin_PROGRAMS = dsd
dsd_SOURCES = main.c dao.c dsd.c request.c 
dsd_SOURCES += dao.h dsd.h request.h
dsd_LDFLAGS = -rdynamic -lpq @libdnds_LIBS@
dsd_CFLAGS = -DCONFIG_FILE=\"@sysconfdir@/dsd.conf\"
dsd_CFLAGS += @libdnds_CFLAGS@ -g
