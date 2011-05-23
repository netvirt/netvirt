#
# src/Makefile.am
#

sbin_PROGRAMS = dnd
dnd_SOURCES = main.c context.c dnd.c dsc.c ippool.c request.c session.c
dnd_SOURCES += context.h dnd.h dsc.h ippool.h request.h session.h
dnd_LDFLAGS = -rdynamic @libdnds_LIBS@
dnd_CFLAGS =  -DCONFIG_FILE=\"@sysconfdir@/dnd.conf\"
dnd_CFLAGS += @libdnds_CFLAGS@ -g
