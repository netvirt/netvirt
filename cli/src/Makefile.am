#
# src/Makefile.am
#

sbin_PROGRAMS = dndscli
dndscli_SOURCES = command.c linenoise.c main.c
dndscli_SOURCES +=
dndscli_LDFLAGS = @DNDSLIBS_LIBS@
dndscli_CFLAGS = -DCONFIG_FILE=\"@sysconfdir@/dndscli.conf\"
dndscli_CFLAGS += @DNDSLIBS_CFLAGS@
